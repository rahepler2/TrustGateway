<#
.SYNOPSIS
    Nexus Trust Gateway — Developer CLI wrapper (PowerShell)

.DESCRIPTION
    Submits packages/containers to the Trust Gateway for security scanning
    before they are promoted to the trusted Nexus repository.

.EXAMPLE
    .\nexus-request.ps1 submit -Package "requests==2.31.0"
    .\nexus-request.ps1 submit -Package "nginx==1.25" -Ecosystem docker
    .\nexus-request.ps1 submit-batch -Requirements requirements.txt
    .\nexus-request.ps1 status -Job "abc-123"

.NOTES
    Environment variables:
        TRUST_GATEWAY_URL  — Gateway API URL (default: http://localhost:5000)
        TRUST_GATEWAY_KEY  — Optional Bearer token
#>

param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet("submit", "submit-batch", "status")]
    [string]$Command,

    [string]$Package,
    [string]$Requirements,
    [string]$Ecosystem = "pypi",
    [int]$Wait = 120,
    [string]$Job,
    [string]$Batch
)

$ErrorActionPreference = "Stop"

$GatewayUrl = if ($env:TRUST_GATEWAY_URL) { $env:TRUST_GATEWAY_URL } else { "http://localhost:5000" }
$GatewayUrl = $GatewayUrl.TrimEnd("/")

$Headers = @{ "Accept" = "application/json" }
if ($env:TRUST_GATEWAY_KEY) {
    $Headers["Authorization"] = "Bearer $($env:TRUST_GATEWAY_KEY)"
}

function Write-Status($msg) {
    Write-Host "[INFO] $msg" -ForegroundColor Cyan
}

function Write-Result($json) {
    $json | ConvertTo-Json -Depth 10
}

function Wait-ForJob($jobId, $timeout) {
    $start = Get-Date
    Write-Status "Scanning job $($jobId.Substring(0,8))... please wait."
    while (((Get-Date) - $start).TotalSeconds -lt $timeout) {
        try {
            $r = Invoke-RestMethod -Uri "$GatewayUrl/job/$jobId" -Headers $Headers -TimeoutSec 10
            if ($r.status -eq "done" -or $r.status -eq "error") {
                return $r
            }
        } catch {}
        $elapsed = [int]((Get-Date) - $start).TotalSeconds
        Write-Host "`r[INFO] Scanning... ($($elapsed)s elapsed)" -NoNewline
        Start-Sleep -Seconds 3
    }
    Write-Host ""
    return @{ error = "timeout"; job_id = $jobId }
}

switch ($Command) {
    "submit" {
        if (-not $Package) { Write-Error "Provide -Package 'pkg==version'"; exit 2 }
        Write-Status "Submitting $Package ($Ecosystem) to Trust Gateway..."

        $body = @{
            package   = $Package
            wait      = $Wait
            ecosystem = $Ecosystem
        } | ConvertTo-Json

        try {
            $resp = Invoke-RestMethod -Uri "$GatewayUrl/request" -Method Post `
                -Headers $Headers -ContentType "application/json" -Body $body -TimeoutSec ($Wait + 10)
            Write-Result $resp

            if ($resp.job_ids) {
                $allOk = $true
                foreach ($jid in $resp.job_ids) {
                    $result = Wait-ForJob $jid $Wait
                    Write-Host ""
                    Write-Result $result
                    if ($result.result.verdict -notin @("pass", "warn")) { $allOk = $false }
                }
                exit $(if ($allOk) { 0 } else { 1 })
            }
        } catch {
            Write-Error "Request failed: $_"
            exit 2
        }
    }

    "submit-batch" {
        if (-not $Requirements) { Write-Error "Provide -Requirements path"; exit 2 }
        Write-Status "Uploading $Requirements for batch scanning ($Ecosystem)..."

        $uri = "$GatewayUrl/request/batch"
        $filePath = Resolve-Path $Requirements
        $boundary = [System.Guid]::NewGuid().ToString()
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
        $fileContent = [System.Text.Encoding]::UTF8.GetString($fileBytes)

        $bodyLines = @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"requirements`"; filename=`"$(Split-Path $filePath -Leaf)`"",
            "Content-Type: text/plain",
            "",
            $fileContent,
            "--$boundary",
            "Content-Disposition: form-data; name=`"wait`"",
            "",
            "$Wait",
            "--$boundary",
            "Content-Disposition: form-data; name=`"ecosystem`"",
            "",
            "$Ecosystem",
            "--$boundary--"
        )
        $bodyStr = $bodyLines -join "`r`n"

        try {
            $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers $Headers `
                -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyStr -TimeoutSec ($Wait + 30)
            Write-Result $resp
        } catch {
            Write-Error "Batch request failed: $_"
            exit 2
        }
    }

    "status" {
        if ($Job) {
            $r = Invoke-RestMethod -Uri "$GatewayUrl/job/$Job" -Headers $Headers -TimeoutSec 10
            Write-Result $r
        } elseif ($Batch) {
            $r = Invoke-RestMethod -Uri "$GatewayUrl/batch/$Batch/status" -Headers $Headers -TimeoutSec 10
            Write-Result $r
        } else {
            Write-Error "Provide -Job <id> or -Batch <id>"
            exit 2
        }
    }
}
