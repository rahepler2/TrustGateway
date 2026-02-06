<#
.SYNOPSIS
    Nexus Trust Gateway — Developer CLI (PowerShell)

.DESCRIPTION
    Scans packages/containers through the Trust Gateway before they are
    promoted to trusted Nexus repositories.

.EXAMPLE
    .\nexus-request.ps1 scan requests==2.32.3
    .\nexus-request.ps1 scan requests 2.32.3
    .\nexus-request.ps1 scan nginx:1.25 -e docker
    .\nexus-request.ps1 scan -f requirements.txt
    .\nexus-request.ps1 status <job_id>
    .\nexus-request.ps1 status -Batch <batch_id>

.NOTES
    Environment variables:
        TRUST_GATEWAY_URL  — Gateway API URL (default: http://localhost:5000)
        TRUST_GATEWAY_KEY  — Optional Bearer token
#>

param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet("scan", "status")]
    [string]$Command,

    [Parameter(Position=1, ValueFromRemainingArguments=$true)]
    [string[]]$Args_,

    [Alias("f")]
    [string]$File,

    [Alias("e")]
    [string]$Ecosystem,

    [Alias("w")]
    [int]$Wait = 120,

    [Alias("b")]
    [string]$Batch
)

$ErrorActionPreference = "Stop"

$GatewayUrl = if ($env:TRUST_GATEWAY_URL) { $env:TRUST_GATEWAY_URL.TrimEnd("/") } else { "http://localhost:5002" }

$Headers = @{ "Accept" = "application/json"; "Content-Type" = "application/json" }
if ($env:TRUST_GATEWAY_KEY) {
    $Headers["Authorization"] = "Bearer $($env:TRUST_GATEWAY_KEY)"
}

$FileEcoMap = @{
    "requirements.txt"  = "pypi"
    "constraints.txt"   = "pypi"
    "package.json"      = "npm"
    "package-lock.json" = "npm"
    "pom.xml"           = "maven"
    "build.gradle"      = "maven"
    "packages.config"   = "nuget"
}

function Wait-ForJob($jobId, $timeout) {
    $short = $jobId.Substring(0, [Math]::Min(8, $jobId.Length))
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $timeout) {
        try {
            $r = Invoke-RestMethod -Uri "$GatewayUrl/job/$jobId" -Headers @{ "Accept"="application/json" } -TimeoutSec 10
            if ($r.status -eq "done" -or $r.status -eq "error") {
                Write-Host ""
                return $r
            }
        } catch {}
        $elapsed = [int]((Get-Date) - $start).TotalSeconds
        Write-Host "`r  Scanning $short... ${elapsed}s" -NoNewline
        Start-Sleep -Seconds 3
    }
    Write-Host ""
    return @{ error = "timeout"; job_id = $jobId }
}

switch ($Command) {
    "scan" {
        # File-based batch scan
        if ($File) {
            $eco = $Ecosystem
            if (-not $eco) {
                $base = (Split-Path $File -Leaf).ToLower()
                $eco = $FileEcoMap[$base]
                if (-not $eco) { $eco = "pypi" }
            }
            Write-Host "Scanning $File ($eco)..."

            $filePath = Resolve-Path $File
            $boundary = [System.Guid]::NewGuid().ToString()
            $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
            $fileContent = [System.Text.Encoding]::UTF8.GetString($fileBytes)

            $bodyLines = @(
                "--$boundary",
                "Content-Disposition: form-data; name=`"requirements`"; filename=`"$(Split-Path $filePath -Leaf)`"",
                "Content-Type: text/plain", "",
                $fileContent,
                "--$boundary",
                "Content-Disposition: form-data; name=`"wait`"", "",
                "$Wait",
                "--$boundary",
                "Content-Disposition: form-data; name=`"ecosystem`"", "",
                "$eco",
                "--$boundary--"
            )

            try {
                $resp = Invoke-RestMethod -Uri "$GatewayUrl/request/batch" -Method Post `
                    -ContentType "multipart/form-data; boundary=$boundary" `
                    -Body ($bodyLines -join "`r`n") -TimeoutSec ($Wait + 30)
                $resp | ConvertTo-Json -Depth 10
            } catch {
                Write-Error "Batch request failed: $_"
                exit 2
            }
            return
        }

        # Single package scan — build spec from positional args
        if (-not $Args_ -or $Args_.Count -eq 0) {
            Write-Error "Provide a package name or use -f <file>"
            exit 2
        }

        if ($Args_.Count -ge 2) {
            $name = $Args_[0]
            $ver  = $Args_[1]
            if ($name -match "==" -or $name -match ":") {
                $spec = $name
            } else {
                $spec = "$name==$ver"
            }
        } else {
            $spec = $Args_[0]
        }

        # Auto-detect docker from colon notation
        $eco = $Ecosystem
        if (-not $eco -and $spec -match ":" -and $spec -notmatch "==") {
            $eco = "docker"
        }
        if (-not $eco) { $eco = "pypi" }

        Write-Host "Scanning $spec ($eco)..."

        $body = @{ package = $spec; ecosystem = $eco; wait = $Wait } | ConvertTo-Json

        try {
            $resp = Invoke-RestMethod -Uri "$GatewayUrl/request" -Method Post `
                -Headers $Headers -Body $body -TimeoutSec ($Wait + 10)
            $resp | ConvertTo-Json -Depth 10

            if ($resp.job_ids) {
                $allOk = $true
                foreach ($jid in $resp.job_ids) {
                    $result = Wait-ForJob $jid $Wait
                    $result | ConvertTo-Json -Depth 10
                    if ($result.result.verdict -notin @("pass", "warn")) { $allOk = $false }
                }
                exit $(if ($allOk) { 0 } else { 1 })
            }
        } catch {
            Write-Error "Request failed: $_"
            exit 2
        }
    }

    "status" {
        if ($Batch) {
            $r = Invoke-RestMethod -Uri "$GatewayUrl/batch/$Batch/status" -Headers @{ "Accept"="application/json" } -TimeoutSec 10
            $r | ConvertTo-Json -Depth 10
        } elseif ($Args_ -and $Args_.Count -gt 0) {
            $r = Invoke-RestMethod -Uri "$GatewayUrl/job/$($Args_[0])" -Headers @{ "Accept"="application/json" } -TimeoutSec 10
            $r | ConvertTo-Json -Depth 10
        } else {
            Write-Error "Provide a job ID or -Batch <batch_id>"
            exit 2
        }
    }
}
