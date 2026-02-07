<#
.SYNOPSIS
    Nexus Trust Gateway — Developer CLI (PowerShell)

.DESCRIPTION
    Scans packages/containers through the Trust Gateway before they are
    promoted to trusted Nexus repositories.

.EXAMPLE
    nexus-request scan python requests
    nexus-request scan python requests==2.32.3
    nexus-request scan python requests 2.32.3
    nexus-request scan docker nginx:1.25
    nexus-request scan docker nginx 1.25
    nexus-request scan npm express@4.18.2
    nexus-request scan python -f requirements.txt
    nexus-request rescan python
    nexus-request rescan -All
    nexus-request status <job_id>
    nexus-request status -Batch <batch_id>

.NOTES
    Environment variables:
        TRUST_GATEWAY_URL  — Gateway API URL (default: http://localhost:5002)
        TRUST_GATEWAY_KEY  — Optional API key (sent as X-API-Key header)
#>

param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet("scan", "status", "rescan")]
    [string]$Command,

    [Parameter(Position=1, ValueFromRemainingArguments=$true)]
    [string[]]$Args_,

    [Alias("f")]
    [string]$File,

    [Alias("w")]
    [int]$Wait = 120,

    [Alias("b")]
    [string]$Batch,

    [Alias("a")]
    [switch]$All
)

$ErrorActionPreference = "Stop"

$GatewayUrl = if ($env:TRUST_GATEWAY_URL) { $env:TRUST_GATEWAY_URL.TrimEnd("/") } else { "http://localhost:5002" }

$Headers = @{ "Accept" = "application/json"; "Content-Type" = "application/json" }
if ($env:TRUST_GATEWAY_KEY) {
    $Headers["X-API-Key"] = $env:TRUST_GATEWAY_KEY
}

# Ecosystem aliases — accept common names
$EcoAliases = @{
    "python" = "pypi"; "pypi" = "pypi"; "pip" = "pypi"
    "node" = "npm"; "npm" = "npm"; "js" = "npm"
    "docker" = "docker"; "container" = "docker"; "image" = "docker"
    "maven" = "maven"; "java" = "maven"; "mvn" = "maven"
    "nuget" = "nuget"; "dotnet" = "nuget"; "csharp" = "nuget"
}

function Resolve-Ecosystem($name) {
    if (-not $name) { return $null }
    return $EcoAliases[$name.ToLower()]
}

function Split-PackageSpec($spec, $ecosystem) {
    if ($spec -match "==") {
        $parts = $spec -split "==", 2
        return @{ name = $parts[0].Trim(); version = $parts[1].Trim() }
    }
    if ($ecosystem -eq "npm" -and $spec -match "@") {
        if ($spec.StartsWith("@") -and ($spec.ToCharArray() | Where-Object { $_ -eq '@' }).Count -ge 2) {
            $idx = $spec.LastIndexOf("@")
            return @{ name = $spec.Substring(0, $idx); version = $spec.Substring($idx + 1) }
        } elseif (-not $spec.StartsWith("@")) {
            $idx = $spec.LastIndexOf("@")
            return @{ name = $spec.Substring(0, $idx); version = $spec.Substring($idx + 1) }
        }
    }
    if ($ecosystem -eq "docker" -and $spec -match ":") {
        $idx = $spec.LastIndexOf(":")
        return @{ name = $spec.Substring(0, $idx); version = $spec.Substring($idx + 1) }
    }
    if ($ecosystem -eq "maven" -and ($spec.ToCharArray() | Where-Object { $_ -eq ':' }).Count -ge 2) {
        $idx = $spec.LastIndexOf(":")
        return @{ name = $spec.Substring(0, $idx); version = $spec.Substring($idx + 1) }
    }
    return @{ name = $spec; version = $null }
}

function Wait-ForJob($jobId, $timeout) {
    $short = $jobId.Substring(0, [Math]::Min(8, $jobId.Length))
    $start = Get-Date
    while (((Get-Date) - $start).TotalSeconds -lt $timeout) {
        try {
            $r = Invoke-RestMethod -Uri "$GatewayUrl/job/$jobId" -Headers $Headers -TimeoutSec 10
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

function Write-Verdict($result, $package, $version, $ecosystem) {
    if (-not $result) { return }
    $verdict = if ($result.verdict) { $result.verdict.ToUpper() } else { "UNKNOWN" }
    $label = "${package}==${version} (${ecosystem})"
    switch ($verdict) {
        "PASS"  { Write-Host "  PASS  $label" -ForegroundColor Green }
        "WARN"  { Write-Host "  WARN  $label" -ForegroundColor Yellow }
        "FAIL"  { Write-Host "  FAIL  $label" -ForegroundColor Red }
        "ERROR" { Write-Host "  ERROR $label" -ForegroundColor Red }
        default { Write-Host "  $verdict $label" }
    }
}

switch ($Command) {
    "scan" {
        # First positional arg is the ecosystem
        if (-not $Args_ -or $Args_.Count -eq 0) {
            Write-Error "Usage: nexus-request scan <ecosystem> <package> [version]"
            exit 2
        }

        $eco = Resolve-Ecosystem $Args_[0]
        if (-not $eco) {
            Write-Error "Unknown ecosystem '$($Args_[0])'. Valid: python, docker, npm, maven, nuget"
            exit 2
        }

        # Remaining args after ecosystem
        $pkgArgs = @()
        if ($Args_.Count -gt 1) {
            $pkgArgs = $Args_[1..($Args_.Count - 1)]
        }

        # File-based batch scan
        if ($File) {
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
                $batchHeaders = @{ "Accept" = "application/json" }
                if ($env:TRUST_GATEWAY_KEY) {
                    $batchHeaders["X-API-Key"] = $env:TRUST_GATEWAY_KEY
                }
                $resp = Invoke-RestMethod -Uri "$GatewayUrl/request/batch" -Method Post `
                    -Headers $batchHeaders `
                    -ContentType "multipart/form-data; boundary=$boundary" `
                    -Body ($bodyLines -join "`r`n") -TimeoutSec ($Wait + 30)
                if ($resp.batch_id) {
                    Write-Host "  Batch ID: $($resp.batch_id)"
                }
                $resp | ConvertTo-Json -Depth 10
            } catch {
                Write-Error "Batch request failed: $_"
                exit 2
            }
            return
        }

        # Single package scan
        if ($pkgArgs.Count -eq 0) {
            Write-Error "Provide a package name or use -f <file>"
            Write-Error "  Example: nexus-request scan $($Args_[0]) requests"
            exit 2
        }

        # Build name + version from remaining args
        if ($pkgArgs.Count -ge 2) {
            $namePart = $pkgArgs[0]
            $verPart = $pkgArgs[1]
            if ($namePart -match "==" -or $namePart -match "@" -or ($eco -eq "docker" -and $namePart -match ":")) {
                $parsed = Split-PackageSpec $namePart $eco
                $pkgName = $parsed.name
                $pkgVer = $parsed.version
            } else {
                $pkgName = $namePart
                $pkgVer = $verPart
            }
        } else {
            $parsed = Split-PackageSpec $pkgArgs[0] $eco
            $pkgName = $parsed.name
            $pkgVer = $parsed.version
        }

        $sep = if ($eco -eq "docker" -and $pkgVer) { ":" } else { "==" }
        $label = if ($pkgVer) { "${pkgName}${sep}${pkgVer}" } else { $pkgName }
        Write-Host "Scanning $label ($eco)..."

        $bodyHash = @{ package = $pkgName; ecosystem = $eco; wait = $Wait }
        if ($pkgVer) { $bodyHash["version"] = $pkgVer }
        $body = $bodyHash | ConvertTo-Json

        try {
            $resp = Invoke-RestMethod -Uri "$GatewayUrl/request" -Method Post `
                -Headers $Headers -Body $body -TimeoutSec ($Wait + 10)

            if ($resp.job_ids) {
                foreach ($jid in $resp.job_ids) {
                    Write-Host "  Job ID: $jid"
                }
                $allOk = $true
                foreach ($jid in $resp.job_ids) {
                    $result = Wait-ForJob $jid $Wait
                    Write-Verdict $result.result $pkgName $pkgVer $eco
                    if ($result.result.verdict -notin @("pass", "warn")) { $allOk = $false }
                }
                exit $(if ($allOk) { 0 } else { 1 })
            } elseif ($resp.results) {
                $allOk = $true
                foreach ($key in $resp.results.PSObject.Properties.Name) {
                    $r = $resp.results.$key
                    Write-Verdict $r $r.package $r.version $eco
                    if ($r.verdict -notin @("pass", "warn")) { $allOk = $false }
                }
                exit $(if ($allOk) { 0 } else { 1 })
            } else {
                $resp | ConvertTo-Json -Depth 10
            }
        } catch {
            Write-Error "Request failed: $_"
            exit 2
        }
    }

    "rescan" {
        if ($All) {
            $eco = $null
            Write-Host "Requesting rescan of ALL trusted packages..."
        } else {
            if (-not $Args_ -or $Args_.Count -eq 0) {
                Write-Error "Usage: nexus-request rescan <ecosystem> or nexus-request rescan -All"
                exit 2
            }
            $eco = Resolve-Ecosystem $Args_[0]
            if (-not $eco) {
                Write-Error "Unknown ecosystem '$($Args_[0])'. Valid: python, docker, npm, maven, nuget"
                exit 2
            }
            Write-Host "Requesting rescan of all trusted $eco packages..."
        }

        $bodyHash = @{}
        if ($eco) { $bodyHash["ecosystem"] = $eco }
        $body = $bodyHash | ConvertTo-Json

        try {
            $resp = Invoke-RestMethod -Uri "$GatewayUrl/rescan" -Method Post `
                -Headers $Headers -Body $body -TimeoutSec 30
            $count = if ($resp.packages_queued) { $resp.packages_queued } else { 0 }
            Write-Host "  Queued $count package(s) for rescan"
            if ($resp.batch_id) {
                Write-Host "  Batch ID: $($resp.batch_id)"
            }
        } catch {
            Write-Error "Rescan request failed: $_"
            exit 2
        }
    }

    "status" {
        if ($Batch) {
            $r = Invoke-RestMethod -Uri "$GatewayUrl/batch/$Batch/status" -Headers $Headers -TimeoutSec 10
            $r | ConvertTo-Json -Depth 10
        } elseif ($Args_ -and $Args_.Count -gt 0) {
            $r = Invoke-RestMethod -Uri "$GatewayUrl/job/$($Args_[0])" -Headers $Headers -TimeoutSec 10
            Write-Verdict $r.result $r.package $r.version $r.ecosystem
            $r | ConvertTo-Json -Depth 10
        } else {
            Write-Error "Provide a job ID or -Batch <batch_id>"
            exit 2
        }
    }
}
