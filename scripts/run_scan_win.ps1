param(
    [Parameter(Mandatory = $true)]
    [string]$SamplePath
)

# Scan one host file, building the image on request if it is missing.
$projectRoot = Split-Path -Parent $PSScriptRoot
$sample = (Resolve-Path -LiteralPath $SamplePath -ErrorAction Stop).ProviderPath
if (-not (Test-Path -LiteralPath $sample -PathType Leaf)) {
    throw "SamplePath must be a file: $sample"
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'docker is required on the host'
}
& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot connect to Docker; start Docker Desktop or check permissions.'
}

$number = 1
while ((Test-Path -LiteralPath (Join-Path $projectRoot "smoke-win-$number.log")) -or
       (Test-Path -LiteralPath (Join-Path $projectRoot "report-win-$number.log")) -or
       (Test-Path -LiteralPath (Join-Path $projectRoot "build-win-$number.log"))) {
    $number++
}
$smokeLog = Join-Path $projectRoot "smoke-win-$number.log"
$reportLog = Join-Path $projectRoot "report-win-$number.log"
$buildLog = Join-Path $projectRoot "build-win-$number.log"
$extension = [System.IO.Path]::GetExtension($sample)
$staged = Join-Path ([System.IO.Path]::GetTempPath()) ("defender-wine-$([guid]::NewGuid().ToString('N'))$extension")
$containerSample = "/sample/input$extension"

& docker image inspect defender-wine:latest *> $null
if ($LASTEXITCODE -ne 0) {
    $answer = Read-Host 'Image defender-wine is not built. Build it now? [y/N]'
    if ($answer -notmatch '^(y|yes)$') {
        Write-Host 'Build declined; scan not started.'
        exit 2
    }
    Write-Host "Building image (details: $buildLog)..."
    & docker build --progress plain -t defender-wine $projectRoot 2>&1 |
        ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ } } |
        Tee-Object -FilePath $buildLog
    $buildCode = $LASTEXITCODE
    if ($buildCode -ne 0) {
        Write-Host "Build failed (exit $buildCode). Full build log: $buildLog"
        exit $buildCode
    }
}

"[smoke] source: $sample" | Set-Content -LiteralPath $smokeLog -Encoding UTF8
"[smoke] image: defender-wine" | Add-Content -LiteralPath $smokeLog -Encoding UTF8
Write-Host "Running scan inside Docker (details: $smokeLog)..."

$dockerCode = 8
$dockerStarted = $false
try {
    # Docker Desktop cannot always bind-mount mapped drives, so use a local copy.
    Copy-Item -LiteralPath $sample -Destination $staged -ErrorAction Stop
    "[smoke] sample_sha256: $((Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash)" |
        Add-Content -LiteralPath $smokeLog -Encoding UTF8
    $dockerArgs = @('run', '--rm', '--network', 'none', '--memory', '4g',
        '--cpus', '2', '--pids-limit', '256', '--security-opt',
        'no-new-privileges', '--mount',
        "type=bind,source=$staged,target=$containerSample,readonly",
        'defender-wine', 'scan', $containerSample)
    $dockerStarted = $true
    & docker @dockerArgs 2>&1 |
        ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ } } |
        Out-File -LiteralPath $smokeLog -Append -Encoding UTF8
    $dockerCode = $LASTEXITCODE
} catch {
    "[smoke] runner error: $($_.Exception.Message)" | Add-Content -LiteralPath $smokeLog -Encoding UTF8
} finally {
    Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
}

if ($dockerStarted) {
    "[smoke] docker exit_code: $dockerCode" | Add-Content -LiteralPath $smokeLog -Encoding UTF8
} else {
    "[smoke] runner exit_code: $dockerCode (Docker did not start)" | Add-Content -LiteralPath $smokeLog -Encoding UTF8
}

$lines = @(Get-Content -LiteralPath $smokeLog)
$report = New-Object 'System.Collections.Generic.List[string]'
$platform = 'unknown'
$summary = $null
$status = $null
$scanCode = $null
foreach ($line in $lines) {
    if ($line -match '^\[scan\] platform: .*?/Platform/([^/]+)/') { $platform = $Matches[1] }
    if ($line -match '^\[mpscan\] scan summary:') { $summary = $line }
    if ($line -match '^\[mpscan\] (DETECTION_REPORTED|EICAR_CONFIRMED|UNVERIFIED):') { $status = $line }
    if ($line -match '^\[scan\] exit_code: (\d+)') { $scanCode = $Matches[1] }
}
$report.Add("[mpscan] WinDef Platform: $platform")
if ($summary) { $report.Add($summary) } else { $report.Add('[mpscan] scan summary: unavailable; see full smoke log') }
if ($status) { $report.Add($status) } else { $report.Add('[mpscan] detection status unavailable; see full smoke log') }

foreach ($line in $lines) {
    if ($line -match '^\[mpscan\] detection candidate: name="([^"]*)" flags=(0x[0-9a-fA-F]+)') {
        $report.Add('[Detection] Candidate Name: "' + $Matches[1] + '"')
        $report.Add('[Detection] Flag: ' + $Matches[2])
    }
}
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\[mpscan\] SCANSTRUCT') {
        $report.Add('[Detection] SCANSTRUCT')
        for ($j = $i + 1; $j -lt $lines.Count -and $lines[$j] -match '^\s+[0-9a-fA-F]{4}\s{2}'; $j++) {
            $report.Add($lines[$j])
        }
        break
    }
}
if ($scanCode) { $report.Add("[scan] Scan completed, returned $scanCode") } else { $report.Add('[scan] Scan did not complete; see full smoke log') }
if ($dockerStarted) { $report.Add("[smoke] Docker run completed, returned $dockerCode") } else { $report.Add("[smoke] Docker run did not start, runner returned $dockerCode") }
$report | Tee-Object -FilePath $reportLog
Write-Host "Full smoke log: $smokeLog"
Write-Host "Report: $reportLog"
exit $dockerCode
