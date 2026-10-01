param(
    [ValidateSet('selftest', 'scan')]
    [string]$Mode = 'selftest',
    [string]$SamplePath,
    [string]$WineDebug = '-all',
    [switch]$SkipBuild
)

$projectRoot = Split-Path -Parent $PSScriptRoot
$numbers = @(Get-ChildItem -LiteralPath $projectRoot -Filter 'smoke*.log' | ForEach-Object {if ($_.Name -match '^smoke(\d+)\.log$') { [int]$Matches[1] }})
$next = if ($numbers.Count) { (($numbers | Measure-Object -Maximum).Maximum + 1) } else { 1 }
$logPath = Join-Path $projectRoot "smoke$next.log"
$buildLogPath = Join-Path $projectRoot "build$next.log"

if ($Mode -eq 'scan') {
    if (-not $SamplePath) { throw '-SamplePath is required for scan mode.' }
    $sample = (Resolve-Path -LiteralPath $SamplePath -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $sample -PathType Leaf)) {
        throw "SamplePath must be a file: $sample"
    }
}

Set-Location -LiteralPath $projectRoot
$exitCode = 0
"[smoke] source SHA256: $((Get-FileHash -LiteralPath 'mpscan/mpscan.c' -Algorithm SHA256).Hash)" | Set-Content -LiteralPath $logPath -Encoding UTF8

if (-not $SkipBuild) {
    Write-Host "Building image (details: $buildLogPath)..."
    & docker build --quiet -t defender-wine . 2>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ } } | Out-File -LiteralPath $buildLogPath -Encoding UTF8
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Write-Host "Build failed (exit $exitCode). Last lines:"
        Get-Content -LiteralPath $buildLogPath -Tail 20
        exit $exitCode
    }
}

$dockerArgs = @('run', '--rm', '--network', 'none', '--pids-limit', '256', '--security-opt', 'no-new-privileges', '-e', "WINEDEBUG=$WineDebug")
$stagedSample = $null
if ($Mode -eq 'scan') {
    $extension = [System.IO.Path]::GetExtension($sample)
    $stagedSample = Join-Path ([System.IO.Path]::GetTempPath()) ("defender-wine-$([guid]::NewGuid().ToString('N'))$extension")
    Write-Host "Staging file on local drive for Docker..."
    try {
        Copy-Item -LiteralPath $sample -Destination $stagedSample -ErrorAction Stop
    } catch {
        Remove-Item -LiteralPath $stagedSample -Force -ErrorAction SilentlyContinue
        throw
    }
    $containerSample = "/sample/input$extension"
    $dockerArgs += @('--mount', "type=bind,source=$stagedSample,target=$containerSample,readonly")
    $dockerArgs += @('defender-wine', 'scan', $containerSample)
} else {
    $dockerArgs += @('defender-wine', 'selftest')
}
"[smoke] docker $($dockerArgs -join ' ')" | Add-Content -LiteralPath $logPath -Encoding UTF8
Write-Host "Running $Mode inside Docker (details: $logPath)..."
& docker @dockerArgs 2>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ } } | Out-File -LiteralPath $logPath -Append -Encoding UTF8
$exitCode = $LASTEXITCODE
if ($stagedSample) {
    try {
        Remove-Item -LiteralPath $stagedSample -Force -ErrorAction Stop
    } catch {
        Write-Warning "Could not remove staged sample: $stagedSample"
    }
}
"[smoke] docker exit_code: $exitCode" | Add-Content -LiteralPath $logPath -Encoding UTF8

$summary = @(Select-String -LiteralPath $logPath -Pattern 'BOOTENGINE|ACCESS VIOLATION|failed rc|detection candidate|scan summary|EICAR_CONFIRMED|UNVERIFIED|exit_code|\[selftest\]' |
    Select-Object -Last 12)
if ($summary.Count) {
    $summary | ForEach-Object { Write-Host $_.Line }
} else {
    Get-Content -LiteralPath $logPath -Tail 12
}
Write-Host "Full smoke log: $logPath"
exit $exitCode
