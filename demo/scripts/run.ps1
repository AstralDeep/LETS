# Starts the warden and the demo app, then opens the dashboard.
# Ctrl+C stops both.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Test-Path ".lets\a\config.json")) { throw "No node found. Run scripts\bootstrap.ps1 first." }
if (-not (Test-Path ".lets-demo.json"))     { throw "No .lets-demo.json. Run scripts\bootstrap.ps1 first." }

$lets   = (Resolve-Path ".\.venv\Scripts\lets.exe").Path
$python = (Resolve-Path ".\.venv\Scripts\python.exe").Path

# The warden takes an exclusive lock on .lets\a\.node.lock, so a second `serve`
# against the same config will refuse to start. That is intended.
$warden = Start-Process -FilePath $lets `
    -ArgumentList "--config", ".lets\a\config.json", "serve", "--host", "127.0.0.1", "--port", "8741" `
    -PassThru -NoNewWindow

try {
    Write-Host "Waiting for the warden to report ready ..."
    $ready = $false
    foreach ($_ in 1..60) {
        Start-Sleep -Milliseconds 500
        try {
            if ((Invoke-RestMethod "http://127.0.0.1:8741/health/ready" -TimeoutSec 2).status -eq "ready") {
                $ready = $true; break
            }
        } catch { }
    }
    if (-not $ready) { throw "The warden did not become ready. Check that port 8741 is free." }

    $info = Invoke-RestMethod "http://127.0.0.1:8741/v1/info"
    Write-Host "Warden ready: $($info.warden_id) - protocol $($info.protocol)" -ForegroundColor Green

    Start-Process "http://127.0.0.1:8800/"
    Write-Host "Dashboard: http://127.0.0.1:8800/   (Ctrl+C to stop)" -ForegroundColor Green
    & $python -m uvicorn demo.server:app --host 127.0.0.1 --port 8800 --log-level warning
}
finally {
    if ($warden -and -not $warden.HasExited) {
        Write-Host "Stopping the warden ..."
        $warden | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}
