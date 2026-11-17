# Starts the production warden and the production dashboard.
# Ctrl+C stops both. The dev node on :8741 is unaffected and can run alongside.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Test-Path ".lets\prod\config.json")) {
    throw "No production node found. Run scripts\bootstrap-prod.ps1 first."
}

$lets   = (Resolve-Path ".\.venv-prod\Scripts\lets.exe").Path
$python = (Resolve-Path ".\.venv-prod\Scripts\python.exe").Path

# --production is the whole point: it refuses to start without an
# operator-signed manifest, TLS, inbound mTLS, and an external runtime provider.
# Removing any one of these flags is a useful thing to try -- the refusal is the
# feature.
$warden = Start-Process -FilePath $lets `
    -ArgumentList @(
        "--config", ".lets\prod\config.json", "serve", "--production",
        "--host", "127.0.0.1", "--port", "8443",
        "--tls-cert", "pki\warden.crt",
        "--tls-key", "pki\warden.key",
        "--client-ca", "pki\ca.crt"
    ) -PassThru -NoNewWindow

try {
    Write-Host "Waiting for the production warden to report ready ..."
    & $python prod\wait_ready.py
    if ($LASTEXITCODE -ne 0) { throw "The production warden did not become ready." }

    Write-Host "Warden ready on https://127.0.0.1:8443 (mutual TLS required)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Verify it is genuinely hardened, in another terminal:" -ForegroundColor Cyan
    Write-Host "  .\.venv-prod\Scripts\python.exe verify_production.py"
    Write-Host "  `$env:LETS_DEMO_PROFILE='production'; .\.venv-prod\Scripts\python.exe verify_core_four.py"
    Write-Host ""

    $env:LETS_DEMO_PROFILE = "production"
    Start-Process "http://127.0.0.1:8801/"
    Write-Host "Dashboard: http://127.0.0.1:8801/   (Ctrl+C to stop)" -ForegroundColor Green
    & $python -m uvicorn demo.server:app --host 127.0.0.1 --port 8801 --log-level warning
}
finally {
    if ($warden -and -not $warden.HasExited) {
        Write-Host "Stopping the production warden ..."
        $warden | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}
