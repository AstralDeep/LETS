# Destroys the warden node and rebuilds it with a fresh genesis budget.
#
# The dashboard's own "Close all and reset" button returns lease residuals to
# the free pool, but budget already consumed by authorized work is gone for
# good -- that is the point of the system. Use this when you want the genesis
# share back.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "This deletes .lets\ (the warden database and its signing key) and re-initializes." -ForegroundColor Yellow
$answer = Read-Host "Type 'reset' to continue"
if ($answer -ne "reset") { Write-Host "Cancelled."; exit 1 }

Get-Process -Name "lets", "python" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*LETS-demo*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

# `lets init` refuses to overwrite existing artifacts, so the directory has to go.
# Scoped to .lets\a on purpose: the production node lives in .lets\prod and is
# reset by scripts\reset-prod.ps1 instead.
Remove-Item -Recurse -Force .lets\a -ErrorAction SilentlyContinue
Remove-Item -Force .lets-demo.json -ErrorAction SilentlyContinue

$out = & ".\.venv\Scripts\lets.exe" --config .lets\a\config.json init `
    --warden-id warden-a `
    --tenant-id example `
    --envelope-id agents `
    --budget 10000,1000000 `
    --local-share 10000,1000000 | ConvertFrom-Json

@{ base_url = "http://127.0.0.1:8741"; token = $out.bootstrap_token } |
    ConvertTo-Json | Set-Content -Encoding utf8 .lets-demo.json

Write-Host "Fresh node ready - key_id $($out.key_id)" -ForegroundColor Green
Write-Host "Next: .\scripts\run.ps1"
