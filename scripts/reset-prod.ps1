# Destroys the production node and rebuilds it with a fresh genesis budget.
#
# Keys and certificates in secrets\ and pki\ are kept, because they are the
# identities the cluster is defined by -- rotating them would mean a new
# manifest. The manifest itself is also kept, so the rebuilt node is the same
# declared cluster with an empty ledger.
#
# The dev node in .lets\a is untouched; use scripts\reset.ps1 for that one.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "This deletes .lets\prod\ (the production database) and state\ (the" -ForegroundColor Yellow
Write-Host "authority anchor and audit archive), then re-initializes the node." -ForegroundColor Yellow
$answer = Read-Host "Type 'reset' to continue"
if ($answer -ne "reset") { Write-Host "Cancelled."; exit 1 }

Get-Process -Name "lets", "python" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -like "*LETS-demo*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

# `lets init` refuses to overwrite existing artifacts. The anchor and the audit
# archive have to go with the database: the anchor records the database's
# authority head, so a fresh database beside an old anchor is a rollback.
Remove-Item -Recurse -Force .lets\prod -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force state -ErrorAction SilentlyContinue
Remove-Item -Force .lets-demo-fleet-prod.json, .lets-demo-verify-prod.json -ErrorAction SilentlyContinue

& ".\.venv-prod\Scripts\python.exe" prod\init_node.py
if ($LASTEXITCODE -ne 0) { throw "init_node.py failed" }

Write-Host ""
Write-Host "Fresh production node ready." -ForegroundColor Green
Write-Host "Next: .\scripts\run-prod.ps1"
