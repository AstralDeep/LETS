# Provisions the production node from a clean checkout.
#
# This builds the configuration LETS calls production: an operator-signed
# cluster manifest, inbound mutual TLS, an external Ed25519 signer, and JWT
# identities. It is entirely separate from the dev node in .lets\a, which keeps
# working exactly as before.
#
# Every step is idempotent -- existing seeds, certificates and the manifest are
# reused rather than regenerated, because regenerating any of them would
# invalidate the node that was initialized against them.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")


if (Test-Path ".lets\prod\config.json") {
    Write-Host "A production node already exists at .lets\prod\." -ForegroundColor Yellow
    Write-Host "Run scripts\reset-prod.ps1 to start over."
    exit 1
}

# --- interpreter -------------------------------------------------------------
# `serve --production` refuses to run on a SQLite build without the 2026 WAL
# reset fix: it wants 3.53+, the 3.51.3 line, the 3.50.7+ backport, or the
# 3.44.6+ backport. That is a property of the interpreter's bundled SQLite, not
# of anything installable, so the right interpreter has to be found first.
$probe = @'
import sqlite3, sys
v = tuple(sqlite3.sqlite_version_info[:3])
ok = ((3,51,3) <= v < (3,52,0)) or v >= (3,53,0) or ((3,50,7) <= v < (3,51,0)) or ((3,44,6) <= v < (3,45,0))
py = sys.version_info[:2]
print("OK" if (ok and (3,11) <= py < (3,15)) else "NO", "%d.%d.%d" % sys.version_info[:3], sqlite3.sqlite_version)
'@

$python = ".\.venv-prod\Scripts\python.exe"

if (-not (Test-Path ".venv-prod")) {
    $candidates = @()
    Get-ChildItem -Path (Join-Path $env:APPDATA "uv\python") -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { $candidates += (Join-Path $_.FullName "python.exe") }
    foreach ($tag in @("-V:3.11", "-V:3.12", "-V:3.13", "-V:3.14")) {
        $found = (py $tag -c "import sys;print(sys.executable)" 2>$null)
        if ($found) { $candidates += $found }
    }

    $chosen = $null
    $seen = @{}
    foreach ($candidate in $candidates) {
        if (-not (Test-Path $candidate) -or $seen.ContainsKey($candidate)) { continue }
        $seen[$candidate] = $true
        $result = (& $candidate -c $probe 2>$null)
        if ($result -and $result.StartsWith("OK")) {
            $chosen = $candidate
            Write-Host "Using $candidate  ($result)" -ForegroundColor Green
            break
        }
        if ($result) { Write-Host "  skipping $candidate ($result)" -ForegroundColor DarkGray }
    }

    if (-not $chosen) {
        throw @"
No interpreter on this machine satisfies production admission.
`serve --production` needs Python 3.11-3.14 built against SQLite 3.53+,
3.51.3+, 3.50.7+, or 3.44.6+. Install one (uv python install 3.11 is the
quickest) and re-run this script.
"@
    }
    & $chosen -m venv .venv-prod
}

& $python -m pip install --upgrade pip --quiet

# --- lets-agent --------------------------------------------------------------
# Installed from this repository's tree, one directory above the demo.
& $python -m pip install "..[server]" --quiet
# Only used to mint the X.509 material below; LETS itself does not need it.
& $python -m pip install cryptography --quiet
Write-Host "Installed lets-agent from this tree into .venv-prod" -ForegroundColor Green

# --- key material ------------------------------------------------------------
Write-Host ""
Write-Host "Generating Ed25519 keys (warden signer, operator, JWT issuer) ..."
& $python prod\make_keys.py
if ($LASTEXITCODE -ne 0) { throw "make_keys.py failed" }

Write-Host ""
Write-Host "Generating the TLS certificate authorities and leaf certificates ..."
& $python prod\make_pki.py
if ($LASTEXITCODE -ne 0) { throw "make_pki.py failed" }

# --- manifest ----------------------------------------------------------------
Write-Host ""
Write-Host "Building and operator-signing the cluster manifest ..."
& $python prod\build_manifest.py
if ($LASTEXITCODE -ne 0) { throw "build_manifest.py failed" }

# --- node --------------------------------------------------------------------
Write-Host ""
Write-Host "Initializing the node under --production ..."
& $python prod\init_node.py
if ($LASTEXITCODE -ne 0) { throw "init_node.py failed" }

Write-Host ""
Write-Host "Production node ready." -ForegroundColor Green
Write-Host "  manifest : prod\cluster-manifest.json  (operator-signed)"
Write-Host "  identity : short-lived EdDSA JWTs, no stored credential"
Write-Host "  transport: mutual TLS on https://127.0.0.1:8443"
Write-Host "  signer   : external subprocess, prod\signer.py"
Write-Host ""
Write-Host "Next: .\scripts\run-prod.ps1"
