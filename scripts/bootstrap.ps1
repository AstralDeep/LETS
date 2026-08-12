# Sets up the demo from a clean checkout:
#   venv -> verified release wheel -> `lets init` -> capture the bootstrap token.
#
# `lets init` prints the bootstrap token exactly once and stores only its SHA-256
# digest, so this script captures it into .lets-demo.json. There is no way to
# recover it afterwards -- if that file is lost, run scripts\reset.ps1.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$WheelName = "lets_agent-1.0.10-py3-none-any.whl"
$Base      = "https://github.com/AstralDeep/LETS/releases/download/v1.0.10"

if (Test-Path ".lets\a\config.json") {
    Write-Host "A node already exists at .lets\a\. Run scripts\reset.ps1 to start over." -ForegroundColor Yellow
    exit 1
}

# --- interpreter -------------------------------------------------------------
# LETS requires >=3.11,<3.15. The `py` launcher does not index every install
# (uv-managed builds in particular), so probe each tag and trust the version it
# actually reports rather than the tag name.
$python = ".\.venv\Scripts\python.exe"

if (-not (Test-Path ".venv")) {
    $chosen = $null
    foreach ($tag in @("-V:3.13", "-V:3.12", "-V:3.14", "-V:3.11")) {
        $v = (py $tag -c "import sys;print('%d.%d' % sys.version_info[:2])" 2>$null)
        if ($v -and [version]$v -ge [version]"3.11" -and [version]$v -lt [version]"3.15") {
            $chosen = $tag
            break
        }
    }
    if (-not $chosen) {
        throw "No Python 3.11-3.14 found on the py launcher. LETS requires >=3.11,<3.15."
    }
    py $chosen -m venv .venv
}

$pyver = & $python -c "import sys;print('%d.%d.%d' % sys.version_info[:3])"
Write-Host "Using Python $pyver (.venv)"
& $python -m pip install --upgrade pip --quiet

# --- wheel -------------------------------------------------------------------
# lets-agent is not published to PyPI, so the wheel comes from the GitHub
# release and is checked against the signed-off checksum file beside it.
New-Item -ItemType Directory -Force wheels | Out-Null
if (-not (Test-Path "wheels\$WheelName")) {
    Write-Host "Downloading $WheelName ..."
    Invoke-WebRequest "$Base/$WheelName"       -OutFile "wheels\$WheelName"
    Invoke-WebRequest "$Base/RELEASE_SHA256SUMS" -OutFile "wheels\RELEASE_SHA256SUMS"
}

$line = Get-Content "wheels\RELEASE_SHA256SUMS" | Where-Object { $_ -match [regex]::Escape($WheelName) }
if (-not $line) { throw "RELEASE_SHA256SUMS has no entry for $WheelName" }
$expected = ($line -split '\s+')[0].ToLower()
$actual   = (Get-FileHash -Algorithm SHA256 "wheels\$WheelName").Hash.ToLower()
if ($expected -ne $actual) {
    Remove-Item "wheels\$WheelName" -Force
    throw "SHA256 mismatch for $WheelName`n  expected $expected`n  actual   $actual"
}
Write-Host "SHA256 verified: $actual" -ForegroundColor Green

# The `server` extra pulls fastapi/uvicorn/httpx, which `lets serve` requires
# and the demo app reuses.
& $python -m pip install "wheels\$WheelName[server]" --quiet
Write-Host "Installed lets-agent 1.0.10 with the server extra" -ForegroundColor Green

# --- node --------------------------------------------------------------------
# --budget / --local-share are positional vectors: index 0 is `actions`,
# index 1 is `tokens`, matching DIMENSIONS in demo\policy.py.
$out = & ".\.venv\Scripts\lets.exe" --config .lets\a\config.json init `
    --warden-id warden-a `
    --tenant-id example `
    --envelope-id agents `
    --budget 10000,1000000 `
    --local-share 10000,1000000 | ConvertFrom-Json

@{ base_url = "http://127.0.0.1:8741"; token = $out.bootstrap_token } |
    ConvertTo-Json | Set-Content -Encoding utf8 .lets-demo.json

Write-Host ""
Write-Host "Warden initialized." -ForegroundColor Green
Write-Host "  warden_id : $($out.warden_id)"
Write-Host "  key_id    : $($out.key_id)"
Write-Host "  budget    : 10000 actions, 1000000 tokens"
Write-Host "  token     : saved to .lets-demo.json (only its SHA-256 lives in the node config)"
Write-Host ""
Write-Host "Next: .\scripts\run.ps1"
