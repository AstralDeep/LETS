<#
.SYNOPSIS
    Stops the demo's warden and dashboard processes.

.DESCRIPTION
    Normally Ctrl+C in the window running run.ps1 or run-prod.ps1 is enough --
    each script stops its own warden in a finally block. This is for the cases
    where that is not available: a process started detached, a script whose
    window was closed, or a warden left holding its node lock after a crash.

    Processes are found by the port they are listening on rather than by name,
    because these run from uv-managed virtual environments where the reported
    executable path is the interpreter in the uv store, not anything under this
    project -- so filtering on a path containing "LETS-demo" silently matches
    nothing.

    Unlike run/reset there is no separate -prod variant, because stopping is not
    node-specific state surgery: it just releases ports. Stopping both is the
    common case and the default.

.PARAMETER Dev
    Stop only the dev warden (:8741) and dashboard (:8800).

.PARAMETER Prod
    Stop only the production warden (:8443) and dashboard (:8801).

.PARAMETER Force
    Stop the listener even when it does not look like one of ours. Without this,
    a port owned by an unrecognized program is reported and left alone.

.EXAMPLE
    .\scripts\stop.ps1
    Stops everything this demo runs.

.EXAMPLE
    .\scripts\stop.ps1 -Prod
    Stops the production pair and leaves the dev pair running.
#>

[CmdletBinding()]
param(
    [switch]$Dev,
    [switch]$Prod,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$services = @(
    [pscustomobject]@{ Profile = "dev";  Role = "warden";    Port = 8741 }
    [pscustomobject]@{ Profile = "dev";  Role = "dashboard"; Port = 8800 }
    [pscustomobject]@{ Profile = "prod"; Role = "warden";    Port = 8443 }
    [pscustomobject]@{ Profile = "prod"; Role = "dashboard"; Port = 8801 }
)

# No switch means both, which is what you usually want when you are done.
if (-not $Dev -and -not $Prod) { $Dev = $true; $Prod = $true }

$wanted = @()
if ($Dev)  { $wanted += "dev" }
if ($Prod) { $wanted += "prod" }
$targets = $services | Where-Object { $wanted -contains $_.Profile }

# The warden and the dashboard can be the same process only in odd setups, but
# a PID stopped once should not be reported as failing the second time.
$stopped = @{}
$anyFound = $false

foreach ($service in $targets) {
    $label = "{0} {1} (:{2})" -f $service.Profile, $service.Role, $service.Port

    $listener = Get-NetTCPConnection -LocalPort $service.Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $listener) {
        Write-Host ("  not running  {0}" -f $label) -ForegroundColor DarkGray
        continue
    }

    $anyFound = $true
    $processId = $listener.OwningProcess

    if ($stopped.ContainsKey($processId)) {
        Write-Host ("  stopped      {0}  (same process)" -f $label) -ForegroundColor Green
        continue
    }

    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-Host ("  gone         {0}  (pid {1} already exited)" -f $label, $processId) -ForegroundColor DarkGray
        continue
    }

    # Killing whatever happens to hold a port is a good way to take out an
    # unrelated program, so confirm it looks like ours before firing.
    $ours = $process.ProcessName -match '^(python|pythonw|lets|uvicorn)'
    if (-not $ours -and -not $Force) {
        Write-Host ("  SKIPPED      {0}  held by '{1}' (pid {2})" -f $label, $process.ProcessName, $processId) -ForegroundColor Yellow
        Write-Host ("               not recognized as part of this demo; re-run with -Force to stop it anyway")
        continue
    }

    try {
        Stop-Process -Id $processId -Force -ErrorAction Stop
        # Confirm rather than assume: the warden holds an exclusive lock on its
        # node, and a reset that runs before the handle is released will fail to
        # delete the database.
        if (-not $process.WaitForExit(5000)) {
            Write-Host ("  STILL ALIVE  {0}  (pid {1} did not exit within 5s)" -f $label, $processId) -ForegroundColor Red
            continue
        }
        $stopped[$processId] = $true
        Write-Host ("  stopped      {0}  pid {1}" -f $label, $processId) -ForegroundColor Green
    }
    catch {
        Write-Host ("  FAILED       {0}  pid {1}: {2}" -f $label, $processId, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ""
if (-not $anyFound) {
    Write-Host "Nothing was running." -ForegroundColor DarkGray
}
elseif ($stopped.Count -gt 0) {
    Write-Host ("Stopped {0} process(es)." -f $stopped.Count) -ForegroundColor Green
}
