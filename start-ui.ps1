<#
.SYNOPSIS
    Start the VulnBox local Web UI on Windows, macOS, or Linux (PowerShell / pwsh).
    All virtual environments and caches stay strictly local to this repository.
.EXAMPLE
    .\start-ui.ps1
    .\start-ui.ps1 --port 8787 --no-browser
    .\start-ui.ps1 --install
#>

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Launcher = Join-Path (Join-Path $ScriptDir "scripts") "start_ui.py"
$CacheDir = Join-Path $ScriptDir ".vulnbox-cache"

$env:UV_PROJECT_ENVIRONMENT = Join-Path $ScriptDir ".venv"
$env:UV_CACHE_DIR = Join-Path $CacheDir "uv"
$env:UV_PYTHON_INSTALL_DIR = Join-Path $CacheDir "python"
$env:PIP_CACHE_DIR = Join-Path $CacheDir "pip"
$env:PIP_USER = "0"
$env:PYTHONNOUSERSITE = "1"

$VenvWin = Join-Path (Join-Path (Join-Path $ScriptDir ".venv") "Scripts") "python.exe"
$VenvPosix = Join-Path (Join-Path (Join-Path $ScriptDir ".venv") "bin") "python"

if (Test-Path $VenvWin) {
    & $VenvWin $Launcher @args
    exit $LASTEXITCODE
}
elseif (Test-Path $VenvPosix) {
    & $VenvPosix $Launcher @args
    exit $LASTEXITCODE
}
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $Launcher @args
    exit $LASTEXITCODE
}
elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    & python3 $Launcher @args
    exit $LASTEXITCODE
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python $Launcher @args
    exit $LASTEXITCODE
}
elseif (Get-Command uv -ErrorAction SilentlyContinue) {
    & uv run --project $ScriptDir python $Launcher @args
    exit $LASTEXITCODE
}
else {
    Write-Error "[vulnbox] Python 3.11+ or uv is required to start the VulnBox Web UI."
    exit 1
}
