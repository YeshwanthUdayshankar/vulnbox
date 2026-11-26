@echo off
REM Start the VulnBox local Web UI on Windows (Command Prompt or double-click).
REM All virtual environments and caches stay strictly local to this repository.
REM Usage: start-ui.bat [--port 8787] [--host 127.0.0.1] [--no-browser] [--install]

setlocal
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "LAUNCHER=%SCRIPT_DIR%\scripts\start_ui.py"
set "VENV_PY=%SCRIPT_DIR%\.venv\Scripts\python.exe"

set "UV_PROJECT_ENVIRONMENT=%SCRIPT_DIR%\.venv"
set "UV_CACHE_DIR=%SCRIPT_DIR%\.vulnbox-cache\uv"
set "UV_PYTHON_INSTALL_DIR=%SCRIPT_DIR%\.vulnbox-cache\python"
set "PIP_CACHE_DIR=%SCRIPT_DIR%\.vulnbox-cache\pip"
set "PIP_USER=0"
set "PYTHONNOUSERSITE=1"

if exist "%VENV_PY%" (
    "%VENV_PY%" "%LAUNCHER%" %*
    exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3 "%LAUNCHER%" %*
    exit /b %ERRORLEVEL%
)

where python >nul 2>nul
if %ERRORLEVEL%==0 (
    python "%LAUNCHER%" %*
    exit /b %ERRORLEVEL%
)

where uv >nul 2>nul
if %ERRORLEVEL%==0 (
    uv run --project "%SCRIPT_DIR%" python "%LAUNCHER%" %*
    exit /b %ERRORLEVEL%
)

echo [vulnbox] Error: Python 3.11+ or uv is required to start the VulnBox Web UI. 1>&2
exit /b 1
