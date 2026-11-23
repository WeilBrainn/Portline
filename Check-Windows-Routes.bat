@echo off
setlocal
cd /d "%~dp0"
echo Portline - read-only route check
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\check-route-conflicts.ps1"
echo.
echo Press any key to close the diagnostics window.
pause >nul
