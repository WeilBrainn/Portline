@echo off
setlocal
cd /d "%~dp0"
title Portline - Build Windows EXE

echo ============================================
echo   Portline - Build from source
 echo ============================================
echo.
where go >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go was not found in PATH.
    echo Install Go from https://go.dev/dl/ and reopen this window.
    goto :failed
)
where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Windows PowerShell was not found.
    goto :failed
)
echo [INFO] Running tests and building server and Windows app...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1"
if errorlevel 1 goto :failed
if not exist "%~dp0Portline.exe" (
    echo [ERROR] Build finished, but Portline.exe was not found.
    goto :failed
)
echo.
echo [OK] Build completed: "%~dp0Portline.exe"
echo.
pause
exit /b 0

:failed
echo.
echo [ERROR] Portline build failed. See messages above.
echo.
pause
exit /b 1
