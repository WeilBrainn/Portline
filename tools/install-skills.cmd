@echo off
cd /d "%~dp0.."
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-skills.ps1" -Agent codex
if errorlevel 1 (echo [ERROR] Installation failed.) else (echo [OK] Skills installed.)
pause
