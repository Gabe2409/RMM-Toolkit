@echo off
rem Double-click to start the RMM Toolkit window. Asks for admin once (UAC).
rem -ExecutionPolicy Bypass applies to these PowerShell processes only; machine policy is not changed.
setlocal
set "TK_DIR=%~dp0"
set "TK_BAT=%~f0"

fltmc >nul 2>&1
if errorlevel 1 (
    powershell.exe -NoProfile -Command "Start-Process -FilePath $env:TK_BAT -Verb RunAs"
    exit /b
)

rem Files copied from a downloaded zip carry a "from the internet" mark; clear it for the toolkit folder only
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath $env:TK_DIR -Recurse -File | Unblock-File"
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%TK_DIR%Toolkit-GUI.ps1"
