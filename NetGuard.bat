@echo off
rem Launch NetGuard without a console window.
setlocal
cd /d "%~dp0"
where pythonw >nul 2>nul
if errorlevel 1 goto :console
start "" pythonw -m netguard
exit /b 0
:console
python -m netguard
if errorlevel 1 pause
