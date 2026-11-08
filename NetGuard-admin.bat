@echo off
rem Launch NetGuard as administrator - required for "Force offline" (ARP blocking).
setlocal
cd /d "%~dp0"
where pythonw >nul 2>nul
if %errorlevel%==0 (
  powershell -NoProfile -Command "Start-Process pythonw -ArgumentList '-m','netguard' -WorkingDirectory \"%~dp0\" -Verb RunAs"
  exit /b %errorlevel%
)
where py >nul 2>nul
if %errorlevel%==0 (
  powershell -NoProfile -Command "Start-Process py -ArgumentList '-3','-m','netguard' -WorkingDirectory \"%~dp0\" -Verb RunAs"
  exit /b %errorlevel%
)
echo ERROR: pythonw and py were not found on PATH. Install Python from python.org and retry.
pause
exit /b 1
