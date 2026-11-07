@echo off
rem Launch NetGuard as administrator - required for "Force offline" (ARP blocking).
setlocal
cd /d "%~dp0"
powershell -NoProfile -Command "Start-Process pythonw -ArgumentList '-m','netguard' -WorkingDirectory '%~dp0' -Verb RunAs"
if errorlevel 1 pause
