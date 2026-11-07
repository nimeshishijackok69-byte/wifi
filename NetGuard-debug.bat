@echo off
rem Launch NetGuard with a console so errors stay visible.
setlocal
cd /d "%~dp0"
python -m netguard
pause
