@echo off
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Install Python 3.11 or newer from python.org and enable the Python launcher.
  pause
  exit /b 1
)
py -3 bootstrap.py
pause
