@echo off
echo Starting AI Forensics Lab services...
cd /d "%~dp0"

echo [*] Checking for Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed or not in PATH. Please install Python 3.
    pause
    exit /b 1
)

echo [*] Installing requirements...
pip install -r requirements.txt

echo [*] Checking if port 8000 is already in use...
netstat -ano | findstr :8000 >nul 2>&1
if %errorlevel% equ 0 (
    echo [!] Port 8000 is in use. Please ensure no other instances are running.
)

echo [*] Starting Live Monitor Daemon...
start /B python -u live_monitor.py %* > daemon.log 2>&1

echo =========================================================
echo [+] Live Monitor Daemon started in the background.
echo [+] Launch dashboard by opening http://localhost:8000/index.html
echo =========================================================
pause
