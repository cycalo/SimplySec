@echo off
echo Starting SimpleSec - Network Security Tool
echo =========================================
echo.

echo Checking dependencies...
python check_nmap.py
if %errorlevel% neq 0 (
    echo.
    echo Please install Nmap and then run this program again.
    pause
    exit
)

echo.
echo Starting SimpleSec...
python main.py

pause 