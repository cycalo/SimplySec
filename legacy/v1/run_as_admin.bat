@echo off
:: Check for admin rights and elevate if needed
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    goto UACPrompt
) else (
    goto GotAdmin
)

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:GotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

:: Run the actual script
echo SimplySec - Network Security Tool
echo ================================
echo.

:: Check and install Python dependencies if needed
echo Checking Python dependencies...
python -m pip install -r requirements.txt --user
if %errorlevel% neq 0 (
    echo.
    echo Failed to install required Python dependencies.
    echo Please run 'python -m pip install -r requirements.txt --user' manually.
    pause
    exit
)

:: Check Nmap dependency
echo Checking Nmap dependency...
python check_nmap.py
if %errorlevel% neq 0 (
    echo.
    echo Please install Nmap and then run this program again.
    pause
    exit
)

echo.
echo Starting SimplySec with administrator privileges...
python main.py

pause 