@echo off
setlocal enabledelayedexpansion

echo SimpleSec - Installation and Setup
echo ================================

echo Checking for Python installation...
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH.
    echo Please install Python 3.8 or newer from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo Installing required Python packages...
pip install -r requirements.txt

echo.
echo Checking for Nmap installation...

:: Check if nmap is installed by running nmap -V
nmap -V >nul 2>&1
if %errorlevel% equ 0 (
    echo Nmap is already installed and ready to use.
    nmap -V | findstr "Nmap version"
    echo.
    echo All dependencies are installed. You can run SimpleSec now.
    goto :FINISH
) else (
    echo Nmap is not installed.
    echo.
    echo Would you like to download and install Nmap now?
    choice /c YN /m "Download and install Nmap now"
    
    if !errorlevel! equ 2 (
        echo.
        echo Please install Nmap manually from https://nmap.org/download.html and run this installer again.
        pause
        exit /b 1
    )
    
    echo.
    echo Downloading Nmap installer...
    
    :: Check if PowerShell is available
    powershell -Command "exit 0" >nul 2>&1
    if !errorlevel! neq 0 (
        echo PowerShell is not available on this system.
        echo Please download and install Nmap manually from https://nmap.org/download.html
        pause
        exit /b 1
    )
    
    :: Clean up any existing files
    if exist "nmap-7.97-setup.exe" del "nmap-7.97-setup.exe"
    if exist "download_nmap.ps1" del "download_nmap.ps1"
    
    :: Create a valid PowerShell script for downloading
    echo try { > download_nmap.ps1
    echo     $client = New-Object System.Net.WebClient >> download_nmap.ps1
    echo     $client.DownloadFile^("https://nmap.org/dist/nmap-7.97-setup.exe", "$PWD\nmap-7.97-setup.exe"^) >> download_nmap.ps1
    echo     Write-Host "Download completed successfully." >> download_nmap.ps1
    echo } catch { >> download_nmap.ps1
    echo     Write-Host "Error downloading file: $_" >> download_nmap.ps1
    echo     exit 1 >> download_nmap.ps1
    echo } >> download_nmap.ps1
    
    :: Run the PowerShell script
    powershell -ExecutionPolicy Bypass -File download_nmap.ps1
    
    :: Check if download was successful
    if not exist "nmap-7.97-setup.exe" (
        echo Failed to download Nmap installer.
        echo Please download and install Nmap manually from https://nmap.org/download.html
        if exist "download_nmap.ps1" del "download_nmap.ps1"
        pause
        exit /b 1
    )
    
    echo Download successful. Running Nmap installer...
    echo Please complete the Nmap installation process.
    echo.
    echo NOTE: After installing Nmap, this script will continue with SimpleSec setup.
    echo.
    
    :: Run the installer
    start /wait nmap-7.97-setup.exe
    
    :: Clean up
    if exist "nmap-7.97-setup.exe" del "nmap-7.97-setup.exe"
    if exist "download_nmap.ps1" del "download_nmap.ps1"
    
    :: Verify installation
    nmap -V >nul 2>&1
    if !errorlevel! neq 0 (
        echo.
        echo Nmap installation was not completed successfully.
        echo Please install Nmap manually and run this installer again.
        pause
        exit /b 1
    ) else (
        echo.
        echo Nmap installed successfully!
    )
)

:FINISH
echo.
echo Installation complete!
echo.
echo To run SimpleSec, you should run as administrator for full functionality.
echo Right-click on run.bat and select "Run as administrator".
echo.
pause
exit /b 0 