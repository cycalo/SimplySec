@echo off
echo SimpleSec - Add Custom Firewall Rule
echo ===================================
echo.

rem Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: This script must be run as administrator.
    echo Please right-click and select "Run as administrator".
    pause
    exit /b 1
)

rem Get user input
set /p RULE_NAME="Enter rule name: "
echo.
echo Direction:
echo 1. Inbound (in)
echo 2. Outbound (out)
set /p DIRECTION_CHOICE="Enter choice (1/2): "

if "%DIRECTION_CHOICE%"=="1" (
    set DIRECTION=in
) else if "%DIRECTION_CHOICE%"=="2" (
    set DIRECTION=out
) else (
    echo Invalid choice.
    pause
    exit /b 1
)

echo.
echo Action:
echo 1. Allow
echo 2. Block
set /p ACTION_CHOICE="Enter choice (1/2): "

if "%ACTION_CHOICE%"=="1" (
    set ACTION=allow
) else if "%ACTION_CHOICE%"=="2" (
    set ACTION=block
) else (
    echo Invalid choice.
    pause
    exit /b 1
)

echo.
echo Rule type:
echo 1. Port rule
echo 2. Program rule
echo 3. Remote IP rule
set /p TYPE_CHOICE="Enter choice (1/2/3): "

if "%TYPE_CHOICE%"=="1" (
    set /p PORT="Enter port number: "
    echo.
    echo Protocol:
    echo 1. TCP
    echo 2. UDP
    set /p PROTO_CHOICE="Enter choice (1/2): "
    
    if "%PROTO_CHOICE%"=="1" (
        set PROTOCOL=TCP
    ) else if "%PROTO_CHOICE%"=="2" (
        set PROTOCOL=UDP
    ) else (
        echo Invalid choice.
        pause
        exit /b 1
    )
    
    python add_custom_rule.py --name "%RULE_NAME%" --direction %DIRECTION% --action %ACTION% --port %PORT% --protocol %PROTOCOL%
    
) else if "%TYPE_CHOICE%"=="2" (
    set /p PROGRAM="Enter program path (e.g. C:\Program Files\app.exe): "
    python add_custom_rule.py --name "%RULE_NAME%" --direction %DIRECTION% --action %ACTION% --program "%PROGRAM%"
    
) else if "%TYPE_CHOICE%"=="3" (
    set /p REMOTE_IP="Enter remote IP address or range (e.g. 192.168.1.0/24): "
    python add_custom_rule.py --name "%RULE_NAME%" --direction %DIRECTION% --action %ACTION% --remote-ip "%REMOTE_IP%"
    
) else (
    echo Invalid choice.
    pause
    exit /b 1
)

echo.
echo Done.
pause 