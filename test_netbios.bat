@echo off
echo SimplySec - Testing NetBIOS Disable Function
echo ==========================================
echo.

echo This test requires administrator privileges.
echo.
echo The test results window will open shortly.
echo After the test completes, press Enter in that window to close it.
echo.

powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %CD% && python test_netbios_function.py' -Verb RunAs" 