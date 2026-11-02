@echo off
echo SimplySec - Testing Firewall Rule Naming
echo ======================================
echo.

echo This test requires administrator privileges.
echo.
echo The test results window will open shortly.
echo After the test completes, press Enter in that window to close it.
echo.

powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %CD% && python test_rule_naming.py' -Verb RunAs" 