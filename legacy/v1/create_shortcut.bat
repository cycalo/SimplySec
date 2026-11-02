@echo off
echo Creating SimpleSec desktop shortcut...

set SCRIPT_PATH=%~dp0
set SHORTCUT_NAME=SimpleSec.lnk
set DESKTOP_PATH=%USERPROFILE%\Desktop
set TARGET=%SCRIPT_PATH%run_as_admin.bat
set ICON=%SCRIPT_PATH%\main.py

echo Set oWS = WScript.CreateObject("WScript.Shell") > "%temp%\shortcut.vbs"
echo sLinkFile = "%DESKTOP_PATH%\%SHORTCUT_NAME%" >> "%temp%\shortcut.vbs"
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> "%temp%\shortcut.vbs"
echo oLink.TargetPath = "%TARGET%" >> "%temp%\shortcut.vbs"
echo oLink.WorkingDirectory = "%SCRIPT_PATH%" >> "%temp%\shortcut.vbs"
echo oLink.Description = "SimpleSec Network Security Tool" >> "%temp%\shortcut.vbs"
echo oLink.IconLocation = "%WINDIR%\System32\SHELL32.dll,47" >> "%temp%\shortcut.vbs"
echo oLink.Save >> "%temp%\shortcut.vbs"
"%temp%\shortcut.vbs"
del "%temp%\shortcut.vbs"

echo.
echo Shortcut created on your desktop.
echo You can now run SimpleSec by double-clicking the shortcut.
echo.
pause 