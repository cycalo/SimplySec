Option Explicit

' Get the path to the script directory
Dim fso, scriptPath
Set fso = CreateObject("Scripting.FileSystemObject")
scriptPath = fso.GetParentFolderName(WScript.ScriptFullName)

' Run SimpleSec as administrator
Dim shell, appPath
Set shell = CreateObject("Shell.Application")
appPath = scriptPath & "\main.py"

' Request admin privileges and launch
shell.ShellExecute "python", """" & appPath & """", "", "runas", 1 