SimplySec 3.0 - tester build
============================

SimplySec checks what other devices can reach on this PC and explains it in plain language.
Scanning is read-only. Every fix is shown to you first, needs administrator permission, is
recorded on the Changes page, and can be undone there.

Needs Windows 10 (1809 or later) or Windows 11, 64-bit. Nothing else to install.
This folder already contains the .NET runtime, so it runs on a PC where .NET was never installed.


Start
-----
1. Unzip the whole folder somewhere you keep programs, for example Documents\SimplySec.
   Keep all the files together; SimplySec.exe needs the files next to it.
2. Double-click SimplySec.exe.
3. This build is not code-signed yet, so Windows may say "Windows protected your PC".
   Click "More info", then "Run anyway". Administrator prompts show "Unknown publisher".

Command line (optional), from a terminal in this folder:
   simplysec-cli.exe scan             read-only scan
   simplysec-cli.exe changes          what SimplySec has changed
   simplysec-cli.exe monitor --status the daily check


Coming from SimplySec 2.0
-------------------------
Your history, accepted risks and recorded changes carry over. If you had the daily check on,
open Settings: SimplySec offers to point the daily check to this copy. Do that before you
delete the 2.0 folder.


Where your data is
------------------
Scan history, settings and log:          %LOCALAPPDATA%\SimplySec
Change journal and firewall backups:     C:\ProgramData\SimplySec


Removing SimplySec
------------------
1. Open the Changes page and undo anything you don't want to keep.
2. In Settings, turn off the daily check (if it is on).
3. Delete this folder. You can also delete the two data folders above.
