# SimplySec 3.0

Plain-language security checks for Windows home and small-business PCs. SimplySec reports what
other devices can **really** reach on this PC, explains it simply, fixes precisely, verifies each
change by reading it back, and can undo everything it did.

- Scanning is read-only and works without administrator rights.
- Every change is previewed, needs administrator permission, is recorded with its previous
  value, and can be undone from the app or the command line.
- SimplySec never kills processes, disables core Windows services, adds outbound rules or
  restarts the firewall.

Written in C# on .NET 10, with a WPF window (WPF-UI). The previous Python version (2.0) is kept at git tag
`v2-python`. SimplySec 3.0 reads 2.0's history and change journal and can undo 2.0's changes.

## What it checks

| Area | Examples |
|---|---|
| Exposure | Which listening programs other devices can reach through the firewall, on which network, and why (rule names). Known apps such as Ollama, Spotify or Tailscale are described neutrally; if you set something up on purpose it says so and offers *Keep*. |
| Firewall | Profiles turned off, default inbound action Allow |
| Remote access | Remote Desktop reachable, NLA off, Remote Assistance on |
| Legacy protocols | SMBv1 server, LLMNR, NetBIOS (optional fixes) |
| File sharing | Shares open to Everyone (guidance) |
| Malware protection | No active antivirus, real-time or tamper protection off, old definitions, ransomware protection |
| Updates | Last update too long ago, updates paused, restart pending |
| Accounts | UAC off, Guest enabled, blank-password network logons |
| System | AutoRun, BitLocker |
| Wi-Fi | Saved open/WEP/TKIP networks that connect automatically; connected to an open network now |
| Home network | Devices on networks you confirm are yours (vendor, name, risky services such as Telnet or an open Docker API), new devices |
| Router | UPnP on, port forwards to this PC or other devices, CGNAT |
| Housekeeping | Rules left behind by SimpleSec v1, managed (domain / Group Policy) PCs |

## Build and run

Requires Windows 10 1809+ or Windows 11 (x64) and the .NET SDK pinned in `global.json` (10.0.4xx).
Run everything from the repository root.

```powershell
dotnet build SimplySec.slnx
dotnet run --project src/SimplySec.App                 # the app (read-only mode unless elevated)
dotnet run --project src/SimplySec.Cli -- scan         # the command line
```

### Tests

```powershell
dotnet test --project tests/SimplySec.Core.Tests       # logic, golden corpus (~25 s)
dotnet test --project tests/SimplySec.Windows.Tests    # OS layer on this PC, read-only (~10 s)
dotnet test --project tests/SimplySec.App.Tests        # view models and windows (~5 s)
```

The admin end-to-end tests change this PC and undo it. They run only from an elevated prompt with
`$env:SIMPLYSEC_ADMIN_TESTS = '1'`.

### Tester build

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build.ps1 [-SkipTests] [-DefenderScan]
```

This runs the tests, publishes both programs self-contained (no .NET needed on the tester's PC)
into `dist\SimplySec-<version>-win64\`, and zips it to `dist\SimplySec-<version>-win64.zip`.
The zip includes a short `README.txt` for testers (`packaging\win64\README.txt`). The programs
are **not code-signed** yet, so SmartScreen warns on first run. The script has a signing hook
for later. nmap is never bundled; install it yourself for the optional deep network scan.

## Command line

`SimplySec.exe` is the window; `simplysec-cli.exe` is the command line:

```
simplysec-cli scan [--json]                     read-only scan
simplysec-cli scan --network [--deep]           also scan your home network (asks "Is this your network?")
simplysec-cli fix recommended                   safe, non-disruptive fixes (preview + confirm)
simplysec-cli fix --finding ID --fix FIX_ID     one fix; add --mark-private, --restore-point, --elevate
simplysec-cli keep --finding ID [--undo]        accept a risk ("Keep: I need this")
simplysec-cli changes                           everything SimplySec changed
simplysec-cli undo --change N | --batch N | --all | --rules
simplysec-cli history [--limit N]               saved scans with score changes
simplysec-cli report --html [PATH]              printable HTML report
simplysec-cli monitor --enable [HH:MM]          daily background check (administrator; undoable)
simplysec-cli monitor --disable | --status | --run
```

`fix`, `undo` and `monitor --enable/--disable` need an elevated prompt (or `--elevate` for a UAC
prompt). `SimplySec.exe` accepts the same arguments without opening a window; the daily-check
task uses `SimplySec.exe monitor --run`.

## Where things are stored

| Path | Contents |
|---|---|
| `%ProgramData%\SimplySec\simplysec.db` | change journal (only administrators can write) |
| `%ProgramData%\SimplySec\backups\` | firewall exports taken before each change (newest 10) |
| `%LOCALAPPDATA%\SimplySec\history.db` | your scans, settings and accepted risks |
| `%LOCALAPPDATA%\SimplySec\logs\` | log files |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): projects, the exposure model, journal and undo
- [docs/ADDING_A_CHECK.md](docs/ADDING_A_CHECK.md): how to add a check
- [docs/SESSION_SUMMARY.md](docs/SESSION_SUMMARY.md): where development stands, decisions, gotchas
- [docs/TODO.md](docs/TODO.md): what is left to do
- [docs/original-brief.md](docs/original-brief.md): the original brief
- Earlier versions: tag `v1-legacy` (v1), tag `v2-python` (2.0, Python).

## License

MIT
