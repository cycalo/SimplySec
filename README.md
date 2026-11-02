# SimplySec 2.0

Plain-language security checks for Windows home and small-business PCs. SimplySec reports what
other devices can **really** reach on this PC, explains it simply, fixes precisely, verifies each
change by reading it back, and can undo everything it did.

- Scanning is read-only and works without administrator rights.
- Every change is previewed, needs administrator permission, is recorded with its previous
  value, and can be undone from the app or the command line.
- SimplySec never kills processes, disables core Windows services, adds outbound rules or
  restarts the firewall.

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

## Install and run from source

Requires Windows 10/11 and Python 3.11+.

```powershell
py -3.11 -m venv .venv
.venv\Scripts\pip install -e .[dev]
.venv\Scripts\python -m simplysec            # GUI
.venv\Scripts\python -m simplysec scan       # CLI, read-only
```

## Command line

```
simplysec                                   start the GUI
simplysec scan [--json]                     read-only scan
simplysec scan --network [--deep]           also scan your home network (asks "Is this your network?")
simplysec fix recommended                   safe, non-disruptive fixes (preview + confirm)
simplysec fix --finding ID --fix FIX_ID     one fix; add --mark-private, --restore-point, --elevate
simplysec keep --finding ID [--undo]        accept a risk ("Keep: I need this")
simplysec changes                           everything SimplySec changed
simplysec undo --change N | --batch N | --all | --rules
simplysec history                           saved scans with score changes
simplysec report --html [PATH]              printable HTML report
simplysec monitor --enable [HH:MM]          daily background check (administrator; undoable)
simplysec monitor --disable | --run
```

`fix` and `undo` need an elevated prompt (or `--elevate` for a UAC prompt).

## Where things are stored

| Path | Contents |
|---|---|
| `%ProgramData%\SimplySec\simplysec.db` | change journal (only administrators can write) |
| `%ProgramData%\SimplySec\backups\` | firewall exports taken before each change (newest 10) |
| `%LOCALAPPDATA%\SimplySec\history.db` | your scans, settings and accepted risks |
| `%LOCALAPPDATA%\SimplySec\logs\` | log files |

## Development

```powershell
.venv\Scripts\pytest                     # unit tests (no admin)
.venv\Scripts\pytest -m admin            # elevated end-to-end tests (changes and restores this PC)
.venv\Scripts\ruff check src tests
.venv\Scripts\ruff format --check src tests
.venv\Scripts\mypy src\simplysec\core
```

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the exposure model, journal and undo work
- [docs/ADDING_A_CHECK.md](docs/ADDING_A_CHECK.md): how to add a check
- [docs/PLAN.md](docs/PLAN.md): the v2 plan; [docs/original-brief.md](docs/original-brief.md): the original brief
- v1 is preserved in [legacy/v1/](legacy/v1/) and at tag `v1-legacy`.

## License

MIT
