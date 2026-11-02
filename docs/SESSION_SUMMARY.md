# Session summary: SimplySec 2.0 build (2026-11-02)

This session carried out [PLAN.md](PLAN.md): a rewrite of SimplySec v1 into an app that
reports what other devices can really reach on this PC, explains it plainly, fixes precisely,
verifies each change and can undo everything. It then refined the GUI based on hands-on
feedback.

All work is on branch `v2` (not pushed). v1 is preserved at tag `v1-legacy` on
`main` and in [legacy/v1/](../legacy/v1/). See [ARCHITECTURE.md](ARCHITECTURE.md) for how it
works and [ADDING_A_CHECK.md](ADDING_A_CHECK.md) for extending it.

## How to run it

```powershell
.venv\Scripts\python -m simplysec            # GUI (read-only until you apply a fix)
.venv\Scripts\python -m simplysec scan       # CLI scan
dist\SimplySec\SimplySec.exe                 # built exe (rebuild with scripts\build.ps1)
```

Run from an elevated prompt, or use Settings > Restart as administrator, to apply and undo
fixes without a UAC prompt each time.

## What was built, by milestone

| Commit | Milestone | Contents |
|---|---|---|
| `b723b89` | M0 Housekeeping | v1 baseline tagged; v1 source moved to `legacy/v1/`, runtime leftovers to `legacy/v1-artifacts/` (git-ignored); `pyproject.toml`; venv rebuilt (Python 3.11) |
| `0e75166` | M1 Core | `windows/` OS layer (psutil, firewall COM, `facts.ps1`, registry, services, accounts); pure exposure evaluator; TOML knowledge base; 10 check areas; reversible primitives, SQLite journal, allow-listed apply/undo; scoring and Keep; CLI; GUI (Overview, This PC, Open ports, Changes, Settings) |
| `2c2e9dc` | M2 Home network | confirmed-network scan (async discovery and service probes, OUI vendors, randomized MACs, reverse DNS, SSDP names, optional nmap), device inventory, read-only UPnP router check, Wi-Fi profile checks, My network page |
| `55850f0` | M3 History and reports | scan comparison, History page with trend chart, printable HTML report (`simplysec report --html`) |
| `898b59f` | M4 Monitoring | journaled `\SimplySec\Daily check` task, `monitor --run`, toast notifications |
| `3e1d4cb` | M5 Standalone exe | PyInstaller onedir build (`SimplySec.exe` + `simplysec-cli.exe`), icon, version info, `scripts/build.ps1` |

Follow-up changes after hands-on testing:

| Commit | Change |
|---|---|
| `4b33445` | The GUI no longer scans automatically on start |
| `801f74c` | Progress panel: steps done, current step, elapsed time (later: the "usually about N s" text and the "taking longer than usual" warning were replaced by a "still working" note after 150 s without news from a step); CLI progress shows elapsed seconds |
| `ab3d1c5` | Fix: the progress panel stayed open after a scan finished (a background task's "finished" signal could be lost) |
| `0bcd219` | Overview cards show "What this means" and a link to the full card; the confirmation window shows *why* each fix is suggested |
| `a130338` | Impact analysis ("What uses this") for every fix; Fix recommended leaves out anything in use; per-fix tick boxes in the confirmation window; This PC ordered by severity with informational items hidden by default; Open ports "In use now" column |
| `43789e0` | Overview cards expand in place ("Show more") instead of jumping to This PC |
| `e9f50b3` | Sidebar shows a coloured mode label (amber Read-only / green Administrator) with a "Restart as administrator" button |
| `1bef7a9` | Guidance about other devices: My network page shows "What to do about your devices" cards (advice visible; click a device row to jump to its card) and router findings with steps in the Router section; router findings explain where to change the setting; This PC has a separate "Other devices on your network and your router" group; Overview lists "Top things to look at", including advice-only findings with a "How to fix" toggle |

### Scope of the network scan

The app scans other devices only on a network you confirm is yours. It finds devices, their
maker and name, and checks about 45 risky ports. It also reads the router's UPnP port forwards
(read-only). It does **not** look up known vulnerabilities (CVEs), test passwords or change
anything on other devices; those get guidance only. The optional nmap deep scan adds software
names and versions. CVE lookup would be a separate, larger feature that needs an online
vulnerability database.

## Accuracy problems found and solved during the build

These go beyond the plan but were needed for honest results on this PC:

- **Hidden firewall conditions.** Built-in rules such as *WFD Driver-only (TCP-In)* and
  *Network Discovery for Teredo (UPnP-In)* look like "allow everything to System" through COM
  and PowerShell. Their registry definitions carry trust-tuple (`TTK`) conditions that limit
  them to Wi-Fi Direct or UPnP-mapped traffic. SimplySec reads these; without it, SMB looked
  reachable on every Public network.
- **Store-app capability rules** (Microsoft Store, Teams…) hide their package from non-admin
  readers. They only apply inside their own app sandbox and no longer count against normal
  programs.
- **Processes whose owner can't be read** (for example the Tailscale helper) inherit the
  account of their parent service when it runs the same program.
- **`Get-NetTCPConnection`** omits the IPv4 half of dual-stack kernel listeners (445, 5357);
  psutil and `netstat` show both.

## Deviations from the plan

- **Data location.** The change journal and firewall backups are in the admin-only
  `%ProgramData%\SimplySec`, as planned. Scan history, settings, Keep choices and devices are in
  `%LOCALAPPDATA%\SimplySec\history.db`, so read-only scans can still save history.
- **Grouped finding.** Unknown programs with Public allow rules that aren't running are one
  grouped finding (21 on this PC) instead of one each.
- **Grades** run A–F including E (50–59).
- **Additions** not in the plan: impact analysis, the progress panel, and per-fix selection in
  the confirmation window.

## Verification

Done:

- 175 unit tests pass, including three real cases from this PC: the Ollama rule on Private and
  Public, the user-scoped Codex rule, and Cursor bound only to Tailscale.
- `ruff check`, `ruff format --check` and `mypy src/simplysec/core` are clean.
- **Live read-only scans:**
  - The listener set matches `netstat`.
  - With Ollama running, port 11434 is Reachable via rule `ollama.exe` and labelled "you set
    this up".
  - Verdicts for Spotify, CDPSvc and SMB match `Get-NetFirewallRule`.
- **Built exe:** starts in read-only mode; `simplysec-cli.exe scan --json` matches the source
  run (apart from short-lived UDP sockets).
- **Daily-check pieces:** a test toast was shown and `monitor --run` completed.

Not run (each needs administrator rights or the owner's decision):

1. Elevated end-to-end tests: `pytest -m admin` from an elevated prompt (firewall block with
   undo, registry fix with undo), then check port 8765 from a phone.
2. Home-network scan (`simplysec scan --network`): it asks "Is this your network?" for
   `EE-G9QKJQ`. Compare the device list with the router's DHCP page.
3. Creating the daily-check task (Settings > Daily check, needs admin), then
   `schtasks /Query /TN "SimplySec\Daily check"` and `schtasks /Run`.
4. The UAC relaunch and the GUI preview → apply → Changes → Undo cycle as administrator.

## State of this PC (latest scan)

Risk score 35–40 (D; the score was inverted after this was written, it was then 65–67 on the old 100 = clean scale), with no Critical or High findings. Main items:

- LLMNR and NetBIOS are on, and the Ethernet is set as a Public network.
- The saved Wi-Fi network `VM3731498` uses TKIP and connects automatically.
- Spotify can be reached from the Public network.
- Remote Assistance is on.
- 21 other programs have Public allow rules.
- Ollama is reachable and was set up on purpose.

SMB, RPC and WSD are correctly blocked on the Ethernet and reachable only over Tailscale.

No settings were changed on this PC during the session. Side effects:

- the venv was rebuilt;
- `%LOCALAPPDATA%\SimplySec` holds a few scans from testing;
- one test notification was shown;
- `ollama serve` was started briefly for verification and then stopped.

## Possible next steps

- Run the four unrun verification steps above.
- Speed up scans by caching program signatures (currently about 9 of the 15 seconds).
- Code-sign the exe to avoid the SmartScreen warning.
- Write device-specific advice (cameras, printers, NAS, smart TVs): some per-port advice
  reads oddly on devices, e.g. "Use SSH instead" for Telnet on a camera.
- Decide whether the Ethernet should be marked Private. Its confirmation window lists what
  would become reachable from it.
