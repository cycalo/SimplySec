# SimplySec 2.0: accurate, explainable, reversible

## Context

SimplySec v1 is a PyQt5 Windows app for home and small-business users. It scans the PC with nmap, explains the open ports in plain language, and offers one-click fixes such as firewall rules, service changes and registry edits. The original brief is in `I want to create a security program.txt`. It ran, but the results were inaccurate, the code was hard to follow, and its changes were hard to clean up. A full read of `main.py`, the helper scripts and the July 2025 logs, plus read-only probes on this PC, found these root causes:

1. **It measures the wrong thing.** It runs nmap against the PC's own IP from the same PC ([main.py:259](main.py#L259)), and it verifies a block by connecting to `127.0.0.1` ([main.py:2535](main.py#L2535)). Windows Firewall never filters traffic a PC sends to itself, so every listening port looks "open" both before and after a fix. Verification could never pass. The code responded by escalating: it disabled services, turned off NetBIOS on every adapter, and restarted the firewall service ([main.py:1951](main.py#L1951)). That is why the README says "firewall rules not working".
2. **Services are identified by guesswork.**
   - nmap names ports from a lookup table, so ports 1042 and 1043 were reported as "afrog" and "boinc".
   - Risk is judged by substring matching ([main.py:1333](main.py#L1333)), so Hyper-V's `vmrdp` counts as High because it contains "rdp", and `https` counts as Medium because it contains "http".
   - The scan only covers the top 1,000 ports, so it never sees Ollama on port 11434. On this PC, Ollama listens on all networks on purpose (the user's `OLLAMA_HOST=0.0.0.0:11434`). The user confirmed this is their local LLM and it is safe. The case is used here only as an accuracy test: v2 must see it, describe it correctly, and respect the user's choice. It must not call it a threat.
3. **Port knowledge is duplicated in 9 places, and they disagree.** Port 10000 is listed as both High and Medium. Port 5357 is treated as WinRM, but it is actually WSD (Web Services on Devices) discovery.
4. **Changes are not tracked.**
   - Rules use at least 6 naming formats, and cleanup guesses 20 rule names per port ([main.py:2574](main.py#L2574)).
   - Registry and service changes are not recorded.
   - The firewall backup is written and then deleted.
5. **Commands fail silently.** All of these are confirmed in `logs/simplysec.log`:
   - `remoteip=Internet` is not valid in netsh, so the block rule was never created. Its LocalSubnet *allow* twin was created, so v1 actually **opened** ports 5357 and 5985 to the LAN.
   - Wildcard `name=` is not supported, so verification always failed.
   - `export policy.wfw` fails once the file already exists.
   - `$pid` is read-only in PowerShell, so the service lookup always returned nothing.
   - An unquoted `@{}` broke `winrm set`.
   - The registry action reads the wrong `type` key and calls a method that doesn't exist ([main.py:540](main.py#L540)).
   - Success is logged whatever the exit code.
6. **Some fixes are harmful or contradict each other.**
   - Remote Desktop services were disabled without asking.
   - "Outbound block" rules use `localport`, which is the wrong field, so they do nothing.
   - `fDenyTSConnections` is set to 0 in one code path and to 1 in another.
7. **The structure makes it hard to follow.**
   - A single 4,200-line file mixes UI, scanning and fixing.
   - Blocking calls run on the UI thread.
   - Three different "primary IP" functions can disagree.
   - `ipconfig` parsing only works in English.
   - Results for other devices from the LAN scan are never shown.

**Read-only probes on this PC, without admin, prove the replacement approach works:**
- psutil found all 24 listeners with their exact program and hosted services (for example 5040 → CDPSvc) in about 1 second.
- The COM API `HNetCfg.FwPolicy2` read all 593 firewall rules in 0.34 seconds.
- The legacy `FwMgr.IsPortAllowed` API said "allowed" for everything, even notepad, so we need our own evaluator.
- A rule scoped to one user (`codex_sandbox_offline_block_inbound`) would make naive matching call every port "blocked". So rule conditions must be modelled.

**Outcome:** a maintainable app that reports what is really reachable, explains it plainly, fixes precisely, verifies honestly, and can undo everything. It also gains home-network and router checks, history and reports, background monitoring, and a standalone .exe.

**Decisions made:** all four add-ons are in scope, PySide6 for the UI, and git with a legacy folder to preserve v1.

## Principles
- The flow is: measure → explain → fix precisely → verify → undo.
- Scanning is read-only and works without admin. Changes need admin and a preview the user confirms.
- Never kill processes, disable core Windows services, add outbound rules, or restart the firewall service.
- Every change is recorded with its before-state and can be undone from the UI or the CLI.
- Use only locale-independent data sources: psutil, COM, WMI/CIM, and PowerShell objects converted to JSON. No parsing of localized text.
- If unsure, report "Uncertain". Never claim "protected" based on a rule we can't fully evaluate.
- Only scan networks the user confirms are theirs. Other devices only get guidance.

## How the exposure check works (the core change)
1. **Listeners.** `psutil.net_connections` gives protocol, bind address, port and PID. From the PID we get:
   - the exe path,
   - the user SID or AppContainer SID (from the pywin32 token),
   - the hosted services (one `win32service.EnumServicesStatusEx` call).
   PID 4 kernel listeners (139, 445, 5357, 5985) are identified by port from the knowledge base.
2. **Network context.**
   - Adapters, IPs and netmasks come from psutil.
   - The profile for each interface (Public, Private or Domain) comes from `Get-NetConnectionProfile`.
   - Bind scope is one of: loopback only, one interface (such as Tailscale or a VMware host-only adapter), or all interfaces.
3. **Firewall model, read via COM.**
   - Per profile: enabled, default inbound action, block-all.
   - For each enabled inbound rule:
     - protocol;
     - local ports, including ranges and the keywords `RPC`, `RPC-EPMap`, `IPHTTPS`, `Teredo` and `Ply2Disc`;
     - application path, with environment variables expanded and case folded (`System` means PID 4);
     - service (`*` means any service);
     - remote and local addresses, including the keywords LocalSubnet, DNS, DHCP and DefaultGateway, resolved against the interface's subnet;
     - interface types and edge traversal;
     - conditions: user-authorized SDDL (parsed with pywin32), AppContainer package, owner, authenticated-only flags.
4. **`core/exposure.py`, a pure function with extensive tests.** For each listener and each relevant profile:
   - If the firewall is off, the listener is Reachable.
   - If block-all is on, it is Blocked.
   - Otherwise, take the allowed remote set minus the blocked remote set.
   - If no rule matches, the default action applies.

   The output is one of LocalOnly, Blocked, Reachable (scope: anyone, local subnet, or specific addresses) or Uncertain. It also lists the responsible rule names and gives a plain-language reason. Uncertain is used, for example, when a process token can't be read without admin.
5. **Risk.** Risk starts from the knowledge-base entry for the port, program or service. It is then weighted by exposure scope and profile, with Public weighing most. These raise it further: an unsigned program, a program in a user-writable path, or edge traversal.
6. **Known apps and intentional exposure.**
   - `programs.toml` describes legitimate apps in neutral words, for example "Ollama, your local AI model server".
   - Findings about these apps are about *who can reach them*, never about the app being bad.
   - If the user deliberately configured the exposure (for example `OLLAMA_HOST=0.0.0.0`), the finding says "you set this up" and starts at Low or Info.
   - Fixes are offered in steps: *only this PC* / *home network or Tailscale only* / **Keep: I need this**. "Keep" is remembered per program and scope. It is not scored, and it is only raised again if the exposure gets wider.
   - The preview warns when a fix would cut off access on the network you are on now. On this PC, the Ethernet adapter is on the **Public** profile, so "block on Public" would also block your own LAN devices. In that case it offers to mark the network Private first; that change can also be undone.

## Architecture
```
pyproject.toml   runtime: PySide6-Essentials, psutil, pywin32, defusedxml, jinja2
                 dev: pytest, pytest-qt, ruff, mypy, pyinstaller
src/simplysec/
  __main__.py    GUI by default; CLI: scan [--json] [--network] | fix | undo | history | report --html | monitor --run
  app/           paths (%ProgramData%\SimplySec with an admin-only ACL; frozen-exe aware),
                 rotating log, elevation (runas relaunch), settings
  windows/       the ONLY layer that touches the OS (thin, mockable)
    runner.py    subprocess + PowerShell→JSON (no shell, CREATE_NO_WINDOW, timeouts)
    firewall.py  COM read/write; every rule we create has Grouping="SimplySec"
    listeners.py network.py registry.py services.py accounts.py wifi.py
    scheduler.py (Task Scheduler)  toast.py (notifications)  nmap.py (optional detection + XML parse)
    scripts/facts.ps1   one PowerShell call per scan (Defender/AV, SMB, updates, UAC, BitLocker…) → JSON,
                        each item reported as ok / needs_admin / error
  core/
    models.py exposure.py scoring.py actions.py journal.py engine.py history.py monitor.py
    knowledge/   ports.toml, programs.toml, services.toml (single source of truth) + loader
    checks/      one file per topic: detection + plain-language text + its fixes
    lan/         discovery.py, probe.py, identify.py (MAC vendor, rDNS, SSDP names), inventory.py
    router/      upnp_igd.py
    report/      html.py + templates/report.html.j2
  resources/     oui.csv.gz (IEEE MA-L vendor list) + scripts/refresh_oui.py
  ui/            PySide6 (Windows 11 style): main_window, pages/, widgets/,
                 workers.py (QThreadPool, so the UI never freezes)
tests/           unit (no admin) + integration (pytest marker `admin`, opt-in) + fixtures/ (real facts captured from this PC)
packaging/       simplysec.spec (PyInstaller)    scripts/build.ps1
docs/            ARCHITECTURE.md, ADDING_A_CHECK.md (replaces port_security_docs.md), original-brief.md
```

## Change journal, undo and cleanup
Every fix is built from a small set of reversible primitives. Each one takes a snapshot, applies the change, verifies it, and can revert to the before-state.

| Kind | Apply | Revert |
|---|---|---|
| `firewall.add_rule` | Rule named `SimplySec:<fix>:<id>` in group "SimplySec", with a description of why and when | Remove it by name |
| `firewall.remove_rule` | Delete the rule after saving its full definition | Recreate it |
| `firewall.profile` | Set enabled or default inbound action | Restore previous values |
| `registry.value` | Set a typed value | Restore the old value, or delete it (and the key) if we created it |
| `service.start_type` | Allow-listed services only | Restore previous start type and state |
| `network.category` | Mark a network Public or Private | Restore previous category |
| `wifi.connection_mode` | Set a saved Wi-Fi profile to manual connect | Set it back to auto |
| `task.schedule` | Create the SimplySec scheduled task | Delete the task |
| `smb.server_setting`, `defender.pref`, `netbios.adapter`, `account.enabled` | Specific setters | Restore previous values |

- **Journal.** `%ProgramData%\SimplySec\simplysec.db` (SQLite) holds the change journal, scans, devices and settings.
  - Only Administrators and SYSTEM can write to the folder. Undo runs elevated and replays the stored before-values, so a standard user must not be able to tamper with them.
  - Revert also checks every kind and parameter against allow-lists declared by the check modules.
- **Backups.** Before each batch, run `netsh advfirewall export` to a unique timestamped file in `backups\` (keep the last 10). The preview also offers an optional System Restore point.
- **Undo** works per change, per batch, or as "Undo everything SimplySec changed" (in reverse order). "Remove all SimplySec rules" deletes the whole group.
- **Legacy v1 cleanup check.** It finds rules named `SimpleSec-*`, `*-SimpleSec`, `BlockPort*`, `RestrictPort*` or `SimpleSec-WinRM-*-AllowLocal`, saves their definitions and removes them (this can be undone).
- **Managed PCs.** If the PC is domain-joined or has a Group Policy firewall policy, managed settings are reported only, not changed.

## Checks on this PC (M1)
Each check has a plain-language explanation, technical details, a severity, a reversible fix where one is safe, and a verification step.

| Area | Finding | Fix |
|---|---|---|
| Firewall | Profile off; default inbound action is Allow | Turn on; set to Block |
| Exposure | High- or medium-risk service reachable (per profile and scope) | Block port, or block the program (all networks or Public only), or the topic fix |
| Exposure | Unsigned program, or one in a user-writable path, accepting connections | Block the program |
| Exposure | Non-Windows app allowed on **Public** networks (for example the `ollama.exe` and Cursor rules); Low or Info if the user set it up on purpose | Choose Keep, home only, or this PC only. A block rule is added on top; the original rule is not touched |
| Exposure | Info: "Listening but protected" list, shown for transparency | None |
| Remote access | RDP on and reachable; RDP without NLA; Remote Assistance on | `fDenyTSConnections=1`; `UserAuthentication=1`; `fAllowToGetHelp=0` |
| Legacy protocols | SMBv1 server on; LLMNR or NetBIOS on (marked optional because it may affect old devices) | `Set-SmbServerConfiguration`; LLMNR policy; NetBIOS per adapter |
| File sharing | Shares granting Everyone access | Guidance only |
| Malware | No active antivirus (SecurityCenter2); Defender real-time protection off; tamper protection off; signatures old; ransomware protection (Controlled Folder Access) off | Open Windows Security; `Update-MpSignature`; Controlled Folder Access (optional) |
| Updates | Last install more than 30–45 days ago (Windows Update history); updates paused; reboot pending | Guidance plus a button to open Settings |
| Accounts | UAC off or no prompt; Guest (SID -501) enabled; blank passwords allowed | Registry setting; disable the account; `LimitBlankPasswordUse=1` |
| System | AutoRun on; BitLocker off (Shell property, readable without admin; laptops weighted higher) | `NoDriveTypeAutoRun=255`; guidance |
| Housekeeping | v1 leftovers; managed PC | Cleanup; report-only mode |

**Score.** Start at 100 and subtract a weight for each open finding: Critical 25, High 12, Medium 5, Low 2. Grades run A to F. Accepted ("Keep") findings are shown but not scored. "Fix recommended" applies only non-disruptive fixes: firewall on, NLA, SMBv1 off, Remote Assistance off, Guest off, blank-password limit, UAC prompts. Disruptive fixes are always picked one at a time: turning RDP off, blocking ports or programs, LLMNR/NetBIOS, Controlled Folder Access, Wi-Fi changes.

## UI (PySide6, Windows 11 style)
- **Overview:**
  - score ring and grade;
  - a **Scan & Protect** button;
  - counts by severity;
  - top recommended fixes;
  - network status (for example "Ethernet: Public network, firewall on");
  - what changed since the last scan.
- **This PC:**
  - Findings are shown as cards grouped by area.
  - Each card has a plain title, "What this means", and "Technical details" (rule names, PIDs, paths, values).
  - Each card has the buttons **Fix**, **Keep** and **Learn more**.
- **Open ports:** a table with Port, Program (publisher), Listening on, Reachable from, Risk and Action columns, plus a "reachable only" filter.
- **My network:** devices (name, vendor, IP, first and last seen, trusted toggle, risky services), the router section (UPnP, port forwards, external IP) and Wi-Fi.
- **History:** score trend, scan list with new and resolved findings, and HTML export.
- **Changes:** every change with Undo, plus Undo all and the firewall backups.
- **Settings:**
  - admin status with "Restart as administrator";
  - the daily check (time and on/off);
  - networks I own;
  - accepted risks;
  - the data folder.
- **Fix flow:** the preview lists the exact changes and "what might stop working". After applying, each change shows Verified ✓ or ✗ based on a fresh re-check, never assumed.

## Milestones (in order; commit at the end of each, on branch `v2`, never pushed)

**M0 Housekeeping**
- `git init` with a `.gitignore` covering `.venv/`, `__pycache__/`, `logs/`, `*.log`, `*.wfw`, `*.db`, `build/`, `dist/` and `legacy/v1-artifacts/`.
- Commit the v1 source as a baseline and tag it `v1-legacy`, then create branch `v2`.
- `git mv` the v1 source (`main.py` and the helper `.py`/`.bat`/`.vbs`/`.ps1` files, `ports.txt`, `port_security_docs.md`, `requirements.txt`) into `legacy/v1/`.
- Move the runtime files (`logs/`, root `*.log`, the 1 MB `*.wfw` firewall exports, `main.py.bak`, `netbios_test_results.txt`) into `legacy/v1-artifacts/`, which is ignored by git.
- Move the brief to `docs/original-brief.md`.
- Recreate `.venv` (Python 3.11) with `pip install -e .[dev]`. The old venv only held packages from requirements.txt, so it is easy to rebuild.

**M1 Core:** the skeleton, the `windows/` layer and `facts.ps1`, the exposure evaluator, the knowledge base (v1 texts migrated and corrected, plus entries seeded from this PC's real listeners: Ollama, Cursor, Spotify, Tailscale, adb, VMware, CDPSvc, WSD, LLMNR, RPC), the checks above, actions, journal, engine, scoring, the CLI, the GUI pages (Overview, This PC, Open ports, Changes, Settings), tests and docs.

**M2 Home network and router**
- **Scope:** the subnet of each private interface, from its netmask, capped at /22. Before scanning, ask "Is this your network?", which is remembered. On this PC the home Ethernet is Public, so the app will ask.
- **Discovery:** async TCP connect probes, which also fill the ARP cache, then `Get-NetNeighbor` for MACs. Device identity comes from:
  - the bundled OUI vendor list (or nmap's `nmap-mac-prefixes` when present);
  - detection of randomized MACs ("private address, likely a phone");
  - reverse DNS;
  - SSDP friendly and model names.
- **Services:** async connect checks on ports flagged `lan_probe=true` in `ports.toml` (about 35, for example telnet, RTSP cameras, unauthenticated databases, admin panels, Docker 2375). An optional "deep scan" runs `nmap -sV` when nmap is installed. nmap and Npcap are never bundled, because their licenses don't allow it.
- **Inventory:** stored in SQLite by MAC, with labels, a trusted flag, and "new device" findings.
- **Router (UPnP IGD):** SSDP finds the gateway's description, then the app calls `GetExternalIPAddress` and loops `GetGenericPortMappingEntry` (up to 256 entries, stopping at fault 713).
  - Uses defusedxml, a 256 KB response cap, and fetches only LAN URLs.
  - Findings: a port forward to this PC (Critical, unless accepted, for example a game server); a forward to another device (High); UPnP turned on (Low, with router guidance); a CGNAT or private WAN IP (Info: "your ISP blocks inbound").
- **Wi-Fi on this PC:** read via `netsh wlan export profile` XML, which is locale-neutral and exported without keys.
  - Open, WEP or TKIP networks set to auto-connect are Medium. The fix is `wifi.connection_mode` = manual.
  - Being connected to an open network right now gives a High warning.
- **Other devices:** guidance only.

**M3 Score history and reports**
- Each scan snapshot is stored in SQLite.
- Scans are compared for new and resolved findings, new listeners, new devices, and the score change.
- The History page has a QPainter trend chart, so no QtCharts dependency.
- `simplysec report --html` and a UI button produce a self-contained, printable Jinja2 report with autoescape on, since device names are untrusted. It covers: summary, findings grouped into 5 small-business control areas (firewalls, secure configuration, access control, malware protection, updates), open ports, devices, changes made, and accepted risks.

**M4 Background monitoring**
- A Settings toggle creates or removes the task `\SimplySec\Daily check` (schtasks, highest privileges, runs when the user is signed in). This is journaled, so it can be undone.
- `monitor --run` does a read-only scan and saves it. It never applies fixes.
- It sends a Windows toast (PowerShell WinRT, no extra package) only when: the score drops by 5 or more; there is a new High or Critical finding; a new device appears; or antivirus or the firewall is turned off.

**M5 Standalone .exe**
- PyInstaller onedir build: windowed `SimplySec.exe` plus a console `simplysec-cli.exe` in one folder.
- It bundles the TOML files, `facts.ps1`, the OUI list, templates, the icon and version info.
- Manifest set to `asInvoker`, with elevation on demand, so read-only mode works.
- `scripts/build.ps1` creates `SimplySec-<ver>-win64.zip`.
- Note in the README: the exe is unsigned, so SmartScreen will warn on first run.

## Reuse from v1
- The plain-language port texts move into `ports.toml`, with errors corrected: `get_port_explanation` ([main.py:1395](main.py#L1395)), `get_port_recommendation` ([main.py:1352](main.py#L1352)) and `ports.txt`.
- The NetBIOS approach (`SetTcpipNetbios` at [main.py:3385](main.py#L3385)) becomes the `netbios.adapter` action, with a snapshot per adapter.
- The RDP and SMB registry keys ([main.py:2848](main.py#L2848), [main.py:3643](main.py#L3643)) move into the `rdp` and `smb` check modules.
- The critical-services list ([main.py:3109](main.py#L3109)) becomes the "never touch" list.
- The admin check ([main.py:4196](main.py#L4196)) moves into `app/elevation`.
- The log viewer is replaced by the History and Changes pages.

## Verification
1. **Unit tests (`pytest`, no admin)**
   - **Evaluator**, table-driven, including three real cases from this PC:
     - the Ollama allow rule on Private and Public;
     - the user-scoped Codex block rule, which must not cover other users' apps;
     - Cursor bound only to the Tailscale IP.
   - **Firewall edge cases:**
     - port keywords (`RPC`, `RPC-EPMap`);
     - PID 4 `System` rules;
     - profile bitmasks;
     - block-overrides-allow;
     - the firewall-off and default-action paths.
   - **Other tests:**
     - knowledge-base schema (no duplicates, every fix ID exists);
     - checks run against fact fixtures;
     - journal apply and undo order, using fake adapters;
     - IGD SOAP and XML parsing on recorded fixtures (an entity-bomb XML must be rejected);
     - OUI lookup and randomized-MAC detection;
     - inventory and scan comparisons;
     - the report escapes a device name like `<script>`;
     - the monitor's notification triggers;
     - the CLI's JSON output shape.
2. **Read-only real run, without admin:** `simplysec scan --json`.
   - The listener set must match `Get-NetTCPConnection`.
   - Ollama 11434 must show as Reachable via rule `ollama.exe`, labelled as user-configured.
   - The verdicts for 3–4 ports must be cross-checked by hand in `wf.msc`.
3. **Elevated end-to-end test of a firewall fix:**
   - Start `python -m http.server 8765 --bind 0.0.0.0`.
   - Scan, then apply "Block this program" and check that the verdict changes to Blocked.
   - `Get-NetFirewallRule -Group SimplySec` should show exactly one readable rule.
   - Test from a phone or another PC that the port fails after the fix and works again after undo.
   - After `simplysec undo --all`, the group should be empty.
4. **Registry fix end-to-end test:** apply the Remote Assistance or AutoRun fix, check the value, undo, and confirm the original value (or its absence) is restored.
5. **Network and router:**
   - Compare `scan --network` (after confirming the home network) with the router's DHCP client list.
   - Compare the UPnP mappings with the router's admin page.
   - A second PC running SimplySec should see this PC's reachable ports. That is a true outside check of the evaluator.
6. **Monitoring:**
   - Turn the toggle on and confirm `schtasks /Query /TN "SimplySec\Daily check"` finds the task.
   - Run `schtasks /Run` after starting a test listener with an allow rule; a toast should appear.
   - Turn the toggle off; the task should be removed.
7. **Exe:**
   - Run `scripts/build.ps1`.
   - Launch `dist\SimplySec\SimplySec.exe` without admin; it should start in read-only mode.
   - Check the elevation relaunch, a scan, and that `simplysec-cli.exe scan --json` matches the run from source.
8. **GUI smoke test and quality:**
   - The UI stays responsive during scans, and preview → apply → Changes → Undo works.
   - `ruff check`, `ruff format --check` and `mypy src/simplysec/core` pass.
