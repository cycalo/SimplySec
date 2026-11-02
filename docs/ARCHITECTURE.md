# SimplySec architecture

SimplySec answers one question precisely: **what can other devices actually reach on this PC,
and what should I do about it?** It measures, explains, fixes precisely, verifies and can undo
everything.

```
measure (read-only, no admin) → explain → preview → fix (admin) → verify (fresh re-read) → undo
```

## Layers

```
src/simplysec/
  __main__.py, cli.py   entry points (GUI by default, CLI sub-commands)
  app/                  paths + admin-only ACL, rotating log, elevation (runas relaunch)
  windows/              the ONLY code that touches the OS (thin and replaceable by fakes)
  core/                 pure logic: models, exposure evaluator, checks, scoring,
                        actions (reversible primitives), journal, engine, history
  ui/                   PySide6 pages and widgets; slow work runs on a QThreadPool
```

`core` never imports `subprocess`, `winreg`, COM or `psutil`. Everything it needs arrives as
plain dataclasses (`core/models.py`) in a `RawScan`, so the whole analysis can be replayed from
a JSON fixture (see `tests/fixtures/this_pc_raw.json`, captured from a real PC).

### Data sources (all locale-independent)

| What | Source |
|---|---|
| Listeners (protocol, address, port, PID) | `psutil.net_connections` |
| Program path, services per PID | psutil; one `EnumServicesStatusEx` call |
| Process user / AppContainer | process token (ctypes); service account from the service config when the token is unreadable |
| Firewall profiles and rules | COM `HNetCfg.FwPolicy2` (≈600 rules in well under a second) |
| Hidden rule conditions (TTK) | the rules' registry definitions (`FirewallRules` key, readable without admin) |
| Adapters, profiles, gateways, DNS | psutil + `facts.ps1` (`Get-NetConnectionProfile`, `Get-NetAdapter`, numeric enums only) |
| Defender, SMB, updates, UAC, RDP, BitLocker… | `windows/scripts/facts.ps1`: one PowerShell call, objects → JSON, each item `ok` / `needs_admin` / `error` |
| Signatures | one batched `Get-AuthenticodeSignature` call |

No command output is ever parsed as text. PowerShell parameters are passed as base64 JSON in an
environment variable, so nothing is spliced into script source.

## The exposure evaluator (`core/exposure.py`)

v1 ran nmap against the PC's own IP and "verified" blocks by connecting to 127.0.0.1. Windows
never filters traffic a PC sends to itself, so everything looked open and verification could
never pass. v2 models the firewall instead.

For every listener and every interface it can be reached through:

1. Loopback binds are **LocalOnly**. A specific bind address means only that interface; a
   wildcard means every active interface of that address family.
2. The interface's profile comes from its connection profile; interfaces without one are treated
   as Public (what Windows does for unidentified networks).
3. Firewall off for that profile → **Reachable** by anyone. "Block all incoming" → **Blocked**.
4. Otherwise each enabled inbound rule is matched on protocol, local port (ranges and the
   `RPC`, `RPC-EPMap`, `IPHTTPS`, `Teredo`, `Ply2Disc` keywords), program path (env vars
   expanded, case folded, `System` = PID 4), service (`*` = any service), interface and
   interface type, local address, and user / owner / AppContainer conditions (SDDL parsed in
   pure Python). Each condition answers *yes*, *no* or *can't tell*.
5. Remote address sets are exact interval sets (`core/addrset.py`), with `LocalSubnet`, `DNS`,
   `DHCP` and `DefaultGateway` resolved against the interface.
6. **Effective = (allowed by matching allow rules, or everything if the default is Allow) −
   blocked by matching block rules.** Block always wins.
7. Rules whose conditions can't be decided are evaluated both ways. If the answer differs the
   verdict is **Uncertain** with the specific reason (for example "which user runs this program").
   SimplySec never claims "Blocked" based on a rule it can't fully evaluate.

The result per listener is `LocalOnly`, `Blocked`, `Reachable` (scope: anyone, local subnet or
specific addresses) or `Uncertain`, plus the responsible rule names and a plain-language reason.

### Windows quirks the model handles

* **Hidden trust-tuple conditions.** Rules such as *WFD Driver-only (TCP-In)* or *Network
  Discovery for Teredo (UPnP-In)* look like "allow everything to System" through COM and
  PowerShell, but their registry definitions carry `TTK2_27=WFDKmDriver` / `TTK2_27=UPnP`: they
  only apply to Wi-Fi Direct sessions or UPnP-mapped traffic. SimplySec reads these from the
  registry and joins them to the COM rules by name, or by rule shape when the cached display
  names differ. Without this, SMB would look reachable on every Public network.
* **Store-app capability rules** (`Microsoft Store`, `Microsoft Teams`, …) carry an owner SID and
  their package is hidden from non-admin readers. They only apply inside that app's AppContainer,
  so they never match a normal program.
* **User-scoped rules** (for example a sandbox rule limited to one local user via
  `LocalUserAuthorizedList`) only match processes of that user. When a process token is
  unreadable the service account (from the service configuration) or a service parent with the
  same program is used; otherwise the verdict is Uncertain.
* `Get-NetTCPConnection` hides the IPv4 half of dual-stack kernel listeners (445, 5357);
  psutil and `netstat` show both, and so does SimplySec.
* Not modelled: Windows Service Hardening's hidden static filters, IPsec connection security
  rules, and AppContainer network isolation (sandboxed Store apps are reported as Uncertain
  rather than Reachable).

## Risk and score (`core/scoring.py`)

The knowledge base gives each port, program and service a risk **for exposure on a Public
network**. Exposure width then adjusts it: Public = as is, Private = one level lower, VPN or
virtual-adapter only = two lower, edge traversal = one higher. An unsigned program or one in a
user-writable folder raises it. If the user configured the exposure on purpose (for example
`OLLAMA_HOST=0.0.0.0`) it is capped at Low (Info on Private networks). `info` in the knowledge
base means harmless by design and is never raised.

Score = 100 − (Critical 25, High 12, Medium 5, Low 2 per open finding). Info, Kept, Managed and
informational findings are not scored. Grades A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, E ≥ 50, F < 50.

"Keep: I need this" stores the finding's exposure width; the finding is shown but not scored,
and comes back only if it becomes reachable more widely.

## Changes: primitives, journal, undo

Every fix is built from reversible primitives (`core/actions.py`): each can `snapshot` the
before-state, `apply`, `verify` by reading the real state back, and `revert`.

| Kind | Apply | Revert |
|---|---|---|
| `firewall.add_rule` | block rule `SimplySec:<fix>:<id>` in group "SimplySec", with a description | remove by name |
| `firewall.remove_rule` | delete after saving every definition with that name | recreate them |
| `firewall.profile` | firewall on / default inbound Block | previous values |
| `registry.value` | typed value | previous value, or delete it (and the key if we created it) |
| `service.start_type` | allow-listed services only | previous start type and state |
| `network.category` | mark a network Private | previous category |
| `smb.server_setting`, `defender.pref`, `netbios.adapter`, `account.enabled` | specific setters | previous values |
| `wifi.connection_mode`, `task.schedule` | added in M2 / M4 | previous values |

* **Never**: kill processes, disable core Windows services (the never-touch list in
  `services.toml`), add outbound rules, add allow rules, or restart the firewall service.
* The **journal** (`%ProgramData%\SimplySec\simplysec.db`) records each change with its kind,
  parameters and before-state *before* applying it, then its status and verification. The folder
  gets an admin-only ACL (SYSTEM and Administrators full control, Users read) every time an
  elevated SimplySec opens it.
* Before each batch with firewall changes, `netsh advfirewall export` writes a unique timestamped
  backup (newest 10 kept). The preview can also create a System Restore point.
* Apply **and** undo check every kind and parameter set against allow-lists declared by the
  check modules, and undo checks that stored before-states look like something SimplySec saved.
  A tampered journal can't be replayed into arbitrary changes.
* Undo works per change, per batch, or for everything (in reverse order). "Remove all SimplySec
  rules" undoes the journaled rules and deletes anything else left in the group.
* Verification is never assumed: each change is re-read from the OS, and the GUI/CLI run a fresh
  scan and report whether each finding is resolved.

### Read-only mode and elevation

Scans need no admin. Per-user data (scan history, settings, accepted risks, devices) lives in
`%LOCALAPPDATA%\SimplySec\history.db`, so read-only scans and the daily check (which runs as the
signed-in user) share one history. Only the change journal is in the admin-only folder.

In the GUI, a non-admin user confirms the preview and SimplySec runs one elevated
`simplysec fix --select FINDING=FIX … --yes` (UAC prompt). The elevated process re-derives the
plan from a fresh scan and re-checks the allow-lists; it does not trust anything passed from the
unelevated process except fix and finding ids. Results are then read back from the journal.
"Restart as administrator" is also available.

## Checks

One module per topic in `core/checks/` (see `docs/ADDING_A_CHECK.md`). Each provides detection,
plain-language text, fixes and allow-lists. Facts that couldn't be read produce an Info finding
("reported as unknown, not as safe"). Settings controlled by Group Policy or a domain are
reported as *Managed* and never changed.

## Home network, router and Wi-Fi (`core/lan`, `core/router`, `windows/wifi.py`)

* **Scope.** The IPv4 subnet of each up Ethernet/Wi-Fi interface with a private address, from its
  netmask, capped at /22 around this PC. VPN and virtual adapters are never scanned.
* **Consent.** Before the first scan of a network SimplySec asks "Is this your network?" and
  remembers the answer by network name + subnet (Settings > Networks I own). Nothing is scanned
  otherwise. Other devices only ever get guidance; SimplySec changes nothing on them.
* **Discovery.** Async TCP connects to every address on a few common ports (any answer, even a
  refusal, proves a host and fills the ARP cache), then `Get-NetNeighbor` for MAC addresses.
* **Identity.** Bundled IEEE OUI list (`resources/oui.csv.gz`, rebuilt by
  `scripts/refresh_oui.py`; nmap's `nmap-mac-prefixes` as fallback), randomized-MAC detection
  (locally administered bit: "private address, likely a phone"), reverse DNS, SSDP friendly and
  model names.
* **Services.** Async connects on the ~45 ports marked `lan_probe = true` in `ports.toml`;
  optional `nmap -sV` deep scan when nmap is installed (never bundled).
* **Inventory.** Devices are stored by MAC in the per-user history DB with first/last seen,
  label and a trusted flag. New devices are flagged from the second network scan on.
* **Router.** SSDP finds the Internet Gateway Device; SOAP `GetExternalIPAddress` and
  `GetGenericPortMappingEntry` (≤ 256 entries, stop at fault 713). Read-only. defusedxml (DTDs
  and entities rejected), 256 KB cap, plain-http URLs on the scanned subnet only, no redirects.
  Findings: forward to this PC (Critical unless kept), forward to another device (High), UPnP on
  (Low), CGNAT/private WAN address (Info).
* **Wi-Fi.** `netsh wlan export profile` without `key=clear`; only name, SSID, connection mode,
  authentication and encryption are read and the export folder is deleted at once. Open, WEP,
  TKIP or WPA networks that auto-connect are Medium (fix: `wifi.connection_mode` = manual, undoable);
  being connected to one right now is High.

## History and reports (`core/history.py`, `core/report/`)

* Every scan is stored (newest 365) in the per-user history DB with its findings and port table
  (raw facts are not stored). `compare()` reports new and resolved findings, newly reachable or
  no-longer-reachable ports, new devices and the score change; the Overview and History pages
  use it.
* The History page draws the score trend with QPainter (no QtCharts).
* `simplysec report --html` and the History page's *Export HTML report* write one
  self-contained, printable file (inline CSS and an inline SVG trend). Jinja2 runs with
  autoescape on because device names, router names and port-forward descriptions come from the
  network and are untrusted. Findings are grouped into five small-business control areas
  (firewalls, secure configuration, user access control, malware protection, security update
  management), followed by reachable ports, devices, router, changes made and accepted risks.

## Background monitoring (`core/monitor.py`, `windows/scheduler.py`, `windows/toast.py`)

* Settings > Daily check (or `simplysec monitor --enable HH:MM` / `--disable`) creates or removes
  the task `\SimplySec\Daily check` from XML: daily, as the signed-in user, highest privileges,
  only while that user is signed in. Creating it is a journaled `task.schedule` change, so it
  appears on the Changes page and can be undone; moving the time undoes the old change first.
* `simplysec monitor --run` (what the task runs) does a read-only scan, also scans confirmed home
  networks, saves the result and compares it with the previous scan. It never applies fixes.
* It shows a Windows toast (PowerShell's WinRT bridge, using PowerShell's registered app id, so
  no extra package) only when the score dropped by 5 or more, a new High or Critical finding
  appeared, a new device joined, or antivirus or the firewall was turned off.

## Knowledge base

`core/knowledge/ports.toml`, `programs.toml` and `services.toml` are the single source of truth
for every description. v1's nine disagreeing copies were merged and corrected (5357 is WSD, not
WinRM; 10000 has one risk; descriptions now describe a *listening* port, not client use). Tests
check there are no duplicates and every referenced fix id exists.
