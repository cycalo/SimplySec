# SimplySec architecture

SimplySec answers one question precisely: **what can other devices actually reach on this PC,
and what should I do about it?** It measures, explains, fixes precisely, verifies and can undo
everything.

```
measure (read-only, no admin) → explain → preview → fix (admin) → verify (fresh re-read) → undo
```

## Projects

```
src/SimplySec.Core/      net10.0, pure logic, no OS access: Model/, Eval/Evaluator (exposure), Net/AddrSet,
                         Security/Sddl, Checks/ (one class per topic + Registry), Knowledge/ + Resources/
                         (TOML knowledge base, OUI list), Scoring, Impact, Engine/ (Analysis, ScanEngine,
                         DailyCheck), Actions/Primitives (+ the OS adapter interfaces), Storage/ (Journal,
                         History), Lan/ (home network, SSDP, router), Report/HtmlReport, Compat/
src/SimplySec.Windows/   the ONLY code that touches the OS: Collector, NativeFacts (+ Wmi), Listeners,
                         Firewall, Network, SystemAdapters, Services (setters, usage, Wi-Fi, scheduler,
                         toast), AppHost (paths, data-folder ACL, logging, elevation), Runner, Interop/
src/SimplySec.Commands/  every CLI subcommand, its texts and exit codes (used by both executables)
src/SimplySec.Cli/       simplysec-cli.exe (console)
src/SimplySec.App/       SimplySec.exe (WPF + WPF-UI): Views/, ViewModels/, Controls/, Dialogs/, Theme/,
                         Infrastructure/ (BackgroundRunner, services). With arguments it runs the CLI
                         without a window (the elevated helper and the daily-check task use this).
tests/                   SimplySec.Core.Tests, SimplySec.Windows.Tests, SimplySec.App.Tests,
                         golden/ (frozen regression corpus) and fixtures/ (this_pc_raw.json, router XML)
```

`SimplySec.Core` targets plain `net10.0` (not `-windows`), so the compiler keeps OS access out of
it. Everything it needs arrives as plain models in a `RawScan`, so the whole analysis can be
replayed from a JSON fixture (`tests/fixtures/this_pc_raw.json`, captured from a real PC;
`simplysec-cli scan --raw` writes one, `scan --from-raw FILE` and `SimplySec.exe --load-raw FILE` replay it).

`Compat/` reproduces the few Python semantics the results and stored data depend on (string
`title`/`normpath`, `ipaddress` rules, truthiness, stable sorts, unbounded integers), because the
analysis was ported from Python 2.0 and verified against it with the golden corpus. Culture-
sensitive APIs are build errors (CA1304/1305/1309/1310/1311): results never depend on the PC's
language.

### Data sources (all locale-independent)

| What | Source |
|---|---|
| Listeners (protocol, address, port, PID) | `GetExtendedTcpTable` / `GetExtendedUdpTable` |
| Program path, services per PID | `QueryFullProcessImageName` (falls back to `NtQuerySystemInformation` for protected processes); one `EnumServicesStatusEx` call |
| Process user / AppContainer | process token; service account from the service config when the token is unreadable |
| Firewall profiles and rules | COM `HNetCfg.FwPolicy2` (about 600 rules in a few tens of ms) |
| Hidden rule conditions (TTK) | the rules' registry definitions (`FirewallRules` key, readable without admin) |
| Adapters, addresses, profiles, gateways, DNS | `GetAdaptersAddresses`, `GetIfTable`, CIM `MSFT_NetConnectionProfile` / `MSFT_NetAdapter` / `MSFT_NetRoute` / `MSFT_DNSClientServerAddress` |
| Defender, SMB, updates, UAC, RDP, BitLocker… | `NativeFacts`: CIM (System.Management), registry, netapi32, WUA COM, Shell property store; each item `ok` / `needs_admin` / `error` |
| Signatures | WinVerifyTrust (embedded and catalog signatures) |
| Wi-Fi profiles | `netsh wlan export profile` (no keys) |
| Daily-check task | `schtasks` with an XML task definition |

No command output is parsed as localized text, and a scan starts no PowerShell (a test checks
this). A full scan takes about 1–1.5 s.

## The exposure evaluator (`Eval/Evaluator.cs`)

v1 ran nmap against the PC's own IP and "verified" blocks by connecting to 127.0.0.1. Windows
never filters traffic a PC sends to itself, so everything looked open and verification could
never pass. Since 2.0 SimplySec models the firewall instead.

For every listener and every interface it can be reached through:

1. Loopback binds are **LocalOnly**. A specific bind address means only that interface; a
   wildcard means every active interface of that address family.
2. The interface's profile comes from its connection profile; interfaces without one are treated
   as Public (what Windows does for unidentified networks).
3. Firewall off for that profile → **Reachable** by anyone. "Block all incoming" → **Blocked**.
4. Otherwise each enabled inbound rule is matched on protocol, local port (ranges and the
   `RPC`, `RPC-EPMap`, `IPHTTPS`, `Teredo`, `Ply2Disc` keywords), program path (env vars
   expanded, case folded, `System` = PID 4), service (`*` = any service), interface and
   interface type, local address, and user / owner / AppContainer conditions (SDDL parsed by
   `Security/Sddl.cs`). Each condition answers *yes*, *no* or *can't tell*.
5. Remote address sets are exact interval sets (`Net/AddrSet.cs`), with `LocalSubnet`, `DNS`,
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
  `netstat` and the IP Helper tables show both, and so does SimplySec.
* Not modelled: Windows Service Hardening's hidden static filters, IPsec connection security
  rules, and AppContainer network isolation (sandboxed Store apps are reported as Uncertain
  rather than Reachable).

## Risk and score (`Scoring.cs`)

The knowledge base gives each port, program and service a risk **for exposure on a Public
network**. Exposure width then adjusts it: Public = as is, Private = one level lower, VPN or
virtual-adapter only = two lower, edge traversal = one higher. An unsigned program or one in a
user-writable folder raises it. If the user configured the exposure on purpose (for example
`OLLAMA_HOST=0.0.0.0`) it is capped at Low (Info on Private networks). `info` in the knowledge
base means harmless by design and is never raised.

The **risk score** is 0 when nothing is open and rises with every open finding: Critical 25,
High 12, Medium 5, Low 2 each, capped at 100. Higher means riskier. Info, Kept, Managed and
informational findings are not scored. Grades A ≤ 9, B ≤ 19, C ≤ 34, D ≤ 54, E ≤ 74, F > 74, except that an open Critical finding
makes the grade at least D and a High one at least C. The ring colour follows the grade
(A, B green; C amber; D orange; E, F red).
A score change is positive when the PC got riskier (the daily check notifies at +5).
Scans saved before this scale (100 = clean) are converted once to `100 − old` when the history
database is opened (setting `score_scale`).

"Keep: I need this" stores the finding's exposure width; the finding is shown but not scored,
and comes back only if it becomes reachable more widely.

## Changes: primitives, journal, undo

Every fix is built from reversible primitives (`Actions/Primitives.cs`): each can `snapshot` the
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
| `wifi.connection_mode` | a saved Wi-Fi network connects manually | previous mode |
| `task.schedule` | the daily-check task | the previous task XML, or no task |

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

### What a fix would affect (`Impact.cs`)

Every fix offered on an open finding gets an impact assessment at scan time, recomputed in the
preview. Firewall-type fixes (block rules, profile changes, marking a network Private, removing
v1 rules) are **simulated**: the change is applied to a copy of the firewall model and the
affected listeners are re-evaluated, giving the exact programs, ports and networks that stop (or
start) being reachable. Other fixes use **live usage** collected by `Usage` (`SimplySec.Windows/Services.cs`):
devices connected right now, Remote Desktop sessions (including whether you are connected
remotely), mapped drives and printers reached by short names (NetBIOS/LLMNR), SMB1 clients
(admin), Guest's last sign-in, Remote Assistance running.

Levels: *In use right now* (the fix starts unticked in the preview and is left out of Fix
recommended), *Might affect something you use* (the evidence is listed), *Nothing found using
this*, and *SimplySec can't check this*. If the live-usage data couldn't be collected, nothing
is ever reported as unused.

### Read-only mode and elevation

Scans need no admin. Per-user data (scan history, settings, accepted risks, devices) lives in
`%LOCALAPPDATA%\SimplySec\history.db`, so read-only scans and the daily check (which runs as the
signed-in user) share one history. Only the change journal is in the admin-only folder.

In the GUI, a non-admin user confirms the preview and SimplySec runs one elevated
`simplysec-cli fix --select FINDING=FIX … --yes` (UAC prompt). The elevated process re-derives the
plan from a fresh scan and re-checks the allow-lists; it does not trust anything passed from the
unelevated process except fix and finding ids. Results are then read back from the journal.
"Restart as administrator" is also available.

## Checks

One class per topic in `SimplySec.Core/Checks/` (see `docs/ADDING_A_CHECK.md`). Each provides detection,
plain-language text, fixes and allow-lists. Facts that couldn't be read produce an Info finding
("reported as unknown, not as safe"). Settings controlled by Group Policy or a domain are
reported as *Managed* and never changed.

## Home network, router and Wi-Fi (`Lan/`, `Services.cs` Wi-Fi)

* **Scope.** The IPv4 subnet of each up Ethernet/Wi-Fi interface with a private address, from its
  netmask, capped at /22 around this PC. VPN and virtual adapters are never scanned.
* **Consent.** Before the first scan of a network SimplySec asks "Is this your network?" and
  remembers the answer by network name + subnet (Settings > Networks I own). Nothing is scanned
  otherwise. Other devices only ever get guidance; SimplySec changes nothing on them.
* **Discovery.** Async TCP connects to every address on a few common ports (any answer, even a
  refusal, proves a host and fills the ARP cache), then the Windows neighbor (ARP) table for MAC addresses.
* **Identity.** Bundled IEEE OUI list (`Resources/oui.csv.gz`, rebuilt by
  `scripts/refresh_oui.ps1`; nmap's `nmap-mac-prefixes` as fallback), randomized-MAC detection
  (locally administered bit: "private address, likely a phone"), reverse DNS, SSDP friendly and
  model names.
* **Services.** Async connects on the ~45 ports marked `lan_probe = true` in `ports.toml`;
  optional `nmap -sV` deep scan when nmap is installed (never bundled).
* **Inventory.** Devices are stored by MAC in the per-user history DB with first/last seen,
  label and a trusted flag. New devices are flagged from the second network scan on.
* **Router.** SSDP finds the Internet Gateway Device; SOAP `GetExternalIPAddress` and
  `GetGenericPortMappingEntry` (≤ 256 entries, stop at fault 713). Read-only. XML with DTDs
  prohibited, 256 KB cap, plain-http URLs on the scanned subnet only, no redirects.
  Findings: forward to this PC (Critical unless kept), forward to another device (High), UPnP on
  (Low), CGNAT/private WAN address (Info).
* **Wi-Fi.** `netsh wlan export profile` without `key=clear`; only name, SSID, connection mode,
  authentication and encryption are read and the export folder is deleted at once. Open, WEP,
  TKIP or WPA networks that auto-connect are Medium (fix: `wifi.connection_mode` = manual, undoable);
  being connected to one right now is High.

## History and reports (`Storage/History.cs`, `Report/HtmlReport.cs`)

* Every scan is stored (newest 365) in the per-user history DB with its findings and port table
  (raw facts are not stored). `compare()` reports new and resolved findings, newly reachable or
  no-longer-reachable ports, new devices and the score change; the Overview and History pages
  use it.
* The History page draws the score trend with WPF shapes (`Controls/Charts.cs`).
* `simplysec-cli report --html` and the History page's *Export HTML report* write one
  self-contained, printable file (inline CSS and an inline SVG trend). Every value is HTML-encoded because device names, router names and port-forward descriptions come from the
  network and are untrusted. Findings are grouped into five small-business control areas
  (firewalls, secure configuration, user access control, malware protection, security update
  management), followed by reachable ports, devices, router, changes made and accepted risks.

## Background monitoring (`Engine/DailyCheck.cs`, `Scheduler` and `Toast` in `Services.cs`)

* Settings > Daily check (or `simplysec-cli monitor --enable HH:MM` / `--disable`) creates or removes
  the task `\SimplySec\Daily check` from XML: daily, as the signed-in user, highest privileges,
  only while that user is signed in. Creating it is a journaled `task.schedule` change, so it
  appears on the Changes page and can be undone; moving the time undoes the old change first.
* `SimplySec.exe monitor --run` (what the task runs; no window) does a read-only scan, also scans confirmed home
  networks, saves the result and compares it with the previous scan. It never applies fixes.
* It shows a Windows toast through WinRT, as "SimplySec" (app id `SimplySec.DailyCheck`, registered
  under `HKCU\Software\Classes\AppUserModelId`), only when the risk score rose by 5 or more, a new High or Critical finding
  appeared, a new device joined, or antivirus or the firewall was turned off.
* `monitor --status` shows the task and warns when it runs another copy of SimplySec (2.0 from
  source, or a moved folder); Settings then offers to re-point it (a journaled change).

## Knowledge base

`SimplySec.Core/Resources/knowledge/ports.toml`, `programs.toml` and `services.toml` (embedded resources) are the single source of truth
for every description. v1's nine disagreeing copies were merged and corrected (5357 is WSD, not
WinRM; 10000 has one risk; descriptions now describe a *listening* port, not client use). Tests
check there are no duplicates and every referenced fix id exists.
