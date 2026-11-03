# SimplySec: port from Python to C# / .NET 10 + WPF

## Context
SimplySec v2 is written in Python 3.11 with PySide6: about 13,000 lines of source, 2,400 lines of tests and 176 unit tests. It works, but it is meant for Windows home and small-business users who can't judge whether an exe is safe. Shipped with PyInstaller, it is a 103 MB unsigned exe that elevates itself, edits the firewall and registry, starts hidden `powershell -EncodedCommand` processes and scans the network. That is the pattern antivirus heuristics flag.

We decided in this conversation to port it to **C# on .NET 10 LTS with WPF** now, before any more UI work goes into PySide6.

Choices you confirmed:
- **UI:** keep the same pages, cards, flows and texts, using native Windows 11 controls.
- **Distribution:** an unsigned zip for testers for now; signing comes later.
- **Execution:** one milestone at a time, in this session.
- **Text:** English, written inline in the code (no resource files).

**Outcome:**
1. A C# app whose behaviour is shown to match Python v2 by tests that compare the two.
2. The PowerShell calls replaced by native Windows calls, which is faster and less suspicious to antivirus.
3. A tester zip.
4. Python v2 moved to `legacy/v2-python/`.

**Approach:** **Python v2 is the reference (oracle).** Python generates JSON "golden" results that every C# module must reproduce exactly. On a live PC, both versions scan and their outputs are compared. The rule is to port first and improve after. The core behaviour stays identical until parity is signed off; known quirks are fixed after that (see "Deliberate deviations").

## Environment facts
- .NET SDK 10.0.401 and the Windows Desktop runtime 10.0.12 are installed. `signtool` is not installed, which is fine because signing is deferred.
- All work happens on branch `port/csharp`, created from `main` (HEAD `71ca88d`). There is one commit per milestone gate. Nothing is pushed unless you ask.
- Python stays runnable in `src/simplysec` and `tests/unit` until the cutover. The only Python additions are under `tools/parity/`. No Python app code changes.

## Solution layout
```
SimplySec.slnx
Directory.Build.props      net10.0, C# latest, nullable, warnings-as-errors, x64 only,
                           version 3.0.0, analyzers: CA1305/1307/1309/1310 (culture/ordinal) as errors
Directory.Packages.props   central, pinned versions
src/
  SimplySec.Core/          net10.0 (NOT -windows: the compiler enforces "core never touches the OS")
    Model/      RawScan, Listener, FirewallRule/State, NetInterface, Finding, FixOption, ActionSpec,
                ScanResult, PortRow, enums + explicit JSON mappers (mirroring each to_dict/from_dict)
    Compat/     Python-semantics helpers: NtPath.NormPath, IpInfo.IsPrivate (Python's IANA table),
                TitleCase, FnMatchCase, JsonNode AsList (single-or-array), OrdinalSort
    Net/AddrSet.cs   Security/Sddl.cs   Exposure/ (evaluator)   Knowledge/ (Tomlyn loader)
    Checks/     base + 11 modules (same names as Python), allow-lists, FIXES registry
    Scoring.cs  Impact.cs  Actions/ (primitives + IAdapters interfaces)  Journal.cs  History.cs
    Engine.cs   Monitor.cs  Progress.cs  Lan/ (discovery, identify, inventory, ssdp)  Router/  Report/
  SimplySec.Windows/       net10.0-windows: adapters + collector; CsWin32 P/Invoke; ComImport interfaces;
                           Runner (process/PowerShell), Paths (+ACL), Elevation, Logging
  SimplySec.Commands/      library: every CLI subcommand, its output text and exit codes
  SimplySec.Cli/           console exe, simplysec-cli.exe (thin host of Commands)
  SimplySec.App/           WPF WinExe, SimplySec.exe; with arguments it runs Commands without a
                           window (the scheduled task needs this)
tests/
  SimplySec.Core.Tests/    xUnit v3: golden-driven tests + ported unit tests
  SimplySec.Windows.Tests/ live read-only smoke tests; [Trait("Category","Admin")] end-to-end tests
  SimplySec.App.Tests/     view-model and background-runner tests
  golden/                  JSON corpora generated from Python v2 (committed)
tools/parity/              export_golden.py, dump_raw.py, compare.ps1
```
**Shared data has one source during the port.** The C# projects link the Python files as embedded resources: `src/simplysec/core/knowledge/*.toml`, `resources/oui.csv.gz` and `windows/scripts/facts.ps1`. Nothing is copied, so nothing can drift. At cutover they move into the C# projects.

**Pinned libraries:**

| Library | Used for |
|---|---|
| Microsoft.Data.Sqlite | Journal and history databases |
| Tomlyn | Reading the knowledge-base TOML files |
| Fluid | Report template, rendered with `HtmlEncoder` so all output is escaped (replaces Jinja2 autoescape) |
| System.Management | WMI/CIM |
| Microsoft.Windows.CsWin32 | P/Invoke declarations |
| System.CommandLine 2.0 | CLI parsing |
| WPF-UI (lepoco) | NavigationView, CardExpander, InfoBar, ContentDialog, Mica, theme that follows the system |
| CommunityToolkit.Mvvm | View models |
| Serilog.Sinks.File | Rotating log, 1 MB × 3, same file location |
| xUnit v3 | Tests |

## Rules for the port (from the code review)
- **JSON:** no reflection-based serialization. Hand-written mappers reproduce the exact shapes:
  - enum encoding depends on context (`Severity` as a lower-case name, `Profile` as an int, string enums as their value);
  - `null` is always written;
  - `null` and `""` stay distinct for `package_sid`, `user_sid` and `services`;
  - `FirewallState.profiles` is a list;
  - `details` is a list of pairs.

  Facts stay untyped (`JsonNode`), as in Python.
- **Ordering and comparison:** `StringComparer.Ordinal` everywhere. Sorting uses stable LINQ `OrderBy`, never `List.Sort`. Insertion order is kept with `OrderedDictionary<,>`, which replaces Python dicts and `dict.fromkeys` de-duplication.
- **AddrSet:** intervals are `UInt128` (or `uint` for IPv4). Every `+1` is guarded at `MaxValue`, because Python's unlimited integers hide that overflow. Python's `summarize_address_range` and dotted-mask parsing are reimplemented.
- **Tri-state rule matching:** `bool?`, with the short-circuit order kept exactly.
- **Determinism hooks:** `TimeProvider`, `IRuleIdSource` (replaces `secrets.token_hex(4)` in rule names) and `Func<string,bool> fileExists` are injected. The golden exporter patches the same points in Python.
- **Text:** all plain-language strings are ported verbatim as interpolated strings. The golden tests compare the text too.
- **Data compatibility:**
  - Same paths, including the `SIMPLYSEC_DATA_DIR`/`SIMPLYSEC_USER_DIR` overrides.
  - Same SQLite schemas and JSON blobs, so C# reads Python's `history.db` and can undo changes the Python version made.
  - Same rule naming (`SimplySec:<fix>:<id>`, group `SimplySec`) and task name `\SimplySec\Daily check`.
  - `PRAGMA user_version` is added for future migrations.
- **Windows specifics:**
  - x64 only.
  - Registry access uses `RegistryView.Registry64` and `DoNotExpandEnvironmentNames`. DWORD values are stored as unsigned in JSON.
  - Process names keep the `.exe` suffix, as psutil does.
  - Environment expansion handles `%VAR%` and `$VAR`/`${VAR}`, as Python's `expandvars` does.
- **Allow-lists** (the security boundary): ported predicate by predicate. They are *stricter* where Python's `isinstance(x, int)` accepts bools. Python never writes bools in those fields, so compatibility is unaffected.

## Golden corpus: `tools/parity/export_golden.py` (runs on Python v2)
It patches the clock, rule ids and `file_exists` to fixed values, then writes `tests/golden/`:
1. **primitives:** seeded random cases for AddrSet operations, `describe` and `parse_literal`, including IPv4 and IPv6 edges at 0 and the maximum address. Also SDDL `decide`, `parse_ports`, `normalize_app_path`, `is_private`, `title`, `fnmatch`, scoring and grade tables, and severity weighting.
2. **exposure:** the 45 `CASES` from `test_exposure.py` (conftest builders expanded), every fixture listener × interface, and about 2,000 seeded random rule/listener/interface cases. Each records the verdict, scope, reason text and rule lists.
3. **analyze:** `this_pc_raw.json` (+ variants with the `usage`/`wifi` facts that `test_impact` builds) and about 50 generated scenarios. The scenarios cover each profile off, default allow, block all, network categories flipped, managed policy, every fact set to `needs_admin`/`error`/`missing`, Keep entries, and admin versus not. Each is saved as `ScanResult.to_dict()`.
4. **plans:** for every finding × fix option in each scenario: `build_plan` specs, warnings, impact and refused items. Also `recommended_split`.
5. **apply/undo traces:** the sequence of fake adapter calls and the resulting journal rows (timestamps excluded) for the `test_engine_undo` flows.
6. **misc:**
   - Monitor triggers, history `compare` pairs, and the score-scale migration.
   - LAN and router findings, IGD/SSDP, Wi-Fi XML and nmap XML parsing, and an OUI sample.
   - CLI text output (`scan`, `changes`, `history`) for the fixture.
   - A Python-written `history.db` and journal, used for the compatibility tests.

C# tests compare the parsed JSON trees and report the path of the first difference.

## Milestones (each ends with a gate and a commit)

**P0 Foundation and risk spikes**
- Create the branch, solution, props files, analyzers, the golden exporter and corpus, and the xUnit golden harness.
- Write three throw-away spikes in a console project, so the riskiest native code is proven before the big investment:
  1. Enumerate all ~600 firewall rules through ComImport `INetFwPolicy2`/`INetFwRules` (`IEnumVARIANT`).
  2. Read listeners with PIDs through `GetExtendedTcpTable`/`GetExtendedUdpTable` (IPv4 and IPv6).
  3. Check signatures with `WinVerifyTrust`, falling back to the signature catalog for Windows binaries. Compare the statuses with `Get-AuthenticodeSignature`.
- *Gate:* clean build, harness running, corpus committed, all three spikes agree with Python on this PC.

**P1 Core foundations**
- Model types and their JSON mappers, Compat helpers, AddrSet, Sddl, the knowledge-base loader (with the same validation), and the exposure evaluator.
- *Gate:*
  - C# loads `this_pc_raw.json` and writes it back out semantically equal to Python's `RawScan.to_dict()`.
  - The exposure corpus matches 100%.
  - `test_exposure`, `test_knowledge` and the primitive parts of `test_core_small` are ported.

**P2 Analysis**
- The checks with their allow-lists and FIXES, scoring, impact (simulation needs an explicit deep clone of the firewall model and interfaces), and the engine's `Analyze`, `BuildPlan` and `RecommendedSplit`.
- *Gate:*
  - The `analyze` and `plans` goldens are identical for the fixture and every scenario.
  - `test_checks`, `test_impact` and `test_this_pc` are ported.

**P3 State, network logic and report**
- `IAdapters` interfaces whose method sets come from the Python fakes. Actions and primitives, Journal (read-only mode through `Mode=ReadOnly`), History (schema, migration, keep the newest 365 scans, compare), and the engine's `Apply` and `Undo` (newest first, allow-list plus `before_ok` checks).
- Monitor.
- LAN:
  - discovery with `Socket.ConnectAsync` and a `SemaphoreSlim(256)`, where a refused connection still counts as a host;
  - OUI lookup;
  - inventory;
  - SSDP, and fetching through `HttpClient` with no redirects, no proxy, a 256 KB cap and only addresses on the confirmed network;
  - XML read with `DtdProcessing.Prohibit` and `XmlResolver=null`.
- Router IGD. Report: `report.html.j2` ported to Fluid.
- *Gate:*
  - The apply/undo traces match the goldens.
  - `test_engine_undo`, `test_monitor`, `test_lan`, `test_report` and the rest of `test_core_small` are ported.
  - Compatibility test: C# reads the Python-written history and journal and undoes a change Python recorded (with fake adapters).

**P4 Windows layer and CLI** (the first time real OS calls run)
- **Adapters:**
  - **Firewall:** COM read with the TTK registry join and `SHLoadIndirectString`; writes set properties in Python's exact order, with `Enabled` last; backups through `netsh advfirewall export`.
  - **Registry, services, accounts:** registry; services through CsWin32; accounts through netapi32 by RID.
  - **Network and Wi-Fi:** network (`build_interfaces`, category get/set through `INetworkListManager`); Wi-Fi through `WlanGetProfile`/`WlanSetProfile` (no temp files, never plaintext keys).
  - **Scheduler:** `ITaskService`, with the same task XML. The `UserId` is the *signed-in user*, not the elevated admin.
  - **Listeners:** `.exe` names, token reading, and the service and parent fallbacks.
  - **Signatures:** native, plus a cache keyed on path, size and modified time (the 9-second hotspot).
  - **Usage:** the native parts.
  - **Kept on PowerShell for now:** `facts.ps1` (unchanged), the PowerShell part of `usage`, the `system` setters and toasts. They run through a ported Runner with the identical command line and prelude.
- **Collector:** two phases run with `Task.WhenAll`, with the same progress strings (7 steps, "✓ " prefix) and a `CancellationToken`.
- **Paths:** ACL through `DirectorySecurity` with SDDL `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`.
- **Elevation:** close the handle; report a timeout separately from an exit code; UAC declined maps to Win32 error 1223.
- **Commands:** all subcommands, flags, output and exit codes 0–4, plus a hidden `scan --raw` used only for parity checks.
- *Gate:*
  - `compare.ps1` shows parity three times in a row:
    1. the raw scan, section by section (listeners, rules, interfaces, signatures, env, each fact);
    2. C# `Analyze` on the raw scan Python collected matches Python's analysis;
    3. `scan --json` on both.
  - The elevated end-to-end tests pass, run from an elevated prompt:
    1. Block a test listener on 8765 and confirm the verdict becomes Blocked, then check from a phone. Undo and confirm the group is empty.
    2. Turn Remote Assistance off, check the value, then undo and confirm the original value is back.
  - `monitor --enable/--disable` works.
  - C# undoes a change made earlier by the Python build.

**P5 WPF app**
- **Shell:** FluentWindow + NavigationView (7 pages, same order), the mode badge with "Restart as administrator", the ProgressPanel (step N of M, elapsed time, "still working" after 150 s) and the status bar. The theme follows the system and switches live.
- **MainViewModel:** ports `controller.py`, covering busy, scan, network scan, fix (in-process when admin, through the elevated CLI otherwise), undo, keep, daily check and report.
- **BackgroundRunner:** ports `workers.py`, keeping the guarantee that "finished" fires before the result or error.
- **Pages:** each reproduces the pages documented in the exploration: the Ports DataGrid with its sort keys and filter, the Changes tree, the Network devices grid with the Trusted checkbox and jump-to-card, and so on.
- **Controls:**
  - `FindingCard` is a UserControl, with a CardExpander for "Show more".
  - `PreviewDialog` and `ResultDialog` keep the same content.
  - `ScoreRing` and `TrendChart` are custom `OnRender` controls ported from the QPainter code.
  - Colours are theme resources (Windows 11 palette, severity and grade colours). The colours that were hard-coded now adapt to dark mode.
- **Fix the UI quirks found in the review:**
  - The busy text stays after a failed scan.
  - "Undo everything" is re-enabled whatever the count.
  - Selecting several batches does nothing.
  - "Finished with code 1" is shown when only a finding is still present.
  - `--mark-private` adds every offered warning fix, not just the ticked ones.
- **Developer switch:** `--load-raw <file>` analyses a saved raw scan, so the UI can be exercised without scanning.
- *Gate:*
  - View-model tests pass, ported from `test_gui_smoke`, including the 25-task background test.
  - A manual checklist passes in light and dark: every page; preview → UAC → apply → result → Changes → undo; "Restart as administrator"; the daily-check toggle; the report export; a network scan compared against the router's DHCP list.

**P6 Remove PowerShell, speed up**
- Replace the `facts.ps1` items one at a time with native code:
  - CIM through System.Management: Defender, SMB, shares, NetBIOS configuration and the network profile;
  - WUA COM for update history;
  - the registry;
  - `NetUserEnum`;
  - `IShellItem2` for the BitLocker property.

  Each item is checked against `facts.ps1` output on this PC before it is switched over.
- **Usage:** native too (SMB mappings, printers, SMB sessions through CIM, last logons).
- **Setters through CIM methods:** SMB configuration, `MpPreference`, signature update, `SetTcpipNetbios`, `SystemRestore.CreateRestorePoint`.
- **Toasts:** the app's own AUMID (registered for the current user with a Start-menu shortcut), so they show as "SimplySec".
- *Gate:*
  - No `powershell.exe` is started during a scan, fix or monitor run (checked from the logs and a process trace).
  - Facts parity.
  - Scan time measured against Python's ~15 s.

**P7 Tester packaging**
- `dotnet publish` self-contained win-x64 with ReadyToRun. Both exes go into one folder.
- The app manifest has `asInvoker`, `longPathAware` and `supportedOS`. Version resources (3.0.0) and the icon are included.
- `scripts/build.ps1` writes `dist/SimplySec-<ver>-win64.zip` and has a signing hook that does nothing for now.
- An existing daily-check task that points to Python is re-pointed through a journaled change.
- *Gate:*
  - The zip runs read-only.
  - An elevated fix and undo works.
  - The daily task runs `SimplySec.exe monitor --run` without a window and the toast shows as "SimplySec".
  - The zip is checked with Defender, and with VirusTotal (that upload is your call).

**P8 Cutover**
- Tag `v2-python`, then `git mv` the Python v2 code (src, tests, packaging, pyproject) to `legacy/v2-python/`. Move the knowledge base, OUI list and `facts.ps1` into the C# projects. The golden corpus stays as a frozen regression suite.
- Rewrite README, ARCHITECTURE.md, ADDING_A_CHECK.md (for C#) and SESSION_SUMMARY.md.
- Ask before merging to `main`.

## Deliberate deviations (after parity, or outside what the goldens cover)
- **Bug fixes in the OS layer:**
  - the elevation handle leak and exit code 259;
  - the unhandled `OSError` in the Runner;
  - the scheduled task's user SID taken from the elevated token;
  - the `Get-NetNeighbor` state filter;
  - the unused `data_dir_is_trusted`, which is either wired in or removed.
- **The UI quirks** listed in P5.
- **Core behaviour changes:** none until P4 parity is signed off. After that they get their own commits, with the goldens regenerated or edited on purpose.

## Risks and how they're handled
- **COM enumeration and catalog signatures:** de-risked by the P0 spikes.
- **Python-only semantics** (normpath, is_private, title, unlimited integers, stable sort): the Compat helpers, each with its own golden tests.
- **WPF-UI as a third-party dependency:** pinned and MIT-licensed. The fallback is .NET's built-in Fluent `ThemeMode` with our own navigation.
- **Live parity noise** (short-lived UDP sockets, PIDs that come and go): `compare.ps1` normalises these and lists what it excludes.

## Verification (end to end)
1. `dotnet test` passes: golden corpora, ported unit tests and view-model tests. The admin tests run with `dotnet test --filter Category=Admin` from an elevated prompt.
2. `tools/parity/compare.ps1` reports no differences on this PC, run several times and after the PC's state changes (for example starting `ollama serve`, toggling a test listener).
3. Manual checks:
   - the GUI checklist (P5);
   - an elevated fix and undo checked from a phone;
   - a home-network scan compared with the router's DHCP page;
   - the daily-check task created, run with `schtasks /Run`, and undone.

   These are the four checks never run on the Python build; they now run on the C# build.
4. The tester zip is checked from a fresh unzip (P7).
