# Session summary: C# / .NET 10 port (2026-11-02/03)

Pick up here. The approved plan is [PORT_PLAN.md](PORT_PLAN.md) (milestones P0–P8). All work is on
branch **`port/csharp`** (from `main` at `71ca88d`), never pushed. Python v2 is untouched and still
runs; it is the reference ("oracle") for the port.

## Status

| Milestone | State | Commit |
|---|---|---|
| P0 Foundation, golden corpus, native spikes | done | `cdd1250` |
| P1 Core foundations | done | `53d6602` (with P2) |
| P2 Checks, impact, analysis | done | `53d6602` |
| P3 Actions, journal, history, engine apply/undo, daily check, LAN/router, report | done | `1c5c6c5` |
| P4 Windows layer + CLI | **done** 2026-11-03: smoke run, live parity gate 3/3, Windows tests, elevated checks | `25633f8`, `d2a5c3f` |
| P5 WPF app | **done**: manual checklist passed with the user | `c31d50b` |
| P6 remove PowerShell | **done**: elevated facts test, toast as "SimplySec", fix and undo of each new setter checked with the user (the restore point itself unconfirmed: Windows may skip one within 24 h) | `c65d43f` |
| P7 tester packaging | **in progress**: `scripts/build.ps1` builds and tests the zip; fresh unzip runs read-only; Defender clean; **elevated checks with the user still to do** (see the P7 section) | not committed yet |
| P8 cutover | not started | |

`dotnet test --project tests/SimplySec.App.Tests` → **17 pass** (about 4 s).

`dotnet test --project tests/SimplySec.Windows.Tests` → **28 pass, 2 skipped** (admin, opt-in), about 10 s.

`dotnet test --project tests/SimplySec.Core.Tests` → **53 tests pass** (about 25 s). They include:
- 2,545 exposure cases plus the PC fixture;
- 71 analyze scenarios;
- more than 1,000 fix plans;
- ports of `test_engine_undo`, `test_monitor`, `test_lan`, `test_report`, `test_this_pc` and `test_core_small`;
- a compatibility test in which C# undoes changes recorded by Python v2.

## Layout (what exists)

```
SimplySec.slnx, global.json (SDK 10.0.401, MTP test runner), Directory.Build.props/.Packages.props, .editorconfig
src/SimplySec.Core/        net10.0, pure: Compat/ (Python semantics), Net/AddrSet, Security/Sddl, Model/,
                           Eval/Evaluator, Knowledge/, Checks/ (11 checks + Registry), Scoring, Impact,
                           Engine/ (Analysis, Engine=ScanEngine, DailyCheck), Actions/Primitives (+ adapter
                           interfaces), Storage/ (Journal, History), Lan/ (Lan, Ssdp, Router, LanScan), Report/HtmlReport
src/SimplySec.Windows/     Interop/ (FirewallCom, IpHelper, WinTrust, Native), Runner, Listeners, Firewall,
                           Network, SystemAdapters (registry/services/accounts), Services.cs (SystemSetters,
                           Usage, Wifi, Scheduler, Toast, Nmap, WindowsLanHost), AppHost.cs (Paths+ACL,
                           Elevation, Logging, WindowsHost), Collector
src/SimplySec.Commands/    Cli.cs: every subcommand, texts, exit codes (CliHost injects the OS for tests)
src/SimplySec.Cli/         simplysec-cli.exe (asInvoker manifest)
src/SimplySec.App/         SimplySec.exe (WPF + WPF-UI, all built in code, no XAML). Program (CLI mode with
                           arguments, dev switches), Infrastructure/ (BackgroundRunner, IAppServices, IDialogs,
                           Snapshots), ViewModels/ (MainViewModel = controller.py, PreviewModel), Views/ (MainWindow
                           + 7 pages), Controls/ (FindingCard, ScoreRing, TrendChart, ProgressPanel), Dialogs/,
                           Theme/ (Palette: severity/grade/impact colours per theme; Ui: text/card builders)
tests/SimplySec.Core.Tests golden + ported tests; Support/ (Golden loader, JsonAssert, Fakes, Pinned clock)
tests/SimplySec.Windows.Tests CLI (fakes), XML parsing, native interop (read-only), admin e2e (opt-in)
tests/SimplySec.App.Tests  view model on fakes (elevated path runs the real CLI), runner, window and Changes page
tests/golden/              JSON from Python (gzip) + compat/ (journal.db, history.db written by Python)
tools/parity/              export_golden.py (regenerate goldens), spike_compare.py (P0 spikes vs Python),
                           dump_raw.py + compare_live.py (live parity on this PC)
tools/spikes/              spike console (firewall/sockets/sigs)
```

Shared data still lives in the Python tree, linked by the C# projects:
- the knowledge-base TOMLs and `oui.csv.gz`, embedded in Core;
- `facts.ps1`, copied to `scripts\` in the output.

## Done in P4 (2026-11-03)

1. **Smoke run.** `scan`, `scan --json/--raw/--from-raw`, `changes`, `history`, `report`, `--version` and usage errors all work. `changes`/`history` output is byte-identical to Python; `scan` text differs only by version, time and live drift.
2. **Parity tooling.** `tools/parity/dump_raw.py` (Python collect / analyze) and `tools/parity/compare_live.py`. Run `.venv\Scripts\python tools\parity\compare_live.py [--runs 3] [--out DIR] [--all]`.
   - Step 2 (same RawScan analysed by both, for Python's and C#'s raw) is strict and clean.
   - Steps 1 and 3 separate real differences from live drift. A socket seen by one side only counts as drift unless it was open both before and after the two collections. UDP 5353 ownership and current connections are also drift.
   - **Gate passed: 3/3 clean runs.**
3. **Tests.** New `tests/SimplySec.Windows.Tests` (links Core.Tests `Support/Fakes.cs` and `Golden.cs`):
   - `CliTests`: port of `test_cli.py`, plus the usage error text.
   - `ParsingTests`: Wi-Fi profile (and DTD rejection), nmap XML.
   - `NativeTests`: read-only, on this PC. Covers DOS-path conversion, image path via the NT fallback, loopback adapter, IPv4-before-IPv6 order, the PSModulePath regression and missing-file signatures.
   - `AdminEndToEndTests` (`Category=Admin`): firewall block on 8765 + undo, Remote Assistance + undo. Skipped unless elevated **and** `SIMPLYSEC_ADMIN_TESTS=1`.

### Runtime bugs found and fixed by the smoke/parity runs

- **Listener `exe` empty for SYSTEM services when not elevated** (65 listeners). psutil gets the path with `NtQuerySystemInformation(SystemProcessIdInformation)` + `convert_dos_path`, without opening the process. `Listeners.ProcessExe` now falls back to the same (`NtImageName`, `ConvertDosPath`). This also fixed the user SIDs that depend on `exe` (parent-service and ALWAYS_SYSTEM rules).
- **Interfaces.** .NET's `NetworkInterface` lists filter-driver pseudo-interfaces and keeps the OS address order. `Network.LocalInterfaces` now calls `GetAdaptersAddresses(AF_UNSPEC, 0)` directly, sorts addresses by family (IPv4 first, like psutil) and takes "up" from `GetIfTable` (oper 4/5 and admin up), as `net_if_stats` does.
- **PSModulePath leak.** Started from PowerShell 7, `powershell.exe` 5.1 inherits 7's module path and can't load its own modules (`Get-AuthenticodeSignature` etc.). `Runner` now removes `PSModulePath` for every PowerShell child (`Run` env: a null value removes the variable). Python v2 has the same latent bug; `compare_live.py` strips the variable for both sides.
- **Signatures of unreadable files** (e.g. protected Xbox game folders): `Get-AuthenticodeSignature` throws (v2 records `Unreadable`); WinTrust said `NotSigned`. `WinTrust.Verify` now returns `Unreadable` when the file can't be opened.
- The usage error now lists the choices, like argparse.

4. **Elevated checks**, all passed, run by the user from an elevated prompt:
   - admin tests 2/2 (`$env:SIMPLYSEC_ADMIN_TESTS=1; dotnet test --project tests/SimplySec.Windows.Tests -- --filter-trait "Category=Admin"`);
   - CLI `fix` / `undo` for Remote Assistance and for a firewall block, plus `monitor --enable/--disable`;
   - phone: `python -m http.server 8765` loaded, couldn't be reached while blocked, loaded again after undo;
   - a change made by Python v2 (`fix`) was listed and undone by C#.
   - Not yet exercised: `fix --elevate` from a normal prompt (the UAC relaunch path).

   Tip: Windows Firewall only blocks *new* connections. A phone that already has a connection open can keep loading until that connection closes.

## P5 (2026-11-03)

**What's built:**
- FluentWindow + NavigationView, with the 7 pages in v2's order. The mode badge and "Restart as administrator" sit in the pane footer, the ProgressPanel in the NavigationView header, and the status bar at the bottom. Mica is used, and the theme follows Windows live: code-chosen colours are rebuilt on change.
- **Pages build their content in code, like v2's Qt pages.** Text is added as Runs, never parsed as markup, so finding text can't inject formatting. That replaces v2's `html.escape` in labels.
- Pages can opt out of the NavigationView's outer scroll viewer with `ScrollViewer.CanContentScroll=true` on the page, and every page scrolls itself.
- **Fixes:** in-process when admin; otherwise one elevated helper call (`SimplySec.exe` in CLI mode, or `simplysec-cli.exe` when it sits next to it), then the results are read back from the journal.

**UI quirks fixed (from the review):**
- The busy text no longer stays after a failed scan.
- "Undo everything" is enabled only when something is active.
- Selecting several batches undoes their active changes: the Changes tree is now a flat list with batch rows, because WPF's TreeView can't multi-select.
- "Finished with code 1" isn't shown when the only problem is a finding still present.
- Only the networks the user ticked are marked Private. This needed a new CLI flag, `fix --private-network INDEX` (repeatable); `--mark-private` still means all of them.

**Developer switches:**
- `SimplySec.exe --load-raw FILE` shows a saved `scan --raw`.
- Add `--snapshot DIR` to render every page plus the preview and result dialogs to PNG and exit. `--snapshot DIR` alone scans this PC first.
- `SIMPLYSEC_THEME=light|dark` forces a theme.

**Manual checklist still to run (the P5 gate), in light and dark:**
- every page;
- preview → UAC → apply → result → Changes → undo;
- "Restart as administrator";
- the daily-check toggle;
- report export;
- a network scan compared with the router's DHCP list;
- Ports "Review…" and the double-click details;
- the device "Trusted" checkbox and jump-to-card.

## P6 (2026-11-03)

**Facts:** `NativeFacts` (`src/SimplySec.Windows/NativeFacts.cs`, with `Wmi.cs` and `PsRegistry`) reads the same CIM providers, registry values, netapi32 and COM objects as `facts.ps1`, and writes the same JSON. That includes PowerShell's quirks the checks may see:
- DWORDs are signed.
- A list fact with one entry is that entry, and with none it is `{}` (AutomationNull).
- DNS servers are listed IPv6 first.
- The hotfix tie-break uses .NET Framework 4.0's unstable quicksort (`LegacyQuickSort`), which Windows PowerShell 5.1's `Sort-Object` uses.
- `Get-SmbServerConfiguration` is the class method `GetConfiguration()`, not an instance query.

`SIMPLYSEC_FACTS=ps1` still runs the script, for comparisons until the cutover.

**Measured:**
- Facts: about 0.8 s instead of about 5.6 s.
- `scan --json`: 1.1–1.3 s (Python v2: about 16 s).

**Deviations (documented, no effect on the analysis):**
- `network.ip` keeps the IP-interface order. It's only ever looked up by interface index.
- Last logons have whole seconds (netapi32) instead of ticks.
- Error texts differ; statuses don't.

`compare_live.py` normalises the first two.

**Usage, setters, toasts:**
- `Usage.Extra()` reads CIM: SMB mappings and sessions, and printers. Last logons come from netapi32.
- The setters call CIM methods:
  - `MSFT_SmbServerConfiguration.SetConfiguration`;
  - `MSFT_MpPreference.Set` and `MSFT_MpSignature.Update`;
  - `Win32_NetworkAdapterConfiguration.SetTcpipNetbios`;
  - `SystemRestore.CreateRestorePoint`.
- The network category is an `MSFT_NetConnectionProfile` Put.
- Toasts use WinRT directly with the app id `SimplySec.DailyCheck`, registered under `HKCU\Software\Classes\AppUserModelId`. If Windows refuses that id, they fall back to v2's PowerShell app id; no PowerShell process starts either way.
- Hidden `monitor --test-notification` shows a sample toast.

**Tests (`NativeFactsTests`, live, read-only):**
- facts vs `facts.ps1`;
- usage vs the old script (kept as `Usage.ReferenceScript`);
- a full `Collector.Collect()` starts no `powershell.exe` (`Runner.Started` records every child process);
- the PowerShell sort and unwrap rules.

**Checked with the user (P6 gate):** `NativeFactsTests` elevated 5/5; the test notification shows as "SimplySec"; fix and undo of NetBIOS off, ransomware protection and mark-Private. The NetBIOS undo on an adapter without DHCP (Tailscale) failed with `SetTcpipNetbios` 100, as in v2; it now writes `NetbiosOptions=0` under `NetBT\Parameters\Interfaces\Tcpip_{guid}` instead.

## P7 (2026-11-03)

- **`scripts/build.ps1`** (Windows PowerShell 5.1 or 7): runs the three test suites (`-SkipTests` skips them), publishes `SimplySec.App` and `SimplySec.Cli` self-contained win-x64 with ReadyToRun into `dist\SimplySec-<ver>-win64\`, drops `.pdb`s, adds `packaging\win64\README.txt` (tester readme), checks `simplysec-cli --version`, runs the signing hook (a no-op that names the files), zips to `dist\SimplySec-<ver>-win64.zip` with a `.sha256`, and with `-DefenderScan` scans the zip with `MpCmdRun`. The v2 PyInstaller script is now `scripts/build_v2.ps1`.
- **Result:** 77.6 MB zip, 266 files; both exes carry version 3.0.0 and the icon; Defender found nothing. From a fresh unzip (not elevated) `scan` takes 1.5 s and the GUI renders every page (`--snapshot`).
- `facts.ps1` is no longer published (`CopyToPublishDirectory="Never"`); it stays in the build output for `SIMPLYSEC_FACTS=ps1` and the facts test.
- **Re-pointing a v2 daily task:** `DailyCheck.ParseTask` reads the command, arguments and time from the task XML; `PointsElsewhere` compares them with this copy (`Scheduler.Command()`). Settings shows a banner ("Use this copy for the daily check") that re-creates the task at the same time through `DailyCheck.Enable`, which is journaled: undo restores the old task's XML. New `monitor --status` prints the task and the command to re-point it.
- `NativeTests` and `NativeFactsTests` share an xUnit collection: `ScanStartsNoPowerShell` records every program started, so PowerShell-running tests can't run beside it (it failed once in a Release run).

**Still to do (P7 gate, needs the user):** from an Explorer-extracted copy of the zip: elevated fix and undo; create a v2 daily task, re-point it from Settings, run it with `schtasks /Run` (no window, a monitor scan in History), `SimplySec.exe monitor --test-notification` shows as "SimplySec"; then remove the task. VirusTotal upload is the user's call.

## Next steps

1. Finish the P7 checks with the user, then commit P7.
2. P8: cutover (see PORT_PLAN.md); ask before merging to `main`.

**After cutover (not for parity):** v2 de-duplicates listeners by (protocol, address, port) and keeps the first PID. UDP 5353 is shared by several programs (svchost, adb, NVIDIA…), so the owner, and with it the findings and score (31 vs 33 here), changes from scan to scan.

## Decisions and deviations made during the session

- **Report:** built in C# with `WebUtility.HtmlEncode` on every value. Fluid was dropped, which means one dependency fewer.
- **Native P/Invoke and typed `ComImport`:**
  - Used hand-written declarations instead of CsWin32 (CsWin32 is unused in the package list and can be removed).
  - The P0 spikes proved this approach agrees with Python: 593 rules match, firewall read takes 26 ms instead of 580 ms, and signatures take 0.7 s instead of 4.4 s.
- **Still on netsh / schtasks / PowerShell in P4:** Wi-Fi uses `netsh wlan export`, the daily check uses `schtasks` with the same XML, and the setters, usage and toast still run through PowerShell. This keeps parity for now; P6 replaces them with native calls.
- **Fixed during P4:**
  - The scheduled task's user is the *signed-in* user (from the WTS session), not the elevated account.
  - The elevation helper reports UAC declined (1223) and timeouts separately.
- **Renames:** `Monitor` became `DailyCheck` to avoid clashing with `System.Threading.Monitor`. The evaluator's namespace is `SimplySec.Core.Eval`.
- **CLI additions:**
  - Hidden `scan --raw` and `scan --from-raw FILE` for parity checks.
  - With no arguments it prints usage instead of starting the GUI.
- **Allow-lists** are stricter about int versus bool than Python's `isinstance`.
- **Python quirks reproduced for parity:**
  - IPv6 addresses stored as `/128`, because psutil gives no netmask.
  - Python 3.11.0 `ipaddress` tables: IPv4-mapped addresses delegate `is_private`.
  - ntpath `normpath`, `str.title`, `fnmatch`, unbounded integers via `BigInteger`, and stable ordinal sorts.

## Gotchas learned

- **.NET 10 `dotnet test`** needs `"test": {"runner": "Microsoft.Testing.Platform"}` in `global.json`. Run it with `dotnet test --project <csproj>`.
- **Building `JsonValue` from C# numbers:** use `Js.TryNumber`, because `TryGetValue<long>` fails on an int-backed value.
- **Analyzers** CA1304/1305/1309/1310/1311 are errors in src (relaxed in tests). Use `CultureInfo.InvariantCulture`, `string.Create(...)` and `StringComparison.Ordinal`.
- **Windows projects** target `net10.0-windows10.0.19041.0`, with `SupportedOSPlatformVersion` 10.0.17763.0.
- **The Bash tool** mangles some heredocs containing C#. Write C# files with the Write tool.
- **Shell for parity runs:** this terminal is PowerShell 7. Anything that starts Windows PowerShell from it (Python v2, scripts) needs `PSModulePath` removed, or 5.1 can't load its built-in modules.
- **Live parity is noisy by nature:** Chrome can open 100+ short-lived UDP sockets between two collections. Read `compare_live.py --all` before trusting a drift classification.
- **Regenerating goldens:** `.venv\Scripts\python tools\parity\export_golden.py` (takes about 2 minutes). Commit the `.json.gz` files and `compat/*.db`; there is a `.gitignore` exception for those.
