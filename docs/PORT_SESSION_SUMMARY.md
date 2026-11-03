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
| P4 Windows layer + CLI | **in progress**: code written and **builds**; not yet run against the real OS or Python | WIP commit (see `git log`) |
| P5 WPF app, P6 remove PowerShell, P7 packaging, P8 cutover | not started | |

`dotnet test --project tests/SimplySec.Core.Tests` → **51 tests pass** (about 25 s). They include:
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
tests/SimplySec.Core.Tests golden + ported tests; Support/ (Golden loader, JsonAssert, Fakes, Pinned clock)
tests/golden/              JSON from Python (gzip) + compat/ (journal.db, history.db written by Python)
tools/parity/              export_golden.py (regenerate goldens), spike_compare.py (P0 spikes vs Python)
tools/spikes/              spike console (firewall/sockets/sigs)
```

Shared data still lives in the Python tree, linked by the C# projects:
- the knowledge-base TOMLs and `oui.csv.gz`, embedded in Core;
- `facts.ps1`, copied to `scripts\` in the output.

## Next steps (finish P4)

1. **Smoke-run the CLI on this PC.**
   - `dotnet run --project src/SimplySec.Cli -- scan`, then `scan --json`, `scan --raw`, `changes`, `history`.
   - Fix runtime issues. Likely candidates:
     - the COM `Interfaces` VARIANT;
     - the `MIB_IPNET_ROW2` layout;
     - `USER_INFO_1` offsets;
     - whether `facts.ps1` reaches the output folder;
     - Serilog setup.
2. **Parity tooling.** Write `tools/parity/dump_raw.py` (Python `windows.collect.collect()` → RawScan JSON) and `tools/parity/compare_live.py`, which checks three things:
   1. the raw scan, section by section: listeners, rules, interfaces, signatures, env and each fact. Ignore UDP 5353 duplicates, timestamps and durations.
   2. C# `scan --from-raw <python raw>` matches Python's `analyze()` of the same raw scan.
   3. `scan --json` from both versions.

   The gate is three clean runs in a row.
3. **Tests.**
   - Add a `tests/SimplySec.Windows.Tests` project: CLI tests with fakes (port `test_cli.py`), Wi-Fi XML (`test_lan` Wi-Fi part) and nmap XML parsing.
   - Add admin end-to-end tests marked `[Trait("Category","Admin")]`: block a test listener on 8765 and undo it; Remote Assistance registry fix and undo.
4. **Elevated checks** (from an elevated prompt):
   - `fix`, `undo`, `monitor --enable/--disable`;
   - check port 8765 from a phone;
   - undo a change made by the Python build.
5. Commit at the P4 gate, then P5 (WPF + WPF-UI, following the documented PySide6 pages and flows).

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
- **Regenerating goldens:** `.venv\Scripts\python tools\parity\export_golden.py` (takes about 2 minutes). Commit the `.json.gz` files and `compat/*.db`; there is a `.gitignore` exception for those.
