# Session summary (2026-11-03)

Pick up here; the open work is in [TODO.md](TODO.md). How the program works is in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Where things stand

- **SimplySec 3.0 is C# / .NET 10.** The port from Python 2.0 is finished and the Python code is
  gone from the tree. It is kept at tag **`v2-python`** (and v1 at `v1-legacy`).
- **Branch `port/csharp`**, branched from `main` at `71ca88d`. Not merged and not pushed.
  Merging to `main` is your call (see TODO).
- Build: `dotnet build SimplySec.slnx`. Tests, all green:

  | Project | Result | Time |
  |---|---|---|
  | `tests/SimplySec.Core.Tests` | 53 pass | ~25 s |
  | `tests/SimplySec.Windows.Tests` | 25 pass, 2 skipped (admin, opt-in) | ~10 s |
  | `tests/SimplySec.App.Tests` | 17 pass | ~5 s |

- Run with `dotnet run --project src/SimplySec.App` (GUI) or
  `dotnet run --project src/SimplySec.Cli -- scan`. A scan takes about 1–1.5 s; Python 2.0 took about 16 s.

## How the port was done (milestones, all committed)

| Milestone | Commit |
|---|---|
| P0 foundation, golden corpus, native spikes | `cdd1250` |
| P1–P2 Core: Python-semantics helpers, checks, impact, analysis | `53d6602` |
| P3 actions, journal, history, apply/undo, daily check, LAN/router, report | `1c5c6c5` |
| P4 Windows layer + CLI; live parity with Python 3/3; elevated checks | `25633f8`, `d2a5c3f` |
| P5 WPF app (WPF-UI); manual checklist passed with the user | `c31d50b` |
| P6 no PowerShell: native facts, usage, setters, toasts | `c65d43f` |
| P7 tester packaging (`scripts/build.ps1`), daily-task re-point, fixes | `20f3905` |
| P8 cutover: Python removed, resources moved, docs rewritten | `a14b10b` |

Parity was checked three ways: the golden corpus exported from Python (thousands of exposure
cases, 71 analysis scenarios, more than 1,000 fix plans, primitives, storage), live side-by-side
scans of this PC, and a test where C# undoes changes Python recorded. The corpus is now frozen
regression data in `tests/golden/`.

## Verified with you on this PC

- Every GUI page, in light and dark; preview → UAC → apply → result → undo; Restart as
  administrator; report export; the network scan; the Ports review.
- Elevated fix and undo for firewall blocks, Remote Assistance, NetBIOS off, ransomware
  protection, mark network Private; a block checked from a phone.
- The daily check created, run and removed; the toast shows as "SimplySec".
- The tester zip from a fresh unzip: read-only scan, the GUI, version resources; Defender found
  nothing. **Not yet** done from the zip: elevated fix/undo, daily-task re-point, task run, toast
  (deferred until the UI work is done; see TODO).
- **Not confirmed:** whether "Create a restore point" actually creates one. Windows skips a
  second point within 24 hours without saying so.

## Changes made this session after the port

- `--elevate` added `--yes` to every command; `monitor` rejects it, so
  `monitor --enable --elevate` failed silently (Python 2.0 had the same bug). Now `--yes` is
  added only where accepted.
- The daily-check setting is saved as "on" only if the task was really created (2.0 showed "On"
  for a task that didn't exist).
- `DailyCheck.ParseTask`/`PointsElsewhere` + `monitor --status` + a Settings banner offer to
  re-point a daily-check task that runs another copy (2.0 from source, or a moved folder).
  Found while testing: 2.0's zip build could never create the task (its scheduler module wasn't
  bundled), so only people who ran 2.0 from source can have one.
- The NetBIOS undo on adapters without DHCP (`SetTcpipNetbios` returns 100) writes
  `NetbiosOptions` in the registry instead.
- Cutover tidy-up: the Python tree, `pyproject.toml`, PyInstaller files, parity tools, P0 spikes,
  `legacy/v1` and the old plans were removed from git; `facts.ps1`, the PowerShell runner and
  the tests that compared against PowerShell are gone. The knowledge base and OUI list are now
  in `src/SimplySec.Core/Resources/`, the icon in `src/SimplySec.App/Resources/`.
  `scripts/refresh_oui.py` became `scripts/refresh_oui.ps1` (checked by round-tripping the
  current list).
- Local clean-up (untracked): `.venv`, `build/`, `dist/`, Python caches removed.
  `legacy/v1-artifacts/` (v1 logs and two 2025 firewall `.wfw` backups) was **kept**; delete it
  yourself if you don't need those backups.

## Decisions worth knowing

- **Data compatibility with 2.0 is kept:** same `%ProgramData%\SimplySec\simplysec.db` journal
  and `%LOCALAPPDATA%\SimplySec\history.db`, same JSON. This is why `Compat/` (Python string,
  `ipaddress`, truthiness rules) still exists. Changing it changes results; do that on purpose,
  with the goldens.
- **UI is built in code** (no XAML): pages add text as `Run`s, never parsed as markup, so finding
  text from the network can't inject formatting. `Theme/Ui.cs` has the builders, `Palette.cs` the
  colours; WPF-UI 4.2.1 supplies FluentWindow, NavigationView and theming.
- **Elevation:** the app stays unelevated; fixes run one elevated `simplysec-cli` (or
  `SimplySec.exe` in CLI mode) per batch, which re-plans from a fresh scan and re-checks the
  allow-lists, then the app reads the result back from the journal.
- **Toasts:** WinRT with app id `SimplySec.DailyCheck` (registered under HKCU). If Windows
  refuses it, they fall back to PowerShell's app id (no PowerShell process runs).
- **CLI additions over 2.0:** `scan --raw/--from-raw`, `fix --private-network INDEX`,
  `monitor --status`, hidden `monitor --test-notification`; no-argument CLI prints usage.
- **Developer switches:** `SimplySec.exe --load-raw FILE [--snapshot DIR]`,
  `SimplySec.exe --snapshot DIR` (renders every page and dialog to PNG and exits),
  `SIMPLYSEC_THEME=light|dark`, `SIMPLYSEC_DATA_DIR` / `SIMPLYSEC_USER_DIR` (tests).

## Gotchas

- **`dotnet test`** uses Microsoft.Testing.Platform (`global.json`): run
  `dotnet test --project <path>` **from the repository root** (from elsewhere it fails with
  MSB1001).
- **Admin tests:** elevated prompt, `$env:SIMPLYSEC_ADMIN_TESTS='1'`, then
  `dotnet test --project tests/SimplySec.Windows.Tests -- --filter-trait "Category=Admin"`.
- **A running SimplySec.exe locks the build output.** Close the app before building.
- **Analyzers:** CA1304/1305/1309/1310/1311 are errors in `src`. Use
  `CultureInfo.InvariantCulture`, `string.Create(...)` and `StringComparison.Ordinal`.
- **Building `JsonValue` from C# numbers:** read with `Js.Long`/`Js.TryNumber`;
  `TryGetValue<long>` fails on an int-backed value.
- **The Bash tool collapses `\\` in heredocs**, which corrupted strings twice this session
  (`\r`, `\f`, `\n` appeared in paths and C# strings). Edit files with the Edit/Write tools, or
  put scripts in a file first.
- **Windows Firewall only blocks new connections:** a phone with a connection already open keeps
  loading until it closes.
- **Live scans are noisy:** UDP 5353 is shared by several programs, so its owner (and with it
  a finding and the score) can change between scans.
