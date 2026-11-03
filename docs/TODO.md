# TODO

Ordered roughly by when it's needed. Background is in [SESSION_SUMMARY.md](SESSION_SUMMARY.md).

## Before changing checks or wording

- [ ] **Golden update mode.** The golden corpus in `tests/golden/` was exported from Python 2.0,
  and the exporter is gone. `AnalyzeGoldenTests` (and the plan, exposure and primitive goldens)
  compare exact JSON, so any deliberate change to a check, a finding's text, scoring or a fix
  plan makes them fail with no way to regenerate them. Add a switch (for example
  `SIMPLYSEC_UPDATE_GOLDEN=1`) that rewrites the expected `*.json.gz` from the C# output, then
  review the diff in git like any other change. UI-only work doesn't touch these tests.

## While improving the GUI / UX

- [ ] Your UI/UX changes. Pages are built in code: `src/SimplySec.App/Views/*Page.cs`, shared
  builders in `Theme/Ui.cs`, colours in `Theme/Palette.cs`, cards and charts in `Controls/`.
- [ ] After each round: `dotnet test --project tests/SimplySec.App.Tests` (it renders every page
  and runs the view-model flows), and check light and dark
  (`$env:SIMPLYSEC_THEME='light'` / `'dark'`). `SimplySec.exe --snapshot DIR` renders every page
  and dialog to PNG for a quick visual review.

## Before giving the zip to testers (deferred P7 checks)

Build with `powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -DefenderScan`, copy the
zip somewhere it gets "downloaded from the internet" status (or add a `Zone.Identifier` stream with
`ZoneId=3`), **Extract All** in Explorer, then from that folder:

- [ ] SmartScreen prompt → Run anyway; the window says "SimplySec 3.x (read-only)".
- [ ] Elevated fix and undo from the window (UAC shows "Unknown publisher").
- [ ] `simplysec-cli.exe fix --finding … --fix … --elevate` from a normal prompt (the CLI's UAC
  relaunch path has never been exercised).
- [ ] Daily check: create it from a *different* copy (for example `dotnet run`), then in the zip
  copy `simplysec-cli.exe monitor --status` should warn and Settings should show
  "Use this copy for the daily check". Re-point it, then `schtasks /Run /TN "\SimplySec\Daily check"`:
  no window, and `simplysec-cli.exe history --limit 1` shows a new `monitor` scan.
- [ ] `SimplySec.exe monitor --test-notification` shows a toast as "SimplySec".
- [ ] Turn the daily check off; the Changes page shows it undone.
- [ ] Optional: upload the zip to VirusTotal (your call; it becomes public there).

## Release and distribution

- [ ] Decide when to merge `port/csharp` into `main` (and whether to push; nothing is pushed yet).
- [ ] Bump the version in **two** places: `Directory.Build.props` (`<Version>`) and
  `AppInfo.Version` in `src/SimplySec.Core/Engine/Analysis.cs`. `build.ps1` fails if they differ.
  Consider deriving `AppInfo.Version` from the assembly instead.
- [ ] Code signing: get a certificate and fill in `Invoke-Signing` in `scripts/build.ps1`. Until
  then SmartScreen warns on every download.
- [ ] Maybe later: an installer or Start-menu shortcut, and a way to tell testers about updates.

## Open questions and known issues

- [ ] **Restore point not confirmed.** Check System Protection is on for C: (Start → "Create a
  restore point"), then try "Create a restore point" in the fix preview and look for
  "SimplySec changes" in System Restore. Windows silently skips a point within 24 hours of the
  last one; consider telling the user when that happens.
- [ ] **UDP 5353 owner flips between scans** (shared by svchost, NVIDIA, adb…). Listeners are
  de-duplicated by (protocol, address, port), keeping the first PID, so the finding and the
  score can change from scan to scan. Pick a stable rule (for example, prefer a known Windows
  service, or report all owners).
- [ ] `simplysec-cli --help` is not supported (prints a usage error). Add real help text.
- [ ] `Compat/` keeps Python names (`Js.PyRepr`, `PyIp`, `PyStr`). Fine as is; rename only together
  with the golden update mode.
- [ ] Some code comments still mention "v2" to explain a behaviour difference; that's intentional
  history, trim them if they get in the way.

## Clean-up on this PC (from the testing session)

- [ ] Settings shows "Daily check: On, daily at 12:30", but no task exists (left by 2.0's
  failed attempt). Untick it and Apply (UAC) to reset the setting.
- [ ] If you didn't undo it: the LLMNR fix from the tester check is still applied (Changes page).
- [ ] `legacy/v1-artifacts/` (untracked) holds v1 logs and two firewall backups from 2025. Delete
  it if you don't need them.
