"""Command-line interface.

simplysec                      start the GUI
simplysec scan [--json]
simplysec fix recommended | --finding ID --fix FIX_ID | --select ID=FIX ...  [--yes]
simplysec keep --finding ID
simplysec undo --change N | --batch N | --all | --rules  [--yes]
simplysec changes
simplysec history [--limit N]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any

from . import __version__
from .app import elevation, logs

log = logging.getLogger(__name__)

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_NEEDS_ADMIN, EXIT_DECLINED = 0, 1, 2, 3, 4

CHECK_MARK, CROSS_MARK = "✓", "✗"
SEV_MARK = {"critical": "!!", "high": "! ", "medium": "~ ", "low": "- ", "info": "  "}


def _out(text: str = "") -> None:
    print(text)


def _engine() -> Any:
    from .core.engine import Engine

    return Engine()


def _progress(text: str) -> None:
    print(f"  {text}", file=sys.stderr)


# --------------------------------------------------------------------------- scan


def _print_scan(result: Any) -> None:
    _out(f"SimplySec {result.version} - {result.computer} - {result.started}")
    _out(
        f"Score {result.score}/100, grade {result.grade}"
        + ("" if result.is_admin else "  (read-only: not running as administrator)")
    )
    for line in result.network_status():
        _out(f"  {line}")
    counts = result.counts()
    _out("Open findings: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
    _out()
    current = None
    for f in result.findings:
        if f.area != current:
            current = f.area
            _out(f"[{current}]")
        status = "" if f.status.value == "open" else f" ({f.status.value})"
        _out(f" {SEV_MARK[f.severity.name.lower()]} {f.severity.label:<8} {f.title}{status}")
        _out(
            f"      id: {f.id}"
            + (f"   fixes: {', '.join(o.fix_id for o in f.fixes)}" if f.fixes else "")
        )
    _out()
    reachable = [p for p in result.ports if p.verdict.value in ("reachable", "uncertain")]
    _out(f"Ports other devices can reach ({len(reachable)} of {len(result.ports)} listening):")
    for p in reachable:
        _out(
            f"  {p.protocol.upper():<4}{p.port:<6} {p.process[:24]:<24} {p.risk.label:<8} {p.reachable_from}"
        )
    if result.errors:
        _out()
        _out("Problems while scanning:")
        for e in result.errors:
            _out(f"  {e}")


def cmd_scan(args: argparse.Namespace) -> int:
    engine = _engine()
    result = engine.scan(progress=None if args.json else _progress, save=not args.no_save)
    if args.json:
        json.dump(result.to_dict(include_facts=args.facts), sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        _print_scan(result)
    return EXIT_OK


# --------------------------------------------------------------------------- fix / keep


def _relaunch_elevated() -> int:
    """Re-run the same command elevated (the user already confirmed by adding --elevate)."""
    argv = [a for a in sys.argv[1:] if a != "--elevate"]
    if "--yes" not in argv:
        argv.append("--yes")
    code = elevation.run_elevated_and_wait(argv)
    return EXIT_DECLINED if code is None else code


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def cmd_fix(args: argparse.Namespace) -> int:
    from .core.engine import NeedsAdmin, Selection

    if not elevation.is_admin():
        _out("Applying fixes needs administrator rights. Run this from an elevated prompt,")
        _out("or add --elevate to relaunch with a UAC prompt.")
        if args.elevate:
            return _relaunch_elevated()
        return EXIT_NEEDS_ADMIN
    engine = _engine()
    before = engine.scan(progress=_progress, save=False)
    selections: list[Selection] = []
    if args.target == "recommended":
        selections = engine.recommended(before)
        if not selections:
            _out("Nothing to fix: no open findings have a recommended, non-disruptive fix.")
            return EXIT_OK
    else:
        pairs = list(args.select or [])
        if args.finding or args.fix:
            if not (args.finding and args.fix):
                _out("Give both --finding ID and --fix FIX_ID.")
                return EXIT_USAGE
            pairs.append(f"{args.finding}={args.fix}")
        if not pairs:
            _out(
                "Give 'recommended', --finding ID --fix FIX_ID, or --select ID=FIX_ID (see 'simplysec scan')."
            )
            return EXIT_USAGE
        for pair in pairs:
            finding_id, _, fix_id = pair.rpartition("=")
            f = before.finding(finding_id)
            if f is None:
                _out(f"No finding {finding_id!r} in a fresh scan (already resolved?).")
                return EXIT_FAIL
            opt = next((o for o in f.fixes if o.fix_id == fix_id), None)
            if opt is None:
                _out(
                    f"Finding {finding_id} offers: {', '.join(o.fix_id for o in f.fixes) or 'no fixes'}"
                )
                return EXIT_USAGE
            selections.append(Selection(opt.fix_id, opt.params, f.id))
        if args.mark_private:
            extra = []
            for item in engine.plan(selections).items:
                for w in item.warnings:
                    if w.offer_fix and all(sel.params != w.offer_params for sel in extra):
                        extra.append(Selection(w.offer_fix, w.offer_params, None))
            selections = extra + selections

    plan = engine.plan(selections)
    for r in plan.refused:
        _out(f"Refused: {r}")
    if not plan.items:
        return EXIT_FAIL
    _out("SimplySec will make these changes:")
    for item in plan.items:
        _out(f"  {item.fix.label}")
        for s in item.specs:
            _out(f"    - {s.summary}")
        for w in item.warnings:
            _out(f"    ! {w.text}")
            if w.offer_fix:
                _out("      (add --mark-private to do that first)")
    _out("What might stop working:")
    for line in plan.might_break:
        _out(f"  - {line}")
    _out("Every change is recorded and can be undone with 'simplysec undo'.")
    if not _confirm("Apply these changes?", args.yes):
        _out("Nothing changed.")
        return EXIT_DECLINED
    try:
        result = engine.apply(plan, restore_point=args.restore_point, progress=_progress)
    except NeedsAdmin as exc:
        _out(str(exc))
        return EXIT_NEEDS_ADMIN
    for w in result.warnings:
        _out(f"Warning: {w}")
    after = engine.scan(progress=_progress, save=True)
    resolved = engine.resolved(before, after, [i.finding_id for i in plan.items if i.finding_id])
    _out()
    _out(
        f"Batch {result.batch_id}"
        + (f", firewall backup: {result.backup}" if result.backup else "")
    )
    ok = True
    for o in result.outcomes:
        mark = f"Verified {CHECK_MARK}" if o.status == "applied" and o.verified else CROSS_MARK
        if not (o.status == "applied" and o.verified):
            ok = False
        _out(f"  [{mark}] #{o.change_id} {o.spec.summary}" + (f"  ({o.error})" if o.error else ""))
    for fid, gone in resolved.items():
        _out(
            f"  Finding {fid}: {'resolved in a fresh scan' if gone else 'STILL PRESENT in a fresh scan'}"
        )
        ok = ok and gone
    _out(f"Score {before.score} -> {after.score}")
    return EXIT_OK if ok else EXIT_FAIL


def cmd_keep(args: argparse.Namespace) -> int:
    engine = _engine()
    result = engine.scan(progress=_progress, save=False)
    f = result.finding(args.finding)
    if f is None or not f.keep_key:
        _out("That finding doesn't offer 'Keep'.")
        return EXIT_USAGE
    if args.undo:
        engine.history.unaccept(f.keep_key)
        _out(f"'{f.title}' will be scored again.")
    else:
        engine.history.accept(f.keep_key, f.width, f.title)
        _out(
            f"Kept: '{f.title}'. It is shown but not scored, and comes back only if it gets wider."
        )
    return EXIT_OK


# --------------------------------------------------------------------------- undo / changes


def cmd_changes(args: argparse.Namespace) -> int:
    from .app import paths
    from .core.journal import Journal

    journal = Journal(paths.journal_path(), readonly=True)
    batches = {b.id: b for b in journal.batches()}
    changes = journal.changes()
    if not changes:
        _out("SimplySec has not changed anything on this PC.")
        return EXIT_OK
    current = None
    for c in changes:
        if c.batch_id != current:
            current = c.batch_id
            b = batches.get(c.batch_id)
            _out(f"Batch {c.batch_id} - {b.created if b else ''} - {b.title if b else ''}")
            if b and b.backup:
                _out(f"  firewall backup: {b.backup}")
        v = {True: "verified", False: "NOT verified", None: ""}[c.verified]
        _out(f"  #{c.id:<4} {c.status:<13} {v:<12} {c.summary}")
        if c.error:
            _out(f"         error: {c.error}")
    return EXIT_OK


def cmd_undo(args: argparse.Namespace) -> int:
    from .core.engine import NeedsAdmin

    if not elevation.is_admin():
        _out(
            "Undo needs administrator rights. Run this from an elevated prompt (or add --elevate)."
        )
        if args.elevate:
            return _relaunch_elevated()
        return EXIT_NEEDS_ADMIN
    engine = _engine()
    if not (args.all or args.batch or args.change or args.rules):
        _out("Choose --change N, --batch N, --all or --rules.")
        return EXIT_USAGE
    what = (
        "every change SimplySec made"
        if args.all
        else "all SimplySec firewall rules"
        if args.rules
        else f"batch {args.batch}"
        if args.batch
        else f"change(s) {', '.join(map(str, args.change))}"
    )
    if not _confirm(f"Undo {what}?", args.yes):
        return EXIT_DECLINED
    try:
        if args.rules:
            outcomes, leftovers = engine.remove_all_rules()
            for name in leftovers:
                _out(f"  removed unjournaled SimplySec rule {name}")
        else:
            outcomes = engine.undo(change_ids=args.change, batch_id=args.batch, everything=args.all)
    except NeedsAdmin as exc:
        _out(str(exc))
        return EXIT_NEEDS_ADMIN
    if not outcomes:
        _out("Nothing to undo.")
    ok = True
    for o in outcomes:
        mark = CHECK_MARK if o.ok else CROSS_MARK
        _out(f"  [{mark}] #{o.change.id} {o.change.summary}" + (f" ({o.error})" if o.error else ""))
        ok = ok and o.ok
    return EXIT_OK if ok else EXIT_FAIL


# --------------------------------------------------------------------------- history / report / monitor


def cmd_history(args: argparse.Namespace) -> int:
    from .core.history import compare

    engine = _engine()
    scans = engine.history.scans(limit=args.limit)
    if not scans:
        _out("No scans saved yet.")
        return EXIT_OK
    for s in scans:
        data = engine.history.scan_data(s.id)
        prev = engine.history.previous_to(s.id)
        diff = compare(prev, data) if data else None
        extra = ""
        if diff and not diff.empty:
            extra = f"  ({diff.score_change:+d}; {len(diff.new_findings)} new, {len(diff.resolved_findings)} resolved)"
        _out(f"#{s.id:<5} {s.ts}  {s.kind:<8} {s.score:>3} {s.grade}{extra}")
    return EXIT_OK


# --------------------------------------------------------------------------- entry


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="simplysec", description="SimplySec: plain-language Windows security checks."
    )
    p.add_argument("--version", action="version", version=f"SimplySec {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose log file")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="read-only scan of this PC")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.add_argument("--facts", action="store_true", help="include raw facts in JSON")
    s.add_argument("--no-save", action="store_true", help="don't add to history")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", help="apply a fix (administrator)")
    f.add_argument(
        "target", nargs="?", default="", help="'recommended' or empty with --finding/--fix"
    )
    f.add_argument("--finding")
    f.add_argument("--fix")
    f.add_argument("--select", action="append", metavar="FINDING_ID=FIX_ID", help="repeatable")
    f.add_argument("--yes", action="store_true")
    f.add_argument(
        "--restore-point", action="store_true", help="create a System Restore point first"
    )
    f.add_argument(
        "--mark-private", action="store_true", help="also mark the current Public network Private"
    )
    f.add_argument("--elevate", action="store_true", help="relaunch with a UAC prompt if needed")
    f.set_defaults(func=cmd_fix)

    k = sub.add_parser("keep", help="keep a finding (accepted risk)")
    k.add_argument("--finding", required=True)
    k.add_argument("--undo", action="store_true", help="score it again")
    k.set_defaults(func=cmd_keep)

    u = sub.add_parser("undo", help="undo changes (administrator)")
    u.add_argument("--change", type=int, nargs="+")
    u.add_argument("--batch", type=int)
    u.add_argument("--all", action="store_true", help="undo everything SimplySec changed")
    u.add_argument("--rules", action="store_true", help="remove all SimplySec firewall rules")
    u.add_argument("--yes", action="store_true")
    u.add_argument("--elevate", action="store_true")
    u.set_defaults(func=cmd_undo)

    c = sub.add_parser("changes", help="list every change SimplySec made")
    c.set_defaults(func=cmd_changes)

    h = sub.add_parser("history", help="list saved scans")
    h.add_argument("--limit", type=int, default=30)
    h.set_defaults(func=cmd_history)

    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    logs.setup(verbose=getattr(args, "verbose", False))
    if not args.command:
        from .ui.app import run_gui

        return run_gui()
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return EXIT_DECLINED
