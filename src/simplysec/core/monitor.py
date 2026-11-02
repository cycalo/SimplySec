"""Background daily check: a read-only scan, saved to history, with a toast only when it matters.

Notifies when the risk score rises by 5 or more, a new High or Critical finding appears, a new
device joins a confirmed network, or antivirus / the firewall was turned off. It never applies
fixes.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from .history import compare
from .models import ActionSpec

if TYPE_CHECKING:
    from .engine import Engine

log = logging.getLogger(__name__)

TASK_NAME = r"\SimplySec\Daily check"
SETTING = "daily_check"
PROTECTION_OFF = re.compile(r"^(firewall\.off\.|malware\.no_antivirus$|malware\.realtime_off$)")


def triggers(prev: dict[str, Any] | None, cur: dict[str, Any]) -> list[str]:
    """Plain-language reasons to notify (empty: stay quiet)."""
    out: list[str] = []
    diff = compare(prev, cur)
    if prev is not None and diff.score_change >= 5:
        out.append(f"Your risk score rose from {prev.get('score')} to {cur.get('score')}.")
    prev_open = {f["id"] for f in (prev or {}).get("findings", []) if f.get("status") == "open"}
    for f in cur.get("findings", []):
        if f.get("status") != "open" or f["id"] in prev_open:
            continue
        if PROTECTION_OFF.match(f["id"]):
            out.append(f["title"] + ".")
    for f in diff.new_findings if prev is not None else []:
        if f.get("severity") in ("high", "critical") and not PROTECTION_OFF.match(f["id"]):
            out.append(f"New: {f['title']}.")
    for d in diff.new_devices:
        out.append(
            f"New device on your network: {d.get('name') or d.get('vendor') or d.get('ip')}."
        )
    return out


def run_once(engine: Engine, notify: Any = None) -> int:
    """``simplysec monitor --run``: scan, save, compare, notify. Returns an exit code."""
    from . import lan

    if notify is None:
        from ..windows import toast

        notify = toast.show
    previous = engine.history.latest(1)
    prev = previous[0] if previous else None
    result = engine.scan(save=False, kind="monitor")
    if lan.owned_networks(engine.history):
        try:
            lan.scan_network(engine, result)
        except Exception as exc:
            log.warning("monitor: network scan failed: %s", exc)
            result.errors.append(f"home-network scan failed: {exc}")
    engine.history.save_scan(result, kind="monitor")
    reasons = triggers(prev, result.to_dict(include_facts=False))
    log.info("monitor run: score %s, %d notification reason(s)", result.score, len(reasons))
    if reasons:
        title = "SimplySec: something changed" if len(reasons) > 1 else "SimplySec"
        notify(
            title,
            reasons[:2]
            + (
                [f"…and {len(reasons) - 2} more. Open SimplySec for details."]
                if len(reasons) > 2
                else []
            ),
        )
    return 0


# --------------------------------------------------------------------------- enabling


def schedule_spec(time: str) -> ActionSpec:
    return ActionSpec(
        "task.schedule",
        {"name": TASK_NAME, "time": time},
        f"Create the scheduled task '{TASK_NAME}' (daily at {time}, read-only).",
    )


def active_change(engine: Engine) -> Any:
    for c in sorted(engine.journal.active_changes(), key=lambda c: c.id, reverse=True):
        if c.kind == "task.schedule":
            return c
    return None


def enable(engine: Engine, time: str) -> Any:
    """Create (or move) the daily check. Journaled; needs admin."""
    from .checks.base import FixDef
    from .engine import Plan, PlannedFix

    current = active_change(engine)
    if current is not None:
        engine.undo(change_ids=[current.id])
    fix = FixDef(id="monitor.enable", label="Daily check", description="", might_break="")
    plan = Plan(items=[PlannedFix(fix, {"time": time}, None, [schedule_spec(time)], [])])
    result = engine.apply(plan)
    engine.history.set_setting(SETTING, {"enabled": True, "time": time})
    return result


def disable(engine: Engine) -> bool:
    """Remove the daily check by undoing its journaled change (or delete a stray task)."""
    current = active_change(engine)
    ok = True
    if current is not None:
        ok = all(o.ok for o in engine.undo(change_ids=[current.id]))
    elif engine.adapters.scheduler is not None and engine.adapters.scheduler.exists(TASK_NAME):
        engine.adapters.scheduler.delete(TASK_NAME)
    settings = engine.history.get_setting(SETTING, {}) or {}
    engine.history.set_setting(SETTING, {**settings, "enabled": False})
    return ok


def cli_toggle(engine: Engine, enable_it: bool, time: str = "12:00") -> int:
    if not engine.is_admin:
        print("Turning the daily check on or off needs administrator rights (use --elevate).")
        return 3
    if enable_it:
        res = enable(engine, time)
        ok = res.ok
        print(
            ("Daily check scheduled at " + time)
            if ok
            else "Could not schedule the daily check; see 'simplysec changes'."
        )
        return 0 if ok else 1
    ok = disable(engine)
    print(
        "Daily check removed."
        if ok
        else "Could not remove the daily check; see 'simplysec changes'."
    )
    return 0 if ok else 1
