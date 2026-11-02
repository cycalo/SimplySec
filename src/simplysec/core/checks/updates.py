"""Windows Update: last install, paused updates, pending restart (guidance only)."""

from __future__ import annotations

import datetime as dt

from ..models import Severity
from .base import Check, FixDef, ScanContext, fact_unavailable, finding

AREA = "Updates"

FIX_OPEN = FixDef(
    id="updates.open_settings",
    label="Open Windows Update",
    description="Opens Settings > Windows Update.",
    might_break="Nothing changes until you install updates.",
    guidance="windows_update",
)


def _parse(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    if "." in text:  # .NET writes 7 fractional digits; Python accepts up to 6
        head, _, tail = text.partition(".")
        digits = "".join(ch for ch in tail if ch.isdigit())
        rest = tail[len(digits) :]
        text = f"{head}.{digits[:6]}{rest}"
    try:
        d = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.UTC)


def run(ctx: ScanContext, now: dt.datetime | None = None) -> list:
    data = ctx.facts.get("updates")
    if data is None:
        f = fact_unavailable(ctx, "updates", "updates", AREA, "Windows Update history")
        return [f] if f else []
    now = now or dt.datetime.now(dt.UTC)
    out = []
    dates = [
        d for d in (_parse(data.get("last_history_install")), _parse(data.get("last_hotfix"))) if d
    ]
    if not dates:
        out.append(
            finding(
                id="updates.unknown",
                check="updates",
                area=AREA,
                title="Could not tell when Windows was last updated",
                severity=Severity.INFO,
                what="No update history was found. Open Windows Update to check.",
                fixes=[FIX_OPEN.option()],
            )
        )
    else:
        last = max(dates)
        days = (now - last).days
        if days > 30:
            out.append(
                finding(
                    id="updates.stale",
                    check="updates",
                    area=AREA,
                    title=f"Windows hasn't installed an update for {days} days",
                    severity=Severity.HIGH if days > 45 else Severity.MEDIUM,
                    what=(
                        "Microsoft fixes security holes every month. Attackers use known holes soon after "
                        "they are published, so PCs that miss updates are easy targets."
                    ),
                    details=[
                        ("Last update installed", last.date().isoformat()),
                        ("Hotfix", str(data.get("last_hotfix_id"))),
                    ],
                    fixes=[FIX_OPEN.option()],
                )
            )
    pause = data.get("pause") or {}
    until = [d for d in (_parse(v) for v in pause.values()) if d and d > now]
    if until:
        out.append(
            finding(
                id="updates.paused",
                check="updates",
                area=AREA,
                title=f"Windows updates are paused until {max(until).date().isoformat()}",
                severity=Severity.MEDIUM,
                what="While updates are paused, security fixes are not installed.",
                fixes=[FIX_OPEN.option(label="Resume updates")],
            )
        )
    if data.get("reboot_pending"):
        out.append(
            finding(
                id="updates.reboot_pending",
                check="updates",
                area=AREA,
                title="Restart to finish installing updates",
                severity=Severity.LOW,
                what="Some updates are installed but only take effect after a restart.",
                fixes=[FIX_OPEN.option()],
            )
        )
    return out


CHECK_DEF = Check(id="updates", area=AREA, run=run, fixes=[FIX_OPEN])
