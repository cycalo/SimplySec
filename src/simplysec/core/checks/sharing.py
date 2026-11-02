"""Shared folders that grant access to Everyone, anonymous users or guests (guidance only)."""

from __future__ import annotations

from ..models import Severity
from ..util import as_list
from .base import Check, FixDef, ScanContext, fact_unavailable, finding

AREA = "File sharing"
OPEN_SIDS = {"S-1-1-0": "Everyone", "S-1-5-7": "Anonymous", "S-1-5-32-546": "Guests"}
RIGHTS = {0: "Full control", 1: "Change", 2: "Read", 3: "Custom"}

FIX_GUIDE = FixDef(
    id="sharing.review",
    label="Open sharing settings",
    description="Opens Windows' advanced sharing settings so you can review who can access shared folders.",
    might_break="Nothing changes until you change it yourself.",
    guidance="sharing",
)


def run(ctx: ScanContext) -> list:
    shares = ctx.facts.get("shares")
    if shares is None:
        f = fact_unavailable(ctx, "shares", "sharing", AREA, "shared folders")
        return [f] if f else []
    out = []
    for share in as_list(shares):
        bad = [
            a
            for a in as_list(share.get("access"))
            if a.get("allow") and (a.get("sid") or "").upper() in OPEN_SIDS
        ]
        if not bad:
            continue
        writable = any(a.get("right") in (0, 1) for a in bad)
        who = ", ".join(sorted({OPEN_SIDS[a["sid"].upper()] for a in bad}))
        out.append(
            finding(
                id=f"sharing.open.{share.get('name', '').lower()}",
                check="sharing",
                area=AREA,
                title=f"Shared folder '{share.get('name')}' is open to {who}",
                severity=Severity.HIGH if writable else Severity.MEDIUM,
                what=(
                    "Anyone who can sign in to this PC over the network can "
                    + ("change or delete" if writable else "read")
                    + " these files. Ransomware on another PC can encrypt writable shares too."
                ),
                details=[("Path", share.get("path", ""))]
                + [(a.get("account", a.get("sid")), RIGHTS.get(a.get("right"), "?")) for a in bad],
                fixes=[FIX_GUIDE.option()],
                learn_more="Share with specific user accounts instead of Everyone, and give Read access where Change isn't needed.",
            )
        )
    return out


CHECK_DEF = Check(id="sharing", area=AREA, run=run, fixes=[FIX_GUIDE])
