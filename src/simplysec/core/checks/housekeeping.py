"""Housekeeping: SimplySec v1 leftovers, managed (organisation) PCs, network categories."""

from __future__ import annotations

import fnmatch
from typing import Any

from ..models import ActionSpec, FindingStatus, Severity
from .base import Allow, Check, FixDef, ScanContext, finding

AREA = "Housekeeping"

# Rule names v1 created (six different formats, see docs/PLAN.md).
V1_PATTERNS = [
    "simplesec-*",
    "*-simplesec",
    "blockport*",
    "restrictport*",
    "simplesec-winrm-*-allowlocal",
]


def is_v1_rule(name: str) -> bool:
    n = (name or "").lower()
    return any(fnmatch.fnmatchcase(n, p) for p in V1_PATTERNS)


def _build_cleanup(params: dict[str, Any]) -> list[ActionSpec]:
    return [
        ActionSpec(
            "firewall.remove_rule",
            {"name": n},
            f"Remove old v1 firewall rule '{n}' (its full definition is saved for undo).",
        )
        for n in params.get("names", [])
    ]


FIX_CLEANUP = FixDef(
    id="housekeeping.remove_v1_rules",
    label="Remove v1 leftovers",
    description="Removes the firewall rules the old SimpleSec v1 created. Their definitions are saved so this can be undone.",
    might_break="Nothing SimplySec 2 relies on. Some v1 rules opened ports to your network; those will close.",
    build=_build_cleanup,
)


def _build_private(params: dict[str, Any]) -> list[ActionSpec]:
    name = params.get("name") or params.get("alias")
    return [
        ActionSpec(
            "network.category",
            {"index": int(params["index"]), "alias": params.get("alias", ""), "profile": "Private"},
            f"Mark the network '{name}' ({params.get('alias')}) as Private (a trusted home network).",
        )
    ]


FIX_PRIVATE = FixDef(
    id="network.mark_private",
    label="Mark as Private (home) network",
    description="Tells Windows this is your trusted home network, so your own devices can reach this PC under the Private firewall rules.",
    might_break="Only do this for your own home or office network, never for café or hotel Wi-Fi.",
    build=_build_private,
)


def run(ctx: ScanContext) -> list:
    out = []
    leftovers = [r for r in ctx.firewall.rules if is_v1_rule(r.name)]
    if leftovers:
        names = sorted({r.name for r in leftovers})
        allow_rules = [r.name for r in leftovers if r.action == "allow"]
        out.append(
            finding(
                id="housekeeping.v1_rules",
                check="housekeeping",
                area=AREA,
                title=f"{len(names)} firewall rule(s) left behind by SimpleSec v1",
                severity=Severity.MEDIUM if allow_rules else Severity.LOW,
                what=(
                    "The old version created firewall rules in several formats and could not clean them up. "
                    + ("Some of them OPEN ports to your network. " if allow_rules else "")
                    + "Removing them is safe and can be undone."
                ),
                details=[
                    (
                        r.name,
                        f"{r.action} {r.protocol_label} {r.local_ports} from {r.remote_addresses}",
                    )
                    for r in leftovers
                ],
                fixes=[FIX_CLEANUP.option({"names": names})],
            )
        )
    if ctx.managed:
        system = ctx.facts.get("system") or {}
        reason = (
            f"it is joined to the domain '{system.get('domain')}'"
            if system.get("part_of_domain")
            else "Group Policy sets its firewall"
        )
        f = finding(
            id="housekeeping.managed",
            check="housekeeping",
            area=AREA,
            title="This PC is managed by an organisation",
            severity=Severity.INFO,
            what=(
                f"SimplySec detected that {reason}. Settings controlled by your organisation are reported "
                "only and never changed. Ask your IT team about them."
            ),
        )
        f.status = FindingStatus.INFO
        out.append(f)
    return out


def _allow_remove(params: dict[str, Any]) -> bool:
    return set(params) == {"name"} and is_v1_rule(str(params["name"]))


def _allow_category(params: dict[str, Any]) -> bool:
    return isinstance(params.get("index"), int) and params.get("profile") in ("Private", "Public")


CHECK_DEF = Check(
    id="housekeeping",
    area=AREA,
    run=run,
    fixes=[FIX_CLEANUP, FIX_PRIVATE],
    allows=[
        Allow("firewall.remove_rule", _allow_remove),
        Allow("network.category", _allow_category),
    ],
)
