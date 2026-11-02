"""Firewall profiles: on/off and the default action for incoming connections."""

from __future__ import annotations

from typing import Any

from ..models import ActionSpec, FindingStatus, Profile, Severity
from .base import Allow, Check, FixDef, ScanContext, finding

CHECK = "firewall"
AREA = "Firewall"


def _build_enable(params: dict[str, Any]) -> list[ActionSpec]:
    prof = Profile(int(params["profile"]))
    return [
        ActionSpec(
            "firewall.profile",
            {"profile": int(prof), "enabled": True},
            f"Turn the Windows firewall on for {prof.label} networks.",
        )
    ]


def _build_block(params: dict[str, Any]) -> list[ActionSpec]:
    prof = Profile(int(params["profile"]))
    return [
        ActionSpec(
            "firewall.profile",
            {"profile": int(prof), "default_inbound_block": True},
            f"Set the firewall to block incoming connections by default on {prof.label} networks.",
        )
    ]


FIX_ENABLE = FixDef(
    id="firewall.enable",
    label="Turn the firewall on",
    description="Turns Windows Defender Firewall on for this network type.",
    might_break="Programs that relied on the firewall being off may ask for permission the next time they accept connections.",
    build=_build_enable,
    recommended=True,
)
FIX_DEFAULT_BLOCK = FixDef(
    id="firewall.default_block",
    label="Block incoming connections by default",
    description="Only programs with an allow rule can accept connections (the Windows default).",
    might_break="Programs without an allow rule stop accepting connections from other devices.",
    build=_build_block,
    disruptive=True,
)


def _allow_profile(params: dict[str, Any]) -> bool:
    keys = set(params) - {"profile"}
    return (
        int(params.get("profile", 0)) in (1, 2, 4)
        and bool(keys)
        and keys <= {"enabled", "default_inbound_block"}
        and all(isinstance(params[k], bool) for k in keys)
    )


def run(ctx: ScanContext) -> list:
    out = []
    managed = ctx.firewall.managed_by_policy
    for prof, state in ctx.firewall.profiles.items():
        in_use = bool(ctx.firewall.current_profiles & prof)
        where = "the network you are on now" if in_use else f"{prof.label} networks"
        if not state.enabled:
            f = finding(
                id=f"firewall.off.{str(prof.name).lower()}",
                check=CHECK,
                area=AREA,
                title=f"The firewall is off for {prof.label} networks",
                severity=Severity.CRITICAL if (in_use or prof == Profile.PUBLIC) else Severity.HIGH,
                what=(
                    f"Without the firewall, any device on {where} can connect to every program that "
                    "listens on this PC."
                ),
                details=[("Profile", prof.label), ("In use now", "yes" if in_use else "no")],
                fixes=[FIX_ENABLE.option({"profile": int(prof)})],
            )
            if managed:
                f.status = FindingStatus.MANAGED
            out.append(f)
        elif not state.default_inbound_block:
            f = finding(
                id=f"firewall.default_allow.{str(prof.name).lower()}",
                check=CHECK,
                area=AREA,
                title=f"The firewall lets in all connections by default on {prof.label} networks",
                severity=Severity.HIGH if (in_use or prof == Profile.PUBLIC) else Severity.MEDIUM,
                what=(
                    "The firewall is on, but anything not explicitly blocked is allowed in. Windows "
                    "normally blocks by default and only lets in programs you approved."
                ),
                details=[("Profile", prof.label), ("Default inbound action", "Allow")],
                fixes=[FIX_DEFAULT_BLOCK.option({"profile": int(prof)})],
            )
            if managed:
                f.status = FindingStatus.MANAGED
            out.append(f)
        elif state.block_all_inbound:
            continue
    return out


CHECK_DEF = Check(
    id=CHECK,
    area=AREA,
    run=run,
    fixes=[FIX_ENABLE, FIX_DEFAULT_BLOCK],
    allows=[Allow("firewall.profile", _allow_profile)],
)
