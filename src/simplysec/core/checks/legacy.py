"""Legacy protocols: SMBv1, LLMNR and NetBIOS over TCP/IP.

LLMNR and NetBIOS fixes are optional: very old printers, NAS boxes or PCs may rely on them.
"""

from __future__ import annotations

from typing import Any

from ..models import ActionSpec, InterfaceKind, Profile, Severity
from .base import (
    Allow,
    Check,
    FixDef,
    ScanContext,
    fact_unavailable,
    finding,
    reg_action,
    reg_allow,
)

AREA = "Legacy protocols"
DNSCLIENT = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"


def _build_smb1(params: dict[str, Any]) -> list[ActionSpec]:
    return [
        ActionSpec(
            "smb.server_setting",
            {"smb1": False},
            "Turn off the SMBv1 file-sharing server (Set-SmbServerConfiguration -EnableSMB1Protocol $false).",
        )
    ]


def _build_netbios(params: dict[str, Any]) -> list[ActionSpec]:
    return [
        ActionSpec(
            "netbios.adapter",
            {
                "config_index": int(a["config_index"]),
                "description": a.get("description", ""),
                "option": 2,
            },
            f"Turn off NetBIOS over TCP/IP on '{a.get('description', a['config_index'])}'.",
        )
        for a in params.get("adapters", [])
    ]


def _netbios_params(ctx: ScanContext) -> dict[str, Any] | None:
    adapters = _netbios_on(ctx)
    return {"adapters": adapters} if adapters else None


FIX_SMB1 = FixDef(
    id="legacy.smb1_off",
    label="Turn SMBv1 off",
    description="Turns off the 30-year-old SMB version 1 file-sharing server, used by the WannaCry worm.",
    might_break="Only very old devices (Windows XP, some old NAS boxes and scanners) used SMBv1 to reach this PC.",
    build=_build_smb1,
    recommended=True,
)
FIX_LLMNR = FixDef(
    id="legacy.llmnr_off",
    label="Turn LLMNR off",
    description="Sets the DNS Client policy EnableMulticast = 0 so Windows stops answering and sending LLMNR lookups.",
    might_break="Finding very old PCs by name without DNS may stop working; mDNS and DNS keep working.",
    build=lambda p: [
        reg_action(
            DNSCLIENT,
            "EnableMulticast",
            0,
            "REG_DWORD",
            "Turn off LLMNR (DNSClient policy EnableMulticast = 0).",
        )
    ],
    disruptive=True,
)
FIX_NETBIOS = FixDef(
    id="legacy.netbios_off",
    label="Turn NetBIOS off",
    description="Turns off NetBIOS over TCP/IP on each network adapter where it is on.",
    might_break="Very old devices that find PCs by NetBIOS name (old printers, NAS boxes, Windows XP) may not see this PC.",
    build=_build_netbios,
    disruptive=True,
    params_from=_netbios_params,
)


def _netbios_on(ctx: ScanContext) -> list[dict[str, Any]]:
    net = ctx.facts.get("network") or {}
    from ..util import as_list

    out = []
    for c in as_list(net.get("config")):
        if c.get("netbios") in (0, 1):  # 0 = default (on unless DHCP says otherwise), 1 = on
            out.append(
                {
                    "config_index": c.get("config_index"),
                    "description": c.get("description", ""),
                    "index": c.get("index"),
                    "setting": c.get("netbios"),
                }
            )
    return out


def _on_public(ctx: ScanContext) -> bool:
    return any(
        i.profile == Profile.PUBLIC and i.kind in (InterfaceKind.ETHERNET, InterfaceKind.WIFI)
        for i in ctx.active_interfaces()
    )


def run(ctx: ScanContext) -> list:
    out = []
    smb = ctx.facts.get("smb")
    if smb is None:
        f = fact_unavailable(ctx, "smb", "legacy", AREA, "the SMB file-sharing settings")
        if f:
            out.append(f)
    elif smb.get("smb1"):
        out.append(
            finding(
                id="legacy.smb1_on",
                check="legacy",
                area=AREA,
                title="The old SMBv1 file-sharing server is on",
                severity=Severity.HIGH,
                what=(
                    "SMB version 1 is the protocol the WannaCry and NotPetya worms spread through. "
                    "Modern devices use SMB 2 or 3."
                ),
                details=[("EnableSMB1Protocol", "True")],
                fixes=[FIX_SMB1.option()],
            )
        )

    llmnr = ctx.facts.get("llmnr")
    if llmnr is not None and llmnr.get("enable_multicast_policy") != 0:
        public = _on_public(ctx)
        out.append(
            finding(
                id="legacy.llmnr_on",
                check="legacy",
                area=AREA,
                title="LLMNR name lookups are on (optional fix)",
                severity=Severity.MEDIUM if public else Severity.LOW,
                what=(
                    "When a name can't be found in DNS, Windows shouts the question to the whole network. "
                    "An attacker on the same network can answer, pretend to be that PC and capture your "
                    "password hash. Risky on public Wi-Fi."
                ),
                details=[
                    ("DNSClient EnableMulticast policy", str(llmnr.get("enable_multicast_policy")))
                ],
                fixes=[FIX_LLMNR.option()],
                learn_more="Turning it off rarely affects home networks; very old devices may need it.",
            )
        )

    adapters = _netbios_on(ctx)
    if adapters:
        public = _on_public(ctx)
        out.append(
            finding(
                id="legacy.netbios_on",
                check="legacy",
                area=AREA,
                title=f"NetBIOS is on for {len(adapters)} network adapter(s) (optional fix)",
                severity=Severity.MEDIUM if public else Severity.LOW,
                what=(
                    "NetBIOS is an old way for Windows PCs to find each other. Like LLMNR it can be "
                    "abused on the same network to capture password hashes, and it reveals this PC's name."
                ),
                details=[
                    (
                        a["description"] or f"Adapter {a['config_index']}",
                        "default (from DHCP)" if a["setting"] == 0 else "on",
                    )
                    for a in adapters
                ],
                fixes=[FIX_NETBIOS.option({"adapters": adapters})],
            )
        )
    return out


def _allow_netbios(params: dict[str, Any]) -> bool:
    return isinstance(params.get("config_index"), int) and params.get("option") in (0, 1, 2)


CHECK_DEF = Check(
    id="legacy",
    area=AREA,
    run=run,
    fixes=[FIX_SMB1, FIX_LLMNR, FIX_NETBIOS],
    allows=[
        reg_allow((DNSCLIENT, "EnableMulticast")),
        Allow("smb.server_setting", lambda p: set(p) == {"smb1"} and isinstance(p["smb1"], bool)),
        Allow("netbios.adapter", _allow_netbios),
    ],
)
