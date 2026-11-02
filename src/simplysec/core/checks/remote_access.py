"""Remote Desktop, Network Level Authentication and Remote Assistance.

One code path for ``fDenyTSConnections`` (v1 set it to 0 in one place and 1 in another).
Remote Desktop is never turned off without the user picking that fix explicitly.
"""

from __future__ import annotations

from ..models import FindingStatus, Severity, Verdict
from ..scoring import WIDTH_LABELS, WIDTH_PUBLIC_SUBNET, exposure_severity, exposure_width
from .base import Check, FixDef, ScanContext, finding, reg_action, reg_allow

CHECK = "rdp"
AREA = "Remote access"

TS = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
RA = r"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance"

FIX_DISABLE = FixDef(
    id="rdp.disable",
    label="Turn Remote Desktop off",
    description="Sets fDenyTSConnections = 1 so this PC no longer accepts Remote Desktop logins.",
    might_break="You (or IT support) can no longer connect to this PC with Remote Desktop.",
    build=lambda p: [
        reg_action(
            TS,
            "fDenyTSConnections",
            1,
            "REG_DWORD",
            "Turn off Remote Desktop (fDenyTSConnections = 1).",
        )
    ],
    disruptive=True,
)
FIX_NLA = FixDef(
    id="rdp.require_nla",
    label="Require Network Level Authentication",
    description="Sets UserAuthentication = 1 so people must sign in before a Remote Desktop session starts.",
    might_break="Very old Remote Desktop clients (Windows XP era) can no longer connect.",
    build=lambda p: [
        reg_action(
            RDP_TCP,
            "UserAuthentication",
            1,
            "REG_DWORD",
            "Require Network Level Authentication for Remote Desktop (UserAuthentication = 1).",
        )
    ],
    recommended=True,
)
FIX_RA = FixDef(
    id="rdp.remote_assistance_off",
    label="Turn Remote Assistance off",
    description="Sets fAllowToGetHelp = 0 so this PC no longer accepts Remote Assistance invitations.",
    might_break="Someone helping you via Windows Remote Assistance (not Quick Assist) can no longer connect.",
    build=lambda p: [
        reg_action(
            RA,
            "fAllowToGetHelp",
            0,
            "REG_DWORD",
            "Turn off Remote Assistance (fAllowToGetHelp = 0).",
        )
    ],
    recommended=True,
)
ALLOWS = [
    reg_allow((TS, "fDenyTSConnections"), (RDP_TCP, "UserAuthentication"), (RA, "fAllowToGetHelp"))
]


def run(ctx: ScanContext) -> list:
    rdp = ctx.facts.get("rdp")
    if rdp is None:
        from .base import fact_unavailable

        f = fact_unavailable(ctx, "rdp", CHECK, AREA, "Remote Desktop settings")
        return [f] if f else []
    out = []
    deny = rdp.get("deny_policy") if rdp.get("deny_policy") is not None else rdp.get("deny")
    enabled = deny == 0
    policy_rdp = rdp.get("deny_policy") is not None
    port = int(rdp.get("port") or 3389)
    groups = [g for g in ctx.groups if g.protocol == "tcp" and g.port == port]
    exposures = [e for g in groups for e in g.exposures]
    reachable = any(e.verdict == Verdict.REACHABLE for e in exposures)

    if enabled:
        width = exposure_width(exposures)
        if reachable:
            sev = exposure_severity(Severity.HIGH, width)
            title = f"Remote Desktop is on and can be reached by {WIDTH_LABELS[width]}"
            what = (
                "Anyone who can reach this PC can try to log in with Remote Desktop. It is one of the "
                "most attacked services; keep it off unless you use it."
            )
        else:
            sev = Severity.LOW
            title = "Remote Desktop is on (currently blocked by the firewall)"
            what = "Remote Desktop accepts logins, but the firewall stops other devices reaching it right now."
        fixes = [FIX_DISABLE.option()]
        if reachable:
            opt = ctx.fix_option(
                "exposure.block_port_public",
                {"protocol": "tcp", "port": port, "label": "Remote Desktop"},
            )
            if opt and width >= WIDTH_PUBLIC_SUBNET:
                fixes.append(opt)
        f = finding(
            id="rdp.enabled",
            check=CHECK,
            area=AREA,
            title=title,
            severity=sev,
            what=what,
            details=[("fDenyTSConnections", str(deny)), ("Port", str(port))]
            + [(f"via {ie.interface}", ie.reason) for e in exposures for ie in e.per_interface],
            fixes=fixes,
        )
        if policy_rdp:
            f.status = FindingStatus.MANAGED
        out.append(f)

        nla = rdp.get("nla_policy") if rdp.get("nla_policy") is not None else rdp.get("nla")
        if nla == 0:
            f = finding(
                id="rdp.nla_off",
                check=CHECK,
                area=AREA,
                title="Remote Desktop does not require sign-in first (NLA is off)",
                severity=Severity.HIGH,
                what=(
                    "Without Network Level Authentication, anyone can open a login screen on this PC and "
                    "attackers can exploit Remote Desktop bugs before signing in."
                ),
                details=[("UserAuthentication", str(nla))],
                fixes=[FIX_NLA.option()],
            )
            if rdp.get("nla_policy") is not None:
                f.status = FindingStatus.MANAGED
            out.append(f)

    ra = rdp.get("remote_assistance_policy")
    ra_policy = ra is not None
    if ra is None:
        ra = rdp.get("remote_assistance")
    if ra == 1:
        f = finding(
            id="rdp.remote_assistance_on",
            check=CHECK,
            area=AREA,
            title="Remote Assistance is on",
            severity=Severity.LOW,
            what=(
                "Remote Assistance lets someone you send an invitation to see and control your screen. "
                "Scammers often talk people into this. Quick Assist still works if you turn it off."
            ),
            details=[("fAllowToGetHelp", "1")],
            fixes=[FIX_RA.option()],
        )
        if ra_policy:
            f.status = FindingStatus.MANAGED
        out.append(f)
    return out


CHECK_DEF = Check(id=CHECK, area=AREA, run=run, fixes=[FIX_DISABLE, FIX_NLA, FIX_RA], allows=ALLOWS)
