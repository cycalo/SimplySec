"""System hardening: AutoRun and BitLocker drive encryption."""

from __future__ import annotations

from ..models import Severity
from .base import Check, FixDef, ScanContext, fact_unavailable, finding, reg_action, reg_allow

AREA = "System"
EXPLORER = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
LAPTOP_CHASSIS = {8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32}

FIX_AUTORUN = FixDef(
    id="system.autorun_off",
    label="Turn AutoRun off for all drives",
    description="Sets NoDriveTypeAutoRun = 255 so USB sticks and discs can't start programs automatically.",
    might_break="Discs and USB sticks no longer start their installers by themselves; open them in File Explorer instead.",
    build=lambda p: [
        reg_action(
            EXPLORER,
            "NoDriveTypeAutoRun",
            255,
            "REG_DWORD",
            "Turn off AutoRun for all drive types (NoDriveTypeAutoRun = 255).",
        )
    ],
)
FIX_BITLOCKER = FixDef(
    id="system.bitlocker_guide",
    label="Open device encryption settings",
    description="Opens Settings so you can turn on BitLocker / device encryption. Save the recovery key somewhere safe first.",
    might_break="Nothing changes until you turn encryption on.",
    guidance="bitlocker",
)

BITLOCKER_STATES = {
    1: "on",
    2: "off",
    3: "encrypting",
    4: "decrypting",
    5: "suspended",
    6: "on (locked)",
    8: "waiting for activation",
}


def run(ctx: ScanContext) -> list:
    out = []
    autorun = ctx.facts.get("autorun")
    if (
        autorun is not None
        and autorun.get("hklm") != 255
        and autorun.get("hkcu") != 255
        and autorun.get("no_autorun_hklm") != 1
    ):
        out.append(
            finding(
                id="system.autorun",
                check="system",
                area=AREA,
                title="AutoRun is not fully turned off",
                severity=Severity.LOW,
                what=(
                    "AutoRun lets a disc or USB drive start a program when inserted. Modern Windows limits "
                    "it, but the recommended setting turns it off for every drive type."
                ),
                details=[("NoDriveTypeAutoRun (HKLM)", str(autorun.get("hklm")))],
                fixes=[FIX_AUTORUN.option()],
            )
        )

    bl = ctx.facts.get("bitlocker")
    if bl is None:
        f = fact_unavailable(ctx, "bitlocker", "system", AREA, "drive encryption")
        if f:
            out.append(f)
        return out
    state = bl.get("protection")
    system = ctx.facts.get("system") or {}
    laptop = bool(system.get("has_battery")) or bool(
        set(system.get("chassis") or []) & LAPTOP_CHASSIS
    )
    if state in (2, 5, 8):
        sev = Severity.HIGH if laptop else Severity.LOW
        out.append(
            finding(
                id="system.bitlocker_off",
                check="system",
                area=AREA,
                title=f"Drive {bl.get('drive', 'C:')} is not encrypted"
                + (" (protection suspended)" if state == 5 else ""),
                severity=sev,
                what=(
                    "If this PC is lost or stolen, anyone can read its files by removing the drive. "
                    + (
                        "Laptops are lost far more often, so this matters more here."
                        if laptop
                        else "On a desktop at home this is less urgent."
                    )
                ),
                details=[
                    ("BitLocker", BITLOCKER_STATES.get(state, str(state))),
                    ("Device", "laptop" if laptop else "desktop"),
                ],
                fixes=[FIX_BITLOCKER.option()],
                learn_more="BitLocker needs Windows Pro; Windows Home offers 'Device encryption' on supported hardware.",
            )
        )
    return out


CHECK_DEF = Check(
    id="system",
    area=AREA,
    run=run,
    fixes=[FIX_AUTORUN, FIX_BITLOCKER],
    allows=[reg_allow((EXPLORER, "NoDriveTypeAutoRun"))],
)
