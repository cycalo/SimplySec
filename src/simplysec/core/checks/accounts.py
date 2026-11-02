"""Accounts: UAC prompts, the Guest account, blank-password network logons."""

from __future__ import annotations

from typing import Any

from ..models import ActionSpec, Severity
from ..util import as_list
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

AREA = "Accounts"
POL_SYS = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"


def _build_uac(params: dict[str, Any]) -> list[ActionSpec]:
    out = []
    if params.get("enable_lua"):
        out.append(
            reg_action(
                POL_SYS,
                "EnableLUA",
                1,
                "REG_DWORD",
                "Turn User Account Control on (EnableLUA = 1, takes effect after a restart).",
            )
        )
    if params.get("consent"):
        out.append(
            reg_action(
                POL_SYS,
                "ConsentPromptBehaviorAdmin",
                5,
                "REG_DWORD",
                "Ask for consent before programs get administrator rights (ConsentPromptBehaviorAdmin = 5, the Windows default).",
            )
        )
    return out


FIX_UAC = FixDef(
    id="accounts.uac_prompt",
    label="Turn UAC prompts back on",
    description="Restores the Windows default: programs must ask before getting administrator rights.",
    might_break="You'll see a prompt when a program needs administrator rights.",
    build=_build_uac,
    recommended=True,
)
FIX_GUEST = FixDef(
    id="accounts.guest_off",
    label="Disable the Guest account",
    description="Disables the built-in Guest account (found by its fixed ID, RID 501).",
    might_break="Nobody can sign in as Guest, locally or over the network.",
    build=lambda p: [
        ActionSpec(
            "account.enabled", {"rid": 501, "enabled": False}, "Disable the built-in Guest account."
        )
    ],
    recommended=True,
)
FIX_BLANK = FixDef(
    id="accounts.blank_password_limit",
    label="Block network logons with blank passwords",
    description="Sets LimitBlankPasswordUse = 1 (the Windows default): accounts without a password can only sign in at the keyboard.",
    might_break="Accounts with no password can't be used to open shared folders from other PCs.",
    build=lambda p: [
        reg_action(
            LSA,
            "LimitBlankPasswordUse",
            1,
            "REG_DWORD",
            "Block network logons for accounts with blank passwords (LimitBlankPasswordUse = 1).",
        )
    ],
    recommended=True,
)


def run(ctx: ScanContext) -> list:
    out = []
    uac = ctx.facts.get("uac")
    if uac is None:
        f = fact_unavailable(ctx, "uac", "accounts", AREA, "User Account Control")
        if f:
            out.append(f)
    else:
        lua_off = uac.get("enable_lua") == 0
        no_prompt = uac.get("consent_admin") == 0
        if lua_off or no_prompt:
            out.append(
                finding(
                    id="accounts.uac_off",
                    check="accounts",
                    area=AREA,
                    title="User Account Control is off"
                    if lua_off
                    else "Programs get administrator rights without asking",
                    severity=Severity.HIGH,
                    what=(
                        "User Account Control makes programs ask before they change system settings. "
                        "Without it, any program you run, including malware, gets full control silently."
                    ),
                    details=[
                        ("EnableLUA", str(uac.get("enable_lua"))),
                        ("ConsentPromptBehaviorAdmin", str(uac.get("consent_admin"))),
                    ],
                    fixes=[FIX_UAC.option({"enable_lua": lua_off, "consent": no_prompt})],
                )
            )

    acc = ctx.facts.get("accounts")
    if acc is None:
        f = fact_unavailable(ctx, "accounts", "accounts", AREA, "local accounts")
        if f:
            out.append(f)
        return out
    users = as_list(acc.get("users"))
    guest = next((u for u in users if str(u.get("sid", "")).endswith("-501")), None)
    if guest and guest.get("enabled"):
        out.append(
            finding(
                id="accounts.guest_on",
                check="accounts",
                area=AREA,
                title="The Guest account is enabled",
                severity=Severity.HIGH,
                what="The Guest account needs no password. Anyone can use it to sign in, also over the network.",
                details=[("Account", guest.get("name", "Guest"))],
                fixes=[FIX_GUEST.option()],
            )
        )
    if acc.get("limit_blank_password_use") == 0:
        blank = [
            u.get("name") for u in users if u.get("enabled") and u.get("password_required") is False
        ]
        out.append(
            finding(
                id="accounts.blank_passwords",
                check="accounts",
                area=AREA,
                title="Accounts with no password can sign in over the network",
                severity=Severity.HIGH,
                what="Windows normally only lets password-less accounts sign in at the keyboard. This PC allows it over the network too.",
                details=[("LimitBlankPasswordUse", "0")]
                + ([("Accounts without a required password", ", ".join(blank))] if blank else []),
                fixes=[FIX_BLANK.option()],
            )
        )
    return out


CHECK_DEF = Check(
    id="accounts",
    area=AREA,
    run=run,
    fixes=[FIX_UAC, FIX_GUEST, FIX_BLANK],
    allows=[
        reg_allow(
            (POL_SYS, "EnableLUA"),
            (POL_SYS, "ConsentPromptBehaviorAdmin"),
            (LSA, "LimitBlankPasswordUse"),
        ),
        Allow("account.enabled", lambda p: p.get("rid") == 501 and p.get("enabled") is False),
    ],
)
