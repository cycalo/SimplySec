"""All check modules, the fix registry and the action allow-lists."""

from __future__ import annotations

from typing import Any

from ..models import ActionSpec
from . import (
    accounts,
    exposure,
    firewall,
    housekeeping,
    legacy,
    malware,
    remote_access,
    sharing,
    system,
    updates,
    wifi,
)
from .base import Allow, Check, FixDef

CHECKS: list[Check] = [
    firewall.CHECK_DEF,
    exposure.CHECK_DEF,
    remote_access.CHECK_DEF,
    legacy.CHECK_DEF,
    sharing.CHECK_DEF,
    malware.CHECK_DEF,
    updates.CHECK_DEF,
    accounts.CHECK_DEF,
    system.CHECK_DEF,
    wifi.CHECK_DEF,
    housekeeping.CHECK_DEF,
]

FIXES: dict[str, FixDef] = {}
for _check in CHECKS:
    for _fix in _check.fixes:
        if _fix.id in FIXES:
            raise RuntimeError(f"duplicate fix id {_fix.id}")
        FIXES[_fix.id] = _fix

# Kinds that are always allowed with any well-formed parameters (scheduled task is created by
# the Settings page, not by a check).
EXTRA_ALLOWS: list[Allow] = [
    Allow(
        "task.schedule",
        lambda p: p.get("name") == r"\SimplySec\Daily check" and isinstance(p.get("time"), str),
    ),
]


def allows() -> list[Allow]:
    out = list(EXTRA_ALLOWS)
    for check in CHECKS:
        out.extend(check.allows)
    return out


def is_allowed(kind: str, params: dict[str, Any]) -> bool:
    """True if some check module declares this exact kind and parameters as allowed."""
    for allow in allows():
        if allow.kind != kind:
            continue
        try:
            if allow.predicate(params):
                return True
        except (KeyError, TypeError, ValueError):
            continue
    return False


def register_check(check: Check) -> None:
    """Used by M2 modules (Wi-Fi etc.) that live outside this package."""
    if any(c.id == check.id for c in CHECKS):
        return
    CHECKS.append(check)
    for fix in check.fixes:
        FIXES[fix.id] = fix


def spec_allowed(spec: ActionSpec) -> bool:
    return is_allowed(spec.kind, spec.params)
