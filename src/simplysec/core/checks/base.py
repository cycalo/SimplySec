"""Framework shared by all check modules.

A check module provides:

* ``run(ctx) -> list[Finding]``: detection plus plain-language text;
* ``FIXES``: the fixes it offers, each building a list of reversible ``ActionSpec``;
* ``ALLOWS``: allow-list predicates. Apply and undo refuse any action that no check module
  allows, so a tampered journal cannot be replayed into arbitrary changes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..knowledge import KnowledgeBase
from ..models import (
    ActionSpec,
    Exposure,
    Finding,
    FirewallState,
    FixOption,
    InterfaceKind,
    Listener,
    NetInterface,
    Profile,
    Severity,
)


class Facts:
    """facts.ps1 output with explicit status per item (ok / needs_admin / error / missing)."""

    def __init__(self, data: dict[str, Any] | None) -> None:
        self.data = data or {}

    def status(self, name: str) -> str:
        item = self.data.get(name)
        if not isinstance(item, dict):
            return "missing"
        return str(item.get("status", "missing"))

    def get(self, name: str) -> Any:
        item = self.data.get(name)
        if isinstance(item, dict) and item.get("status") == "ok":
            return item.get("value")
        return None

    def error(self, name: str) -> str:
        item = self.data.get(name)
        return str(item.get("error", "")) if isinstance(item, dict) else ""

    def to_dict(self) -> dict[str, Any]:
        return self.data


@dataclass
class SignatureInfo:
    status: str
    publisher: str = ""

    @property
    def signed(self) -> bool:
        return self.status == "Valid"


@dataclass
class PortGroup:
    """All listeners of one program on one protocol/port, with the combined exposure."""

    protocol: str
    port: int
    pid: int
    process: str
    exe: str
    services: list[str] | None
    exposures: list[Exposure]

    @property
    def listeners(self) -> list[Listener]:
        return [e.listener for e in self.exposures]

    @property
    def addresses(self) -> list[str]:
        return [e.listener.address for e in self.exposures]


@dataclass
class ScanContext:
    facts: Facts
    listeners: list[Listener]
    exposures: list[Exposure]
    groups: list[PortGroup]
    interfaces: list[NetInterface]
    firewall: FirewallState
    kb: KnowledgeBase
    signatures: dict[str, SignatureInfo] = field(default_factory=dict)
    is_admin: bool = False
    env: dict[str, str] = field(default_factory=dict)  # user + machine environment (for intent)
    accepted: dict[str, int] = field(default_factory=dict)  # keep_key -> accepted width
    windows_dir: str = r"C:\Windows"
    file_exists: Callable[[str], bool] = field(default=lambda _path: True)

    def fix_option(self, fix_id: str, params: dict[str, Any] | None = None) -> FixOption | None:
        """A FixOption for any registered fix, with parameters derived from this scan."""
        from . import FIXES

        fix = FIXES.get(fix_id)
        if fix is None:
            return None
        if params is None and fix.params_from is not None:
            params = fix.params_from(self)
            if params is None:
                return None
        return fix.option(params)

    @property
    def managed(self) -> bool:
        system = self.facts.get("system") or {}
        return bool(system.get("part_of_domain")) or self.firewall.managed_by_policy

    def active_interfaces(self) -> list[NetInterface]:
        return [
            i
            for i in self.interfaces
            if i.up and i.kind not in (InterfaceKind.LOOPBACK,) and i.ip_interfaces()
        ]

    def current_public_networks(self) -> list[NetInterface]:
        """Physical networks (Ethernet / Wi-Fi) Windows currently treats as Public."""
        return [
            i
            for i in self.active_interfaces()
            if i.kind in (InterfaceKind.ETHERNET, InterfaceKind.WIFI)
            and i.profile == Profile.PUBLIC
        ]

    def signature(self, exe: str) -> SignatureInfo | None:
        return self.signatures.get((exe or "").lower())

    def is_windows_binary(self, exe: str) -> bool:
        return bool(exe) and exe.lower().startswith(self.windows_dir.lower().rstrip("\\") + "\\")


# --------------------------------------------------------------------------- fixes


@dataclass
class Warning_:
    text: str
    offer_fix: str | None = None  # a fix id the preview offers to add first
    offer_params: dict[str, Any] = field(default_factory=dict)
    offer_label: str = ""


@dataclass
class FixDef:
    id: str
    label: str
    description: str  # what changes, in plain words
    might_break: str  # "what might stop working"
    build: Callable[[dict[str, Any]], list[ActionSpec]] | None = None
    disruptive: bool = False
    recommended: bool = False
    guidance: str | None = None  # settings page to open instead of changing anything
    warnings: Callable[[ScanContext, dict[str, Any]], list[Warning_]] | None = None
    params_from: Callable[[ScanContext], dict[str, Any] | None] | None = None

    def option(self, params: dict[str, Any] | None = None, label: str | None = None) -> FixOption:
        return FixOption(
            fix_id=self.id,
            label=label or self.label,
            params=params or {},
            disruptive=self.disruptive,
            recommended=self.recommended,
            guidance_only=self.guidance is not None,
        )


@dataclass
class Allow:
    kind: str
    predicate: Callable[[dict[str, Any]], bool]


@dataclass
class Check:
    id: str
    area: str
    run: Callable[[ScanContext], list[Finding]]
    fixes: list[FixDef] = field(default_factory=list)
    allows: list[Allow] = field(default_factory=list)


# --------------------------------------------------------------------------- helpers


def reg_allow(*pairs: tuple[str, str]) -> Allow:
    """Allow ``registry.value`` changes to exactly these (path, name) pairs."""
    allowed = {(p.lower(), n.lower()) for p, n in pairs}
    return Allow(
        "registry.value",
        lambda params: (
            (str(params.get("path", "")).lower(), str(params.get("name", "")).lower()) in allowed
        ),
    )


def reg_action(path: str, name: str, value: Any, vtype: str, summary: str) -> ActionSpec:
    return ActionSpec(
        "registry.value", {"path": path, "name": name, "value": value, "type": vtype}, summary
    )


def finding(
    *,
    id: str,
    check: str,
    area: str,
    title: str,
    severity: Severity,
    what: str,
    details: list[tuple[str, str]] | None = None,
    fixes: list[FixOption] | None = None,
    learn_more: str = "",
) -> Finding:
    return Finding(
        id=id,
        check=check,
        area=area,
        title=title,
        severity=severity,
        what_it_means=what,
        details=details or [],
        fixes=fixes or [],
        learn_more=learn_more,
    )


def fact_unavailable(
    ctx: ScanContext, name: str, check: str, area: str, what: str
) -> Finding | None:
    """An Info finding when a fact could not be read, so 'unknown' never looks like 'safe'."""
    status = ctx.facts.status(name)
    if status == "ok":
        return None
    reason = {
        "needs_admin": "SimplySec needs administrator rights to read this.",
        "missing": "This information was not collected.",
    }.get(status, f"Windows reported an error: {ctx.facts.error(name)[:200]}")
    return finding(
        id=f"{check}.unavailable.{name}",
        check=check,
        area=area,
        title=f"Could not check {what}",
        severity=Severity.INFO,
        what=f"{reason} This is reported as unknown, not as safe.",
    )
