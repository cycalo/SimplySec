"""Reversible primitives. Every change SimplySec makes is one of these.

Each primitive can ``snapshot`` the before-state, ``apply`` the change, ``verify`` it by
reading the real state back, and ``revert`` to the stored before-state. All OS access goes
through an ``Adapters`` bundle so tests can use fakes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .models import FirewallRule, Profile

# Services SimplySec may ever change the start type of. Nothing on the knowledge base's
# never-touch list can be added here (enforced in tests).
SERVICE_ALLOWLIST = {
    "remoteregistry",
    "tlntsvr",
    "ftpsvc",
    "snmp",
    "ssdpsrv",
    "upnphost",
    "lmhosts",
}


class ActionError(RuntimeError):
    pass


@dataclass
class Adapters:
    """The OS-facing modules (or fakes with the same functions)."""

    firewall: Any
    registry: Any
    services: Any
    network: Any
    system: Any
    accounts: Any
    wifi: Any = None
    scheduler: Any = None

    @classmethod
    def real(cls) -> Adapters:
        import importlib

        from ..windows import accounts, firewall, network, registry, services, system

        def optional(name: str) -> Any:
            try:
                return importlib.import_module(f"simplysec.windows.{name}")
            except ImportError:  # pragma: no cover - added by later milestones
                return None

        return cls(
            firewall,
            registry,
            services,
            network,
            system,
            accounts,
            optional("wifi"),
            optional("scheduler"),
        )


@dataclass
class Primitive:
    kind: str
    snapshot: Callable[[Adapters, dict[str, Any]], dict[str, Any]]
    apply: Callable[[Adapters, dict[str, Any], dict[str, Any]], None]
    verify: Callable[[Adapters, dict[str, Any]], bool]
    revert: Callable[[Adapters, dict[str, Any], dict[str, Any]], None]
    verify_reverted: Callable[[Adapters, dict[str, Any], dict[str, Any]], bool]
    before_ok: Callable[[dict[str, Any], dict[str, Any]], bool] = lambda params, before: True


# --------------------------------------------------------------------------- firewall


def _fw_add_snapshot(a: Adapters, p: dict[str, Any]) -> dict[str, Any]:
    existing = a.firewall.find_rules(p["rule"]["name"])
    if existing:
        raise ActionError(f"a rule named {p['rule']['name']!r} already exists")
    return {"existed": 0}


def _fw_add_verify(a: Adapters, p: dict[str, Any]) -> bool:
    rules = a.firewall.find_rules(p["rule"]["name"])
    want = p["rule"]
    return (
        len(rules) == 1
        and rules[0].enabled
        and rules[0].action == want["action"]
        and rules[0].direction == want["direction"]
    )


FW_ADD = Primitive(
    kind="firewall.add_rule",
    snapshot=_fw_add_snapshot,
    apply=lambda a, p, b: a.firewall.add_rule(FirewallRule.from_dict(p["rule"])),
    verify=_fw_add_verify,
    revert=lambda a, p, b: a.firewall.remove_rules_named(p["rule"]["name"]),
    verify_reverted=lambda a, p, b: not a.firewall.find_rules(p["rule"]["name"]),
    before_ok=lambda p, b: b == {"existed": 0},
)


def _fw_remove_revert(a: Adapters, p: dict[str, Any], b: dict[str, Any]) -> None:
    for d in b.get("rules", []):
        a.firewall.add_rule(FirewallRule.from_dict(d))


FW_REMOVE = Primitive(
    kind="firewall.remove_rule",
    snapshot=lambda a, p: {"rules": [r.to_dict() for r in a.firewall.find_rules(p["name"])]},
    apply=lambda a, p, b: a.firewall.remove_rules_named(p["name"]),
    verify=lambda a, p: not a.firewall.find_rules(p["name"]),
    revert=_fw_remove_revert,
    verify_reverted=lambda a, p, b: (
        len(a.firewall.find_rules(p["name"])) == len(b.get("rules", []))
    ),
    # Undo may only recreate rules with the very name that was removed.
    before_ok=lambda p, b: all(d.get("name") == p["name"] for d in b.get("rules", [])),
)


def _profile_keys(p: dict[str, Any]) -> list[str]:
    return [k for k in ("enabled", "default_inbound_block") if k in p]


def _fw_profile_snapshot(a: Adapters, p: dict[str, Any]) -> dict[str, Any]:
    st = a.firewall.read_profile(Profile(int(p["profile"])))
    return {"enabled": st.enabled, "default_inbound_block": st.default_inbound_block}


def _fw_profile_apply(a: Adapters, p: dict[str, Any], b: dict[str, Any]) -> None:
    a.firewall.set_profile(Profile(int(p["profile"])), **{k: p[k] for k in _profile_keys(p)})


def _fw_profile_verify(a: Adapters, p: dict[str, Any]) -> bool:
    now = _fw_profile_snapshot(a, p)
    return all(now[k] == p[k] for k in _profile_keys(p))


def _fw_profile_revert(a: Adapters, p: dict[str, Any], b: dict[str, Any]) -> None:
    a.firewall.set_profile(Profile(int(p["profile"])), **{k: b[k] for k in _profile_keys(p)})


FW_PROFILE = Primitive(
    kind="firewall.profile",
    snapshot=_fw_profile_snapshot,
    apply=_fw_profile_apply,
    verify=_fw_profile_verify,
    revert=_fw_profile_revert,
    verify_reverted=lambda a, p, b: all(
        _fw_profile_snapshot(a, p)[k] == b[k] for k in _profile_keys(p)
    ),
    before_ok=lambda p, b: all(isinstance(b.get(k), bool) for k in _profile_keys(p)),
)


# --------------------------------------------------------------------------- registry


def _reg_snapshot(a: Adapters, p: dict[str, Any]) -> dict[str, Any]:
    return a.registry.read(p["path"], p["name"]).to_dict()


def _reg_verify(a: Adapters, p: dict[str, Any]) -> bool:
    snap = a.registry.read(p["path"], p["name"])
    return bool(snap.exists and snap.value == p["value"] and snap.type == p["type"])


def _reg_revert(a: Adapters, p: dict[str, Any], b: dict[str, Any]) -> None:
    a.registry.restore(p["path"], p["name"], b)


def _reg_verify_reverted(a: Adapters, p: dict[str, Any], b: dict[str, Any]) -> bool:
    snap = a.registry.read(p["path"], p["name"])
    if not b["exists"]:
        return not snap.exists
    return bool(snap.exists and snap.value == b["value"])


def _reg_before_ok(p: dict[str, Any], b: dict[str, Any]) -> bool:
    if set(b) != {"key_existed", "exists", "type", "value"}:
        return False
    if b["exists"]:
        # Restoring may only write the same kind of value the fix itself writes.
        return b["type"] == p["type"] and isinstance(b["value"], type(p["value"]))
    return True


REG_VALUE = Primitive(
    kind="registry.value",
    snapshot=_reg_snapshot,
    apply=lambda a, p, b: a.registry.write(p["path"], p["name"], p["value"], p["type"]),
    verify=_reg_verify,
    revert=_reg_revert,
    verify_reverted=_reg_verify_reverted,
    before_ok=_reg_before_ok,
)


# --------------------------------------------------------------------------- services


def _svc_apply(a: Adapters, p: dict[str, Any], b: dict[str, Any]) -> None:
    a.services.set_start_type(p["name"], p["start_type"])
    if p["start_type"] == "disabled" and b.get("running"):
        a.services.stop(p["name"])


def _svc_revert(a: Adapters, p: dict[str, Any], b: dict[str, Any]) -> None:
    a.services.set_start_type(p["name"], b["start_type"], b.get("delayed", False))
    if b.get("running") and not a.services.get(p["name"]).running:
        a.services.start(p["name"])


SERVICE = Primitive(
    kind="service.start_type",
    snapshot=lambda a, p: a.services.get(p["name"]).to_dict(),
    apply=_svc_apply,
    verify=lambda a, p: a.services.get(p["name"]).start_type == p["start_type"],
    revert=_svc_revert,
    verify_reverted=lambda a, p, b: a.services.get(p["name"]).start_type == b["start_type"],
    before_ok=lambda p, b: (
        b.get("start_type") in ("auto", "manual", "disabled") and b.get("name") == p["name"]
    ),
)


# --------------------------------------------------------------------------- network


def _cat_name(profile: Profile | None) -> str | None:
    return {Profile.PRIVATE: "Private", Profile.PUBLIC: "Public"}.get(profile) if profile else None


NET_CATEGORY = Primitive(
    kind="network.category",
    snapshot=lambda a, p: {"profile": _cat_name(a.network.get_category(int(p["index"])))},
    apply=lambda a, p, b: a.network.set_category(int(p["index"]), Profile[p["profile"].upper()]),
    verify=lambda a, p: _cat_name(a.network.get_category(int(p["index"]))) == p["profile"],
    revert=lambda a, p, b: a.network.set_category(int(p["index"]), Profile[b["profile"].upper()]),
    verify_reverted=lambda a, p, b: (
        _cat_name(a.network.get_category(int(p["index"]))) == b["profile"]
    ),
    before_ok=lambda p, b: b.get("profile") in ("Private", "Public"),
)

WIFI_MODE = Primitive(
    kind="wifi.connection_mode",
    snapshot=lambda a, p: {"mode": a.wifi.get_connection_mode(p["profile_name"])},
    apply=lambda a, p, b: a.wifi.set_connection_mode(p["profile_name"], p["mode"]),
    verify=lambda a, p: a.wifi.get_connection_mode(p["profile_name"]) == p["mode"],
    revert=lambda a, p, b: a.wifi.set_connection_mode(p["profile_name"], b["mode"]),
    verify_reverted=lambda a, p, b: a.wifi.get_connection_mode(p["profile_name"]) == b["mode"],
    before_ok=lambda p, b: b.get("mode") in ("auto", "manual"),
)

TASK = Primitive(
    kind="task.schedule",
    snapshot=lambda a, p: {"xml": a.scheduler.export_xml(p["name"])},
    apply=lambda a, p, b: a.scheduler.create(p["name"], p["time"]),
    verify=lambda a, p: a.scheduler.exists(p["name"]),
    revert=lambda a, p, b: a.scheduler.restore(p["name"], b.get("xml")),
    verify_reverted=lambda a, p, b: a.scheduler.exists(p["name"]) == bool(b.get("xml")),
    before_ok=lambda p, b: b.get("xml") is None or "SimplySec" in str(b.get("xml")),
)


# --------------------------------------------------------------------------- specific setters

SMB = Primitive(
    kind="smb.server_setting",
    snapshot=lambda a, p: {"smb1": bool(a.system.smb_server_get()["smb1"])},
    apply=lambda a, p, b: a.system.smb_server_set(p["smb1"]),
    verify=lambda a, p: bool(a.system.smb_server_get()["smb1"]) == p["smb1"],
    revert=lambda a, p, b: a.system.smb_server_set(b["smb1"]),
    verify_reverted=lambda a, p, b: bool(a.system.smb_server_get()["smb1"]) == b["smb1"],
    before_ok=lambda p, b: isinstance(b.get("smb1"), bool),
)

DEFENDER_PREF = Primitive(
    kind="defender.pref",
    snapshot=lambda a, p: {
        "controlled_folder_access": int(a.system.defender_get()["controlled_folder_access"])
    },
    apply=lambda a, p, b: a.system.defender_set_cfa(p["controlled_folder_access"]),
    verify=lambda a, p: (
        int(a.system.defender_get()["controlled_folder_access"]) == p["controlled_folder_access"]
    ),
    revert=lambda a, p, b: a.system.defender_set_cfa(b["controlled_folder_access"]),
    verify_reverted=lambda a, p, b: (
        int(a.system.defender_get()["controlled_folder_access"]) == b["controlled_folder_access"]
    ),
    before_ok=lambda p, b: b.get("controlled_folder_access") in (0, 1, 2),
)

DEFENDER_UPDATE = Primitive(
    kind="defender.update_signatures",
    snapshot=lambda a, p: {},
    apply=lambda a, p, b: a.system.update_signatures(),
    verify=lambda a, p: True,
    revert=lambda a, p, b: None,  # downloading definitions has nothing to undo
    verify_reverted=lambda a, p, b: True,
    before_ok=lambda p, b: b == {},
)

NETBIOS = Primitive(
    kind="netbios.adapter",
    snapshot=lambda a, p: {"option": a.system.netbios_get(int(p["config_index"]))},
    apply=lambda a, p, b: a.system.netbios_set(int(p["config_index"]), int(p["option"])),
    verify=lambda a, p: a.system.netbios_get(int(p["config_index"])) == int(p["option"]),
    revert=lambda a, p, b: a.system.netbios_set(int(p["config_index"]), int(b["option"])),
    verify_reverted=lambda a, p, b: (
        a.system.netbios_get(int(p["config_index"])) == int(b["option"])
    ),
    before_ok=lambda p, b: b.get("option") in (0, 1, 2),
)


def _acct_snapshot(a: Adapters, p: dict[str, Any]) -> dict[str, Any]:
    acct = a.accounts.find_by_rid(int(p["rid"]))
    if acct is None:
        raise ActionError(f"no local account with RID {p['rid']}")
    return {"name": acct.name, "enabled": acct.enabled}


ACCOUNT = Primitive(
    kind="account.enabled",
    snapshot=_acct_snapshot,
    apply=lambda a, p, b: a.accounts.set_enabled(b["name"], p["enabled"]),
    verify=lambda a, p: _acct_snapshot(a, p)["enabled"] == p["enabled"],
    revert=lambda a, p, b: a.accounts.set_enabled(b["name"], b["enabled"]),
    verify_reverted=lambda a, p, b: _acct_snapshot(a, p)["enabled"] == b["enabled"],
    before_ok=lambda p, b: isinstance(b.get("enabled"), bool) and isinstance(b.get("name"), str),
)


PRIMITIVES: dict[str, Primitive] = {
    p.kind: p
    for p in (
        FW_ADD,
        FW_REMOVE,
        FW_PROFILE,
        REG_VALUE,
        SERVICE,
        NET_CATEGORY,
        WIFI_MODE,
        TASK,
        SMB,
        DEFENDER_PREF,
        DEFENDER_UPDATE,
        NETBIOS,
        ACCOUNT,
    )
}
