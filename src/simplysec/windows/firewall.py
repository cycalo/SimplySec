"""Windows Defender Firewall via the HNetCfg.FwPolicy2 COM API.

Reads the full rule set (about 600 rules in well under a second) and makes the few changes
SimplySec needs. Every rule SimplySec creates carries ``Grouping = "SimplySec"`` and a name
of the form ``SimplySec:<fix>:<id>``.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
import winreg
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..core.models import (
    FirewallProfileState,
    FirewallRule,
    FirewallState,
    Profile,
)
from . import runner

log = logging.getLogger(__name__)

GROUP = "SimplySec"
NET_FW_RULE_DIR_IN = 1
NET_FW_ACTION_BLOCK = 0
NET_FW_ACTION_ALLOW = 1

_local = threading.local()


class FirewallError(RuntimeError):
    pass


def ensure_com() -> None:
    """Initialise COM once per thread (Qt worker threads need this)."""
    if getattr(_local, "com", False):
        return
    import pythoncom

    try:
        pythoncom.CoInitialize()
    except pythoncom.com_error:
        pass  # already initialised in another mode: fine for these objects
    _local.com = True


def _policy() -> Any:
    ensure_com()
    import win32com.client

    return win32com.client.Dispatch("HNetCfg.FwPolicy2")


def _com_message(exc: Exception) -> str:
    try:
        import pythoncom

        if isinstance(exc, pythoncom.com_error):
            inner = exc.excepinfo[5] if exc.excepinfo else exc.hresult
            if inner in (-2147024891, 0x80070005):
                return "access denied (administrator rights are needed)"
            return f"COM error {inner & 0xFFFFFFFF:#010x}"
    except ImportError:
        pass
    return str(exc)


@contextmanager
def _com_errors(what: str):
    try:
        yield
    except FirewallError:
        raise
    except Exception as exc:
        raise FirewallError(f"{what}: {_com_message(exc)}") from exc


def _put_indexed(obj: Any, name: str, index: int, value: Any) -> None:
    import pythoncom

    ole = obj._oleobj_
    dispid = ole.GetIDsOfNames(name)
    ole.Invoke(dispid, 0, pythoncom.DISPATCH_PROPERTYPUT, 0, index, value)


# --------------------------------------------------------------------------- read


def _rule_from_com(r: Any) -> FirewallRule:
    def get(attr: str, default: Any = "") -> Any:
        try:
            value = getattr(r, attr)
        except Exception:
            return default
        return default if value is None else value

    interfaces = get("Interfaces", None)
    return FirewallRule(
        name=get("Name"),
        description=get("Description"),
        application=get("ApplicationName"),
        service=get("serviceName"),
        protocol=int(get("Protocol", 256)),
        local_ports=get("LocalPorts") or "*",
        remote_ports=get("RemotePorts") or "*",
        local_addresses=get("LocalAddresses") or "*",
        remote_addresses=get("RemoteAddresses") or "*",
        icmp_types=get("IcmpTypesAndCodes"),
        direction="in" if int(get("Direction", 1)) == NET_FW_RULE_DIR_IN else "out",
        interfaces=[str(i) for i in interfaces] if interfaces else [],
        interface_types=get("InterfaceTypes") or "All",
        enabled=bool(get("Enabled", False)),
        grouping=get("Grouping"),
        profiles=int(get("Profiles", 0x7FFFFFFF)),
        edge_traversal=bool(get("EdgeTraversal", False)),
        action="allow" if int(get("Action", 1)) == NET_FW_ACTION_ALLOW else "block",
        edge_traversal_options=int(get("EdgeTraversalOptions", 0)),
        local_app_package_id=get("LocalAppPackageId"),
        local_user_owner=get("LocalUserOwner"),
        local_user_authorized=get("LocalUserAuthorizedList"),
        remote_user_authorized=get("RemoteUserAuthorizedList"),
        remote_machine_authorized=get("RemoteMachineAuthorizedList"),
        secure_flags=int(get("SecureFlags", 0)),
    )


RULE_STORES = (
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
    r"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules",
)


def _indirect(text: str) -> str:
    """Resolve '@FirewallAPI.dll,-28511' to the display name Windows shows (and COM returns)."""
    if not text.startswith("@"):
        return text
    import ctypes

    buf = ctypes.create_unicode_buffer(1024)
    try:
        hr = ctypes.windll.shlwapi.SHLoadIndirectString(text, buf, len(buf), None)
    except OSError:
        return text
    return buf.value if hr == 0 else text


_PROFILE_BITS = {"domain": 1, "private": 2, "public": 4}


def _shape(
    direction: str, protocol: int, app: str, service: str, profiles: int, action: str
) -> tuple[str, int, str, str, int, str]:
    from ..core.exposure import normalize_app_path

    mask = 7 if profiles in (0, 0x7FFFFFFF) else profiles & 7
    return (direction, protocol, normalize_app_path(app), (service or "").lower(), mask, action)


class TrustTupleIndex:
    """Hidden TTK conditions from the rules' registry definitions (readable without admin).

    COM shows display names, which can differ from the resolved registry names (cached MUI
    strings), so rules are joined by name when possible and otherwise by their shape
    (direction, protocol, program, service, profiles, action) when that shape is unique.
    """

    def __init__(self) -> None:
        self.by_name: dict[tuple[str, tuple[str, int, str, str, int, str]], list[str]] = {}
        self.by_shape: dict[tuple[str, int, str, str, int, str], list[list[str]]] = {}

    def lookup(self, rule: FirewallRule) -> list[str]:
        shape = _shape(
            rule.direction,
            rule.protocol,
            rule.application,
            rule.service,
            rule.profiles,
            rule.action,
        )
        hit = self.by_name.get((rule.name.lower(), shape))
        if hit is not None:
            return hit
        candidates = self.by_shape.get(shape, [])
        if len(candidates) == 1:
            return candidates[0]
        return []


def trust_tuple_index() -> TrustTupleIndex:
    index = TrustTupleIndex()
    for sub in RULE_STORES:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub)
        except OSError:
            continue
        with key:
            i = 0
            while True:
                try:
                    _, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if not isinstance(value, str) or not value.startswith("v2"):
                    continue
                fields: dict[str, str] = {}
                ttk: list[str] = []
                profiles = 0
                for part in value.split("|"):
                    k, _, v = part.partition("=")
                    if k.startswith("TTK"):
                        ttk.append(v)
                    elif k == "Profile":
                        profiles |= _PROFILE_BITS.get(v.lower(), 0)
                    elif k not in fields:
                        fields[k] = v
                direction = "in" if fields.get("Dir", "In").lower() == "in" else "out"
                proto = int(fields.get("Protocol", "256") or 256)
                action = "allow" if fields.get("Action", "Allow").lower() == "allow" else "block"
                shape = _shape(
                    direction, proto, fields.get("App", ""), fields.get("Svc", ""), profiles, action
                )
                index.by_shape.setdefault(shape, []).append(ttk)
                if ttk:
                    index.by_name[(_indirect(fields.get("Name", "")).lower(), shape)] = ttk
    return index


def _policy_managed() -> bool:
    """True when Group Policy sets the firewall state or default action."""
    base = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"
    for sub in ("DomainProfile", "PrivateProfile", "PublicProfile", "StandardProfile"):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{sub}") as k:
                for value in ("EnableFirewall", "DefaultInboundAction"):
                    try:
                        winreg.QueryValueEx(k, value)
                        return True
                    except OSError:
                        continue
        except OSError:
            continue
    return False


def read_state(include_rules: bool = True) -> FirewallState:
    with _com_errors("reading the firewall"):
        fw = _policy()
        profiles = {}
        for p in (Profile.DOMAIN, Profile.PRIVATE, Profile.PUBLIC):
            profiles[p] = FirewallProfileState(
                profile=p,
                enabled=bool(fw.FirewallEnabled(int(p))),
                default_inbound_block=int(fw.DefaultInboundAction(int(p))) == NET_FW_ACTION_BLOCK,
                block_all_inbound=bool(fw.BlockAllInboundTraffic(int(p))),
            )
        rules = [_rule_from_com(r) for r in fw.Rules] if include_rules else []
        if rules:
            try:
                ttk = trust_tuple_index()
            except Exception as exc:  # pragma: no cover - registry layout changed
                log.warning("could not read trust-tuple conditions: %s", exc)
                ttk = None
            for r in rules:
                hit = ttk.lookup(r) if ttk else []
                if hit:
                    r.trust_tuples = list(hit)
        return FirewallState(
            profiles=profiles,
            rules=rules,
            current_profiles=int(fw.CurrentProfileTypes),
            managed_by_policy=_policy_managed(),
            local_policy_modify_state=int(fw.LocalPolicyModifyState),
        )


def find_rules(name: str) -> list[FirewallRule]:
    with _com_errors(f"looking up rule {name!r}"):
        fw = _policy()
        return [_rule_from_com(r) for r in fw.Rules if r.Name == name]


def group_rules(group: str = GROUP) -> list[FirewallRule]:
    with _com_errors("listing SimplySec rules"):
        fw = _policy()
        return [_rule_from_com(r) for r in fw.Rules if (r.Grouping or "") == group]


# --------------------------------------------------------------------------- write


def add_rule(rule: FirewallRule) -> None:
    """Create one rule exactly as described. Raises FirewallError on failure."""
    with _com_errors(f"creating rule {rule.name!r}"):
        import win32com.client

        fw = _policy()
        r = win32com.client.Dispatch("HNetCfg.FWRule")
        r.Name = rule.name
        r.Description = rule.description
        if rule.application:
            r.ApplicationName = rule.application
        if rule.service:
            r.serviceName = rule.service
        r.Protocol = rule.protocol  # must precede ports
        if rule.protocol in (6, 17):
            if rule.local_ports not in ("", "*"):
                r.LocalPorts = rule.local_ports
            if rule.remote_ports not in ("", "*"):
                r.RemotePorts = rule.remote_ports
        if rule.local_addresses not in ("", "*"):
            r.LocalAddresses = rule.local_addresses
        if rule.remote_addresses not in ("", "*"):
            r.RemoteAddresses = rule.remote_addresses
        if rule.icmp_types:
            r.IcmpTypesAndCodes = rule.icmp_types
        r.Direction = NET_FW_RULE_DIR_IN if rule.direction == "in" else 2
        if rule.interfaces:
            r.Interfaces = list(rule.interfaces)
        r.InterfaceTypes = rule.interface_types or "All"
        r.Profiles = rule.profiles
        r.Action = NET_FW_ACTION_ALLOW if rule.action == "allow" else NET_FW_ACTION_BLOCK
        r.EdgeTraversal = bool(rule.edge_traversal)
        if rule.grouping:
            r.Grouping = rule.grouping
        for attr, value in (
            ("LocalAppPackageId", rule.local_app_package_id),
            ("LocalUserOwner", rule.local_user_owner),
            ("LocalUserAuthorizedList", rule.local_user_authorized),
            ("RemoteUserAuthorizedList", rule.remote_user_authorized),
            ("RemoteMachineAuthorizedList", rule.remote_machine_authorized),
        ):
            if value:
                setattr(r, attr, value)
        if rule.edge_traversal_options:
            r.EdgeTraversalOptions = rule.edge_traversal_options
        r.Enabled = bool(rule.enabled)  # COM default is disabled
        fw.Rules.Add(r)
    log.info("firewall rule added: %s", rule.name)


def remove_rules_named(name: str, limit: int = 50) -> int:
    """Remove every rule with exactly this name. Returns how many were removed."""
    removed = 0
    with _com_errors(f"removing rule {name!r}"):
        fw = _policy()
        while removed < limit and any(r.Name == name for r in fw.Rules):
            fw.Rules.Remove(name)
            removed += 1
    log.info("firewall rule removed: %s (x%d)", name, removed)
    return removed


def set_profile(
    profile: Profile, enabled: bool | None = None, default_inbound_block: bool | None = None
) -> None:
    with _com_errors(f"changing the {profile.label} firewall profile"):
        fw = _policy()
        if enabled is not None:
            _put_indexed(fw, "FirewallEnabled", int(profile), bool(enabled))
        if default_inbound_block is not None:
            action = NET_FW_ACTION_BLOCK if default_inbound_block else NET_FW_ACTION_ALLOW
            _put_indexed(fw, "DefaultInboundAction", int(profile), action)


def read_profile(profile: Profile) -> FirewallProfileState:
    return read_state(include_rules=False).profiles[profile]


def export_policy(folder: Path, keep: int = 10) -> Path:
    """``netsh advfirewall export`` to a unique timestamped file; keep the newest ``keep``."""
    folder.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    target = folder / f"firewall-{stamp}.wfw"
    runner.run(
        [str(runner.SYSTEM32 / "netsh.exe"), "advfirewall", "export", str(target)],
        timeout=60,
        check=True,
    )
    if not target.exists():
        raise FirewallError(f"netsh reported success but {target} was not written")
    backups = sorted(folder.glob("firewall-*.wfw"))
    for old in backups[:-keep]:
        try:
            old.unlink()
        except OSError:
            log.warning("could not delete old backup %s", old)
    return target
