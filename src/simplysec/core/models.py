"""Plain data types shared by every layer.

Everything here is serialisable to JSON (``to_dict``/``from_dict``) so scans can be stored,
compared and exported, and so tests can build fixtures by hand.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]

    def shifted(self, delta: int) -> Severity:
        return Severity(max(Severity.INFO, min(Severity.CRITICAL, int(self) + delta)))


class Profile(enum.IntFlag):
    """Windows Firewall profiles (same bit values as NET_FW_PROFILE_TYPE2)."""

    DOMAIN = 1
    PRIVATE = 2
    PUBLIC = 4

    @property
    def label(self) -> str:
        names = [
            str(p.name).title()
            for p in (Profile.DOMAIN, Profile.PRIVATE, Profile.PUBLIC)
            if p & self
        ]
        return " + ".join(n for n in names if n) or "None"


ALL_PROFILES_MASK = 0x7FFFFFFF  # what COM reports for "all profiles"
SINGLE_PROFILES = (Profile.DOMAIN, Profile.PRIVATE, Profile.PUBLIC)


class Verdict(enum.StrEnum):
    LOCAL_ONLY = "local_only"
    BLOCKED = "blocked"
    REACHABLE = "reachable"
    UNCERTAIN = "uncertain"

    @property
    def label(self) -> str:
        return {
            "local_only": "Only this PC",
            "blocked": "Blocked",
            "reachable": "Reachable",
            "uncertain": "Uncertain",
        }[self.value]


class Scope(enum.StrEnum):
    NONE = "none"
    SPECIFIC = "specific"
    LOCAL_SUBNET = "local_subnet"
    ANYONE = "anyone"

    @property
    def rank(self) -> int:
        return ["none", "specific", "local_subnet", "anyone"].index(self.value)


class InterfaceKind(enum.StrEnum):
    ETHERNET = "ethernet"
    WIFI = "wifi"
    VPN = "vpn"
    VIRTUAL = "virtual"
    LOOPBACK = "loopback"
    OTHER = "other"


# --------------------------------------------------------------------------- network


@dataclass
class NetInterface:
    index: int
    alias: str
    description: str = ""
    kind: InterfaceKind = InterfaceKind.ETHERNET
    mac: str = ""
    up: bool = True
    addresses: list[str] = field(default_factory=list)  # "192.168.1.71/24"
    profile: Profile | None = None  # None: Windows has no connection profile for it
    network_name: str = ""
    gateways: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    dhcp_servers: list[str] = field(default_factory=list)

    @property
    def effective_profile(self) -> Profile:
        # Windows treats unidentified networks as Public.
        return self.profile if self.profile is not None else Profile.PUBLIC

    def ip_interfaces(self) -> list[ipaddress.IPv4Interface | ipaddress.IPv6Interface]:
        out: list[ipaddress.IPv4Interface | ipaddress.IPv6Interface] = []
        for text in self.addresses:
            try:
                out.append(ipaddress.ip_interface(text.split("%")[0]))
            except ValueError:
                continue
        return out

    def has_ip(self, ip: str) -> bool:
        try:
            target = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return False
        return any(i.ip == target for i in self.ip_interfaces())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        d["profile"] = int(self.profile) if self.profile is not None else None
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> NetInterface:
        d = dict(d)
        d["kind"] = InterfaceKind(d.get("kind", "ethernet"))
        prof = d.get("profile")
        d["profile"] = Profile(prof) if prof is not None else None
        return cls(**d)


# --------------------------------------------------------------------------- listeners


@dataclass
class Listener:
    protocol: str  # "tcp" | "udp"
    address: str  # bind address
    port: int
    pid: int
    process: str = ""  # image name, e.g. "svchost.exe"
    exe: str = ""  # full path; "" for PID 4 or when unreadable
    services: list[str] | None = field(default_factory=list)  # None: unknown
    user_sid: str | None = None  # None: unknown (token unreadable)
    package_sid: str | None = ""  # "": not an AppContainer; None: unknown

    @property
    def key(self) -> str:
        return f"{self.protocol}:{self.address}:{self.port}"

    @property
    def family(self) -> int:
        try:
            return ipaddress.ip_address(self.address.split("%")[0]).version
        except ValueError:
            return 4

    @property
    def is_loopback(self) -> bool:
        try:
            return ipaddress.ip_address(self.address.split("%")[0]).is_loopback
        except ValueError:
            return False

    @property
    def is_wildcard(self) -> bool:
        return self.address in ("0.0.0.0", "::", "")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Listener:
        return cls(**d)


# --------------------------------------------------------------------------- firewall


@dataclass
class FirewallProfileState:
    profile: Profile
    enabled: bool = True
    default_inbound_block: bool = True
    block_all_inbound: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": int(self.profile),
            "enabled": self.enabled,
            "default_inbound_block": self.default_inbound_block,
            "block_all_inbound": self.block_all_inbound,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FirewallProfileState:
        return cls(
            profile=Profile(d["profile"]),
            enabled=d["enabled"],
            default_inbound_block=d["default_inbound_block"],
            block_all_inbound=d["block_all_inbound"],
        )


@dataclass
class FirewallRule:
    name: str
    action: str = "allow"  # "allow" | "block"
    direction: str = "in"  # "in" | "out"
    enabled: bool = True
    protocol: int = 256  # 6 TCP, 17 UDP, 256 any
    local_ports: str = "*"
    remote_ports: str = "*"
    local_addresses: str = "*"
    remote_addresses: str = "*"
    application: str = ""
    service: str = ""
    profiles: int = ALL_PROFILES_MASK
    interface_types: str = "All"
    interfaces: list[str] = field(default_factory=list)
    edge_traversal: bool = False
    edge_traversal_options: int = 0
    grouping: str = ""
    description: str = ""
    local_user_authorized: str = ""  # SDDL
    local_user_owner: str = ""  # SID
    local_app_package_id: str = ""  # AppContainer SID
    remote_user_authorized: str = ""
    remote_machine_authorized: str = ""
    secure_flags: int = 0
    icmp_types: str = ""
    # Hidden "trust tuple keyword" conditions (TTK, e.g. WFDKmDriver, UPnP): the rule only
    # applies to Wi-Fi Direct sessions or UPnP/Teredo-mapped traffic. COM hides these; they
    # are read from the rule's registry definition.
    trust_tuples: list[str] = field(default_factory=list)

    @property
    def protocol_label(self) -> str:
        return {6: "TCP", 17: "UDP", 256: "Any", 1: "ICMPv4", 58: "ICMPv6"}.get(
            self.protocol, str(self.protocol)
        )

    @property
    def profile_mask(self) -> int:
        return (
            Profile.DOMAIN | Profile.PRIVATE | Profile.PUBLIC
            if self.profiles == ALL_PROFILES_MASK
            else self.profiles & 7
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FirewallRule:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class FirewallState:
    profiles: dict[Profile, FirewallProfileState]
    rules: list[FirewallRule] = field(default_factory=list)
    current_profiles: int = 0
    managed_by_policy: bool = False
    local_policy_modify_state: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "profiles": [p.to_dict() for p in self.profiles.values()],
            "rules": [r.to_dict() for r in self.rules],
            "current_profiles": self.current_profiles,
            "managed_by_policy": self.managed_by_policy,
            "local_policy_modify_state": self.local_policy_modify_state,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FirewallState:
        profs = [FirewallProfileState.from_dict(p) for p in d["profiles"]]
        return cls(
            profiles={p.profile: p for p in profs},
            rules=[FirewallRule.from_dict(r) for r in d.get("rules", [])],
            current_profiles=d.get("current_profiles", 0),
            managed_by_policy=d.get("managed_by_policy", False),
            local_policy_modify_state=d.get("local_policy_modify_state", 0),
        )


# --------------------------------------------------------------------------- exposure


@dataclass
class InterfaceExposure:
    interface: str
    interface_kind: InterfaceKind
    profile: Profile
    profile_assumed: bool
    verdict: Verdict
    scope: Scope
    remote: list[str] = field(default_factory=list)
    allow_rules: list[str] = field(default_factory=list)
    block_rules: list[str] = field(default_factory=list)
    uncertain_rules: list[str] = field(default_factory=list)
    edge_traversal: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["interface_kind"] = self.interface_kind.value
        d["profile"] = int(self.profile)
        d["verdict"] = self.verdict.value
        d["scope"] = self.scope.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> InterfaceExposure:
        d = dict(d)
        d["interface_kind"] = InterfaceKind(d["interface_kind"])
        d["profile"] = Profile(d["profile"])
        d["verdict"] = Verdict(d["verdict"])
        d["scope"] = Scope(d["scope"])
        return cls(**d)


@dataclass
class Exposure:
    listener: Listener
    verdict: Verdict
    scope: Scope = Scope.NONE
    per_interface: list[InterfaceExposure] = field(default_factory=list)
    reason: str = ""

    @property
    def reachable(self) -> list[InterfaceExposure]:
        return [i for i in self.per_interface if i.verdict == Verdict.REACHABLE]

    @property
    def rules(self) -> list[str]:
        names: list[str] = []
        for ie in self.per_interface:
            for n in ie.allow_rules + ie.block_rules + ie.uncertain_rules:
                if n not in names:
                    names.append(n)
        return names

    def to_dict(self) -> dict[str, Any]:
        return {
            "listener": self.listener.to_dict(),
            "verdict": self.verdict.value,
            "scope": self.scope.value,
            "per_interface": [i.to_dict() for i in self.per_interface],
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Exposure:
        return cls(
            listener=Listener.from_dict(d["listener"]),
            verdict=Verdict(d["verdict"]),
            scope=Scope(d["scope"]),
            per_interface=[InterfaceExposure.from_dict(i) for i in d.get("per_interface", [])],
            reason=d.get("reason", ""),
        )


# --------------------------------------------------------------------------- findings


@dataclass
class FixOption:
    fix_id: str
    label: str
    params: dict[str, Any] = field(default_factory=dict)
    disruptive: bool = False
    recommended: bool = False  # included in "Fix recommended"
    guidance_only: bool = False  # opens Settings etc.; no tracked change

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FixOption:
        return cls(**d)


class FindingStatus(enum.StrEnum):
    OPEN = "open"
    ACCEPTED = "accepted"  # user chose "Keep"
    MANAGED = "managed"  # set by Group Policy / organisation: report only
    INFO = "info"  # transparency only, never scored


@dataclass
class Finding:
    id: str  # stable across scans, e.g. "rdp.nla_off" or "exposure.program:ollama.exe"
    check: str
    area: str
    title: str
    severity: Severity
    what_it_means: str
    details: list[tuple[str, str]] = field(default_factory=list)
    fixes: list[FixOption] = field(default_factory=list)
    learn_more: str = ""
    status: FindingStatus = FindingStatus.OPEN
    keep_key: str | None = None  # set when "Keep: I need this" is offered
    width: int = 0  # exposure width; a kept finding returns if this grows
    user_configured: bool = False

    @property
    def scored(self) -> bool:
        return self.status == FindingStatus.OPEN and self.severity > Severity.INFO

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "check": self.check,
            "area": self.area,
            "title": self.title,
            "severity": self.severity.name.lower(),
            "what_it_means": self.what_it_means,
            "details": [list(x) for x in self.details],
            "fixes": [f.to_dict() for f in self.fixes],
            "learn_more": self.learn_more,
            "status": self.status.value,
            "keep_key": self.keep_key,
            "width": self.width,
            "user_configured": self.user_configured,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        return cls(
            id=d["id"],
            check=d["check"],
            area=d["area"],
            title=d["title"],
            severity=Severity.parse(d["severity"]),
            what_it_means=d["what_it_means"],
            details=[(str(a), str(b)) for a, b in d.get("details", [])],
            fixes=[FixOption.from_dict(f) for f in d.get("fixes", [])],
            learn_more=d.get("learn_more", ""),
            status=FindingStatus(d.get("status", "open")),
            keep_key=d.get("keep_key"),
            width=d.get("width", 0),
            user_configured=d.get("user_configured", False),
        )


@dataclass
class ActionSpec:
    """One reversible primitive change, as shown in the preview and stored in the journal."""

    kind: str
    params: dict[str, Any]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ActionSpec:
        return cls(**d)
