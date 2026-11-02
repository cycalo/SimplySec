"""Loader for the knowledge base (ports, programs, services).

The TOML files next to this module are the single source of truth for every port, program
and service description. Nothing else in the code base hard-codes port meanings.
"""

from __future__ import annotations

import ntpath
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ..models import Severity

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class PortInfo:
    port: int
    protocol: str
    name: str
    risk: Severity
    summary: str
    explain: str
    advice: str
    topic: str = ""
    kernel: bool = False
    service: str = ""
    lan_probe: bool = False
    fixes: tuple[str, ...] = ()
    discovery: bool = False


@dataclass(frozen=True)
class RangeInfo:
    start: int
    end: int
    protocol: str
    name: str
    risk: Severity
    summary: str
    explain: str
    advice: str


@dataclass(frozen=True)
class ProgramInfo:
    id: str
    exe: tuple[str, ...]
    name: str
    description: str
    risk: Severity
    explain: str
    intent_env: str = ""
    ports: tuple[int, ...] = ()


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    display: str
    description: str
    risk: Severity
    never_touch: bool = False


@dataclass
class KnowledgeBase:
    ports: dict[tuple[str, int], PortInfo] = field(default_factory=dict)
    ranges: list[RangeInfo] = field(default_factory=list)
    programs: list[ProgramInfo] = field(default_factory=list)
    services: dict[str, ServiceInfo] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def port(self, protocol: str, port: int) -> PortInfo | None:
        return self.ports.get((protocol.lower(), port))

    def port_or_range(self, protocol: str, port: int) -> PortInfo | RangeInfo | None:
        exact = self.port(protocol, port)
        if exact is not None:
            return exact
        for r in self.ranges:
            if r.protocol == protocol and r.start <= port <= r.end:
                return r
        return None

    def program(self, exe_or_name: str) -> ProgramInfo | None:
        name = ntpath.basename(exe_or_name or "").lower()
        if not name:
            return None
        for p in self.programs:
            if name in p.exe:
                return p
        return None

    def program_by_id(self, pid: str) -> ProgramInfo | None:
        return next((p for p in self.programs if p.id == pid), None)

    def service(self, name: str) -> ServiceInfo | None:
        return self.services.get((name or "").lower())

    @property
    def never_touch(self) -> set[str]:
        return {s.name.lower() for s in self.services.values() if s.never_touch}

    def lan_probe_ports(self) -> list[PortInfo]:
        return sorted(
            (p for p in self.ports.values() if p.lan_probe and p.protocol == "tcp"),
            key=lambda p: p.port,
        )

    def all_fix_ids(self) -> set[str]:
        return {f for p in self.ports.values() for f in p.fixes}


def _risk(value: str, where: str, errors: list[str]) -> Severity:
    try:
        return Severity.parse(value)
    except KeyError:
        errors.append(f"{where}: unknown risk {value!r}")
        return Severity.MEDIUM


def load(directory: Path = HERE) -> KnowledgeBase:
    kb = KnowledgeBase()
    errors = kb.errors

    with (directory / "ports.toml").open("rb") as f:
        data = tomllib.load(f)
    for entry in data.get("port", []):
        where = f"ports.toml {entry.get('protocol')}/{entry.get('port')}"
        proto = str(entry.get("protocol", "")).lower()
        if proto not in ("tcp", "udp"):
            errors.append(f"{where}: protocol must be tcp or udp")
            continue
        for req in ("name", "summary", "explain", "advice", "risk"):
            if not entry.get(req):
                errors.append(f"{where}: missing {req}")
        key = (proto, int(entry["port"]))
        if key in kb.ports:
            errors.append(f"{where}: duplicate entry")
            continue
        kb.ports[key] = PortInfo(
            port=int(entry["port"]),
            protocol=proto,
            name=entry.get("name", ""),
            risk=_risk(entry.get("risk", "medium"), where, errors),
            summary=entry.get("summary", ""),
            explain=entry.get("explain", ""),
            advice=entry.get("advice", ""),
            topic=entry.get("topic", ""),
            kernel=bool(entry.get("kernel", False)),
            service=entry.get("service", ""),
            lan_probe=bool(entry.get("lan_probe", False)),
            fixes=tuple(entry.get("fixes", [])),
            discovery=bool(entry.get("discovery", False)),
        )
    for entry in data.get("range", []):
        where = f"ports.toml range {entry.get('start')}-{entry.get('end')}"
        kb.ranges.append(
            RangeInfo(
                start=int(entry["start"]),
                end=int(entry["end"]),
                protocol=entry["protocol"],
                name=entry["name"],
                risk=_risk(entry["risk"], where, errors),
                summary=entry["summary"],
                explain=entry["explain"],
                advice=entry["advice"],
            )
        )

    with (directory / "programs.toml").open("rb") as f:
        data = tomllib.load(f)
    seen_ids: set[str] = set()
    seen_exe: dict[str, str] = {}
    for entry in data.get("program", []):
        pid = entry.get("id", "")
        where = f"programs.toml {pid}"
        if pid in seen_ids:
            errors.append(f"{where}: duplicate id")
        seen_ids.add(pid)
        exes = tuple(e.lower() for e in entry.get("exe", []))
        for e in exes:
            if e in seen_exe:
                errors.append(f"{where}: exe {e} already listed under {seen_exe[e]}")
            seen_exe[e] = pid
        kb.programs.append(
            ProgramInfo(
                id=pid,
                exe=exes,
                name=entry.get("name", pid),
                description=entry.get("description", pid),
                risk=_risk(entry.get("risk", "medium"), where, errors),
                explain=entry.get("explain", ""),
                intent_env=entry.get("intent_env", ""),
                ports=tuple(entry.get("ports", [])),
            )
        )

    with (directory / "services.toml").open("rb") as f:
        data = tomllib.load(f)
    for entry in data.get("service", []):
        name = entry.get("name", "")
        where = f"services.toml {name}"
        if name.lower() in kb.services:
            errors.append(f"{where}: duplicate entry")
        kb.services[name.lower()] = ServiceInfo(
            name=name,
            display=entry.get("display", name),
            description=entry.get("description", ""),
            risk=_risk(entry.get("risk", "low"), where, errors),
            never_touch=bool(entry.get("never_touch", False)),
        )
    return kb


@lru_cache(maxsize=1)
def get() -> KnowledgeBase:
    return load()
