"""Shared test helpers: tiny builders for listeners, interfaces and firewall state."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from simplysec.core.engine import RawScan
from simplysec.core.exposure import EvalContext
from simplysec.core.models import (
    FirewallProfileState,
    FirewallRule,
    FirewallState,
    InterfaceKind,
    Listener,
    NetInterface,
    Profile,
)

FIXTURES = Path(__file__).parent / "fixtures"
ENV = {
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
    "PROGRAMFILES": r"C:\Program Files",
    "LOCALAPPDATA": r"C:\Users\alice\AppData\Local",
    "APPDATA": r"C:\Users\alice\AppData\Roaming",
    "USERPROFILE": r"C:\Users\alice",
    "PROGRAMDATA": r"C:\ProgramData",
    "TEMP": r"C:\Users\alice\AppData\Local\Temp",
}
ALICE = "S-1-5-21-1-2-3-1001"
BOB = "S-1-5-21-1-2-3-1004"


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Never touch the real %ProgramData%/%LOCALAPPDATA% stores from tests."""
    monkeypatch.setenv("SIMPLYSEC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SIMPLYSEC_USER_DIR", str(tmp_path / "user"))


def ethernet(
    profile: Profile | None = Profile.PRIVATE, ip: str = "192.168.1.10/24", alias: str = "Ethernet"
) -> NetInterface:
    return NetInterface(
        index=9,
        alias=alias,
        kind=InterfaceKind.ETHERNET,
        addresses=[ip, "fe80::1/64"],
        profile=profile,
        gateways=["192.168.1.1"],
        dns_servers=["192.168.1.1"],
    )


def tailscale(ip: str = "100.87.181.68/32") -> NetInterface:
    return NetInterface(
        index=8, alias="Tailscale", kind=InterfaceKind.VPN, addresses=[ip], profile=Profile.PRIVATE
    )


def fw(
    rules: list[FirewallRule] | None = None,
    enabled: bool = True,
    default_block: bool = True,
    block_all: bool = False,
    **per_profile: Any,
) -> FirewallState:
    profiles = {}
    for p in (Profile.DOMAIN, Profile.PRIVATE, Profile.PUBLIC):
        cfg = per_profile.get(p.name.lower(), {})
        profiles[p] = FirewallProfileState(
            p,
            enabled=cfg.get("enabled", enabled),
            default_inbound_block=cfg.get("default_block", default_block),
            block_all_inbound=cfg.get("block_all", block_all),
        )
    return FirewallState(profiles=profiles, rules=rules or [])


_UNSET: Any = object()


def listener(
    port: int = 8765,
    address: str = "0.0.0.0",
    exe: str = r"C:\Tools\server.exe",
    proto: str = "tcp",
    pid: int = 1234,
    user: str | None = ALICE,
    services: Any = _UNSET,
    package: str | None = "",
) -> Listener:
    return Listener(
        protocol=proto,
        address=address,
        port=port,
        pid=pid,
        process=exe.rsplit("\\", 1)[-1] if exe else ("System" if pid == 4 else ""),
        exe=exe,
        services=[] if services is _UNSET else services,
        user_sid=user,
        package_sid=package,
    )


def ctx(*interfaces: NetInterface) -> EvalContext:
    return EvalContext(interfaces=list(interfaces), env=ENV)


@pytest.fixture(scope="session")
def this_pc_raw() -> RawScan:
    return RawScan.from_dict(
        json.loads((FIXTURES / "this_pc_raw.json").read_text(encoding="utf-8"))
    )
