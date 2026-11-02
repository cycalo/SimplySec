"""Network adapters, addresses and firewall profiles (Public / Private / Domain).

Addresses and netmasks come from psutil; adapter type, profile, gateways and DNS servers come
from the ``network`` section of facts.ps1 (all numeric or object data, nothing localized).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Any

import psutil

from ..core.models import InterfaceKind, NetInterface, Profile
from ..core.util import as_list
from . import runner

log = logging.getLogger(__name__)

CATEGORY_TO_PROFILE = {0: Profile.PUBLIC, 1: Profile.PRIVATE, 2: Profile.DOMAIN}
PROFILE_TO_CATEGORY = {Profile.PUBLIC: "Public", Profile.PRIVATE: "Private"}

VPN_HINTS = (
    "tailscale",
    "wireguard",
    "openvpn",
    "tap-windows",
    "zerotier",
    "wintun",
    "vpn",
    "nordlynx",
    "fortinet",
    "cisco anyconnect",
)
VIRTUAL_HINTS = (
    "vmware",
    "virtualbox",
    "hyper-v",
    "vethernet",
    "virtual ethernet",
    "wsl",
    "docker",
)


def classify(adapter: dict[str, Any] | None, alias: str) -> InterfaceKind:
    if adapter is None:
        return InterfaceKind.LOOPBACK if "loopback" in alias.lower() else InterfaceKind.OTHER
    text = f"{adapter.get('name', '')} {adapter.get('description', '')}".lower()
    if_type = int(adapter.get("if_type") or 0)
    if if_type == 24:
        return InterfaceKind.LOOPBACK
    if if_type == 71 or int(adapter.get("medium") or 0) == 9:
        return InterfaceKind.WIFI
    if if_type in (23, 53, 131) or any(h in text for h in VPN_HINTS):
        if any(h in text for h in VIRTUAL_HINTS):
            return InterfaceKind.VIRTUAL
        return InterfaceKind.VPN
    if adapter.get("virtual") or any(h in text for h in VIRTUAL_HINTS):
        return InterfaceKind.VIRTUAL
    return InterfaceKind.ETHERNET


def _netmask_prefix(addr: Any) -> str | None:
    try:
        ip = addr.address.split("%")[0]
        if addr.netmask:
            iface = ipaddress.ip_interface(f"{ip}/{addr.netmask}")
        else:
            iface = ipaddress.ip_interface(ip)
        return str(iface)
    except ValueError:
        return None


def build_interfaces(network_fact: dict[str, Any] | None) -> list[NetInterface]:
    """Combine psutil addresses with the facts.ps1 network section."""
    net = network_fact or {}
    adapters = {a.get("name"): a for a in as_list(net.get("adapters"))}
    profiles = {
        int(p["index"]): p for p in as_list(net.get("profiles")) if p.get("index") is not None
    }
    ipcfg = {int(c["index"]): c for c in as_list(net.get("ip")) if c.get("index") is not None}
    cfg = {int(c["index"]): c for c in as_list(net.get("config")) if c.get("index") is not None}

    stats = psutil.net_if_stats()
    out: list[NetInterface] = []
    for alias, addrs in psutil.net_if_addrs().items():
        adapter = adapters.get(alias)
        index = int(adapter["index"]) if adapter else -1
        addresses = []
        mac = ""
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                text = _netmask_prefix(a)
                if text:
                    addresses.append(text)
            elif a.family == psutil.AF_LINK:
                mac = a.address
        prof = profiles.get(index)
        st = stats.get(alias)
        iface = NetInterface(
            index=index,
            alias=alias,
            description=(adapter or {}).get("description", ""),
            kind=classify(adapter, alias),
            mac=(adapter or {}).get("mac") or mac,
            up=bool(st.isup) if st else False,
            addresses=addresses,
            profile=CATEGORY_TO_PROFILE.get(int(prof["category"])) if prof else None,
            network_name=prof.get("name", "") if prof else "",
            gateways=[
                g
                for g in as_list(ipcfg.get(index, {}).get("gateways"))
                if g and g not in ("0.0.0.0", "::")
            ],
            dns_servers=[d for d in as_list(ipcfg.get(index, {}).get("dns")) if d],
            dhcp_servers=[d for d in [cfg.get(index, {}).get("dhcp_server")] if d],
        )
        out.append(iface)
    out.sort(key=lambda i: (i.kind == InterfaceKind.LOOPBACK, not i.up, i.alias))
    return out


def set_category(interface_index: int, profile: Profile) -> None:
    """Mark a network Public or Private (admin)."""
    if profile not in PROFILE_TO_CATEGORY:
        raise ValueError("only Public or Private can be set")
    runner.powershell_json(
        "Set-NetConnectionProfile -InterfaceIndex ([int]$P.index) -NetworkCategory $P.category; 'null'",
        {"index": interface_index, "category": PROFILE_TO_CATEGORY[profile]},
    )


def get_category(interface_index: int) -> Profile | None:
    data = runner.powershell_json(
        "$p = Get-NetConnectionProfile -InterfaceIndex ([int]$P.index) -ErrorAction SilentlyContinue;"
        " if ($p) { [int]$p.NetworkCategory } else { 'null' }",
        {"index": interface_index},
    )
    return CATEGORY_TO_PROFILE.get(int(data)) if data is not None else None


_NEIGHBORS = r"""
$rows = @(Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex ([int]$P.index) -ErrorAction SilentlyContinue |
  Where-Object { [int]$_.State -ne 1 } |
  ForEach-Object { [ordered]@{ ip = $_.IPAddress; mac = $_.LinkLayerAddress; state = [int]$_.State } })
ConvertTo-Json -InputObject $rows -Compress
"""


def neighbors(interface_index: int) -> dict[str, str]:
    """IPv4 neighbour (ARP) table for one interface: ip -> MAC, skipping unreachable entries."""
    data = runner.powershell_json(_NEIGHBORS, {"index": int(interface_index)})
    out: dict[str, str] = {}
    for n in as_list(data):
        mac = str(n.get("mac") or "").replace("-", ":").upper()
        if not mac or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            continue
        out[str(n.get("ip"))] = mac
    return out
