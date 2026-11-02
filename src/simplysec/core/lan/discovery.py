"""Which networks may be scanned, and which devices are on them.

Scope: the IPv4 subnet of each private (RFC 1918) Ethernet or Wi-Fi interface, from its
netmask, capped at /22 around this PC. VPN and virtual adapters are never scanned. A network
is only scanned after the user confirmed it is theirs (remembered by name + subnet).

Discovery: async TCP connect probes to every address (any answer, even "refused", proves a
host; the attempts also fill the ARP cache), then the neighbour table gives MAC addresses.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from ..models import InterfaceKind, NetInterface

MAX_PREFIX = 22
DISCOVERY_PORTS = (80, 443, 445, 22, 139, 554, 8080, 62078, 8008, 9100)


@dataclass(frozen=True)
class ScanTarget:
    interface: str
    interface_index: int
    network_name: str
    local_ip: str
    network: ipaddress.IPv4Network
    gateways: tuple[str, ...]

    @property
    def key(self) -> str:
        """How a confirmation is remembered: the network's name and subnet."""
        return f"{self.network_name or self.interface}|{self.network}"

    @property
    def label(self) -> str:
        return f"{self.network_name or self.interface} ({self.network}, via {self.interface})"


def scan_targets(interfaces: Iterable[NetInterface]) -> list[ScanTarget]:
    out = []
    for iface in interfaces:
        if not iface.up or iface.kind not in (InterfaceKind.ETHERNET, InterfaceKind.WIFI):
            continue
        for ipi in iface.ip_interfaces():
            if (
                ipi.version != 4
                or not ipi.ip.is_private
                or ipi.ip.is_loopback
                or ipi.ip.is_link_local
            ):
                continue
            net = ipaddress.IPv4Network(ipi.network)
            if net.prefixlen < MAX_PREFIX:
                net = ipaddress.IPv4Network(f"{ipi.ip}/{MAX_PREFIX}", strict=False)
            if net.prefixlen >= 31:
                continue
            out.append(
                ScanTarget(
                    interface=iface.alias,
                    interface_index=iface.index,
                    network_name=iface.network_name,
                    local_ip=str(ipi.ip),
                    network=net,
                    gateways=tuple(g for g in iface.gateways if "." in g),
                )
            )
    return out


async def _probe(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> bool | None:
    """True: open; False: refused (host is up); None: no answer."""
    async with sem:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except ConnectionRefusedError:
            return False
        except (TimeoutError, OSError):
            return None
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (TimeoutError, OSError):
            pass
        return True


async def _sweep(
    hosts: list[str], ports: Iterable[int], timeout: float, concurrency: int
) -> dict[str, set[int]]:
    """Map of host -> open ports, for every host that answered at all."""
    sem = asyncio.Semaphore(concurrency)
    ports = list(ports)
    tasks = {(h, p): asyncio.create_task(_probe(h, p, timeout, sem)) for h in hosts for p in ports}
    await asyncio.gather(*tasks.values(), return_exceptions=True)
    alive: dict[str, set[int]] = {}
    for (h, p), t in tasks.items():
        r = t.result() if not t.cancelled() and t.exception() is None else None
        if r is not None:
            alive.setdefault(h, set())
            if r:
                alive[h].add(p)
    return alive


def sweep(
    hosts: list[str], ports: Iterable[int], timeout: float = 0.6, concurrency: int = 256
) -> dict[str, set[int]]:
    return asyncio.run(_sweep(hosts, ports, timeout, concurrency))


def hosts_of(target: ScanTarget) -> list[str]:
    return [str(h) for h in target.network.hosts() if str(h) != target.local_ip]
