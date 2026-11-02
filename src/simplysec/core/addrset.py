"""Sets of IP addresses for one address family, stored as sorted disjoint integer intervals.

Used by the exposure evaluator to compute "allowed remote addresses minus blocked remote
addresses" exactly, including ranges such as ``0.0.0.0-126.255.255.255``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

Interval = tuple[int, int]

MAX = {4: 2**32 - 1, 6: 2**128 - 1}


def _normalise(intervals: Iterable[Interval]) -> list[Interval]:
    out: list[Interval] = []
    for lo, hi in sorted(i for i in intervals if i[0] <= i[1]):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


class AddrSet:
    __slots__ = ("family", "intervals")

    def __init__(self, family: int, intervals: Iterable[Interval] = ()) -> None:
        self.family = family
        self.intervals = _normalise(intervals)

    # ----------------------------------------------------------------- constructors
    @classmethod
    def everything(cls, family: int) -> AddrSet:
        return cls(family, [(0, MAX[family])])

    @classmethod
    def empty(cls, family: int) -> AddrSet:
        return cls(family)

    @classmethod
    def from_network(cls, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> AddrSet:
        return cls(net.version, [(int(net.network_address), int(net.broadcast_address))])

    @classmethod
    def loopback(cls, family: int) -> AddrSet:
        if family == 4:
            return cls.from_network(ipaddress.ip_network("127.0.0.0/8"))
        return cls.from_network(ipaddress.ip_network("::1/128"))

    # ----------------------------------------------------------------- algebra
    def _check(self, other: AddrSet) -> None:
        if other.family != self.family:
            raise ValueError("address family mismatch")

    def union(self, other: AddrSet) -> AddrSet:
        self._check(other)
        return AddrSet(self.family, self.intervals + other.intervals)

    def subtract(self, other: AddrSet) -> AddrSet:
        self._check(other)
        result: list[Interval] = []
        cut = other.intervals
        for lo, hi in self.intervals:
            cur = lo
            for clo, chi in cut:
                if chi < cur or clo > hi:
                    continue
                if clo > cur:
                    result.append((cur, clo - 1))
                cur = max(cur, chi + 1)
                if cur > hi:
                    break
            if cur <= hi:
                result.append((cur, hi))
        return AddrSet(self.family, result)

    def intersect(self, other: AddrSet) -> AddrSet:
        return self.subtract(self.subtract(other))

    def is_empty(self) -> bool:
        return not self.intervals

    def is_everything(self) -> bool:
        return self.intervals == [(0, MAX[self.family])]

    def issubset(self, other: AddrSet) -> bool:
        return self.subtract(other).is_empty()

    def contains_ip(self, ip: str) -> bool:
        try:
            value = int(ipaddress.ip_address(ip.split("%")[0]))
        except ValueError:
            return False
        return any(lo <= value <= hi for lo, hi in self.intervals)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AddrSet) and (self.family, self.intervals) == (
            other.family,
            other.intervals,
        )

    def __hash__(self) -> int:
        return hash((self.family, tuple(self.intervals)))

    def __repr__(self) -> str:
        return f"AddrSet({self.family}, {self.describe()})"

    # ----------------------------------------------------------------- display
    def describe(self, limit: int = 6) -> list[str]:
        if self.is_everything():
            return ["any address"]
        parts: list[str] = []
        addr_cls = ipaddress.IPv4Address if self.family == 4 else ipaddress.IPv6Address
        for lo, hi in self.intervals:
            first, last = addr_cls(lo), addr_cls(hi)
            nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = list(
                ipaddress.summarize_address_range(first, last)
            )
            if len(nets) <= 2:
                parts.extend(
                    str(n) if n.num_addresses > 1 else str(n.network_address) for n in nets
                )
            else:
                parts.append(f"{first}-{last}")
        if len(parts) > limit:
            return [*parts[:limit], f"+{len(parts) - limit} more"]
        return parts


def parse_literal(token: str) -> AddrSet | None:
    """Parse one firewall address token that is not a keyword.

    Supports single addresses, CIDR (``/24``), dotted masks (``/255.255.255.0``) and ranges
    (``a-b``). Returns ``None`` if the token is not a literal address.
    """
    token = token.strip()
    if not token:
        return None
    try:
        if "-" in token and "/" not in token:
            a, b = token.split("-", 1)
            lo, hi = ipaddress.ip_address(a), ipaddress.ip_address(b)
            if lo.version != hi.version:
                return None
            return AddrSet(lo.version, [(int(lo), int(hi))])
        if "/" in token:
            addr, mask = token.split("/", 1)
            if "." in mask or ":" in mask:
                net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
            else:
                net = ipaddress.ip_network(f"{addr}/{int(mask)}", strict=False)
            return AddrSet.from_network(net)
        ip = ipaddress.ip_address(token.split("%")[0])
        return AddrSet(ip.version, [(int(ip), int(ip))])
    except ValueError:
        return None
