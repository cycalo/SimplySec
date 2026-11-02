"""Who is this device? MAC vendor (OUI), randomized MACs, reverse DNS, SSDP names."""

from __future__ import annotations

import csv
import gzip
import io
from functools import lru_cache
from pathlib import Path


def normalize_mac(mac: str) -> str:
    hexes = "".join(ch for ch in (mac or "").upper() if ch in "0123456789ABCDEF")
    if len(hexes) != 12:
        return ""
    return ":".join(hexes[i : i + 2] for i in range(0, 12, 2))


def is_randomized(mac: str) -> bool:
    """Locally administered bit set: a private (randomized) address, typical for phones."""
    m = normalize_mac(mac)
    return bool(m) and bool(int(m[:2], 16) & 0x02)


def is_multicast(mac: str) -> bool:
    m = normalize_mac(mac)
    return bool(m) and bool(int(m[:2], 16) & 0x01)


class OuiDatabase:
    def __init__(self, entries: dict[str, str]) -> None:
        self.entries = entries

    @classmethod
    def from_gzip_csv(cls, path: Path) -> OuiDatabase:
        data = gzip.decompress(path.read_bytes()).decode("utf-8")
        return cls({row[0]: row[1] for row in csv.reader(io.StringIO(data)) if len(row) >= 2})

    @classmethod
    def from_nmap(cls, path: Path) -> OuiDatabase:
        """nmap's nmap-mac-prefixes: 'AABBCC Vendor Name' lines."""
        entries = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if len(line) > 7 and not line.startswith("#"):
                prefix, _, vendor = line.partition(" ")
                if len(prefix) == 6:
                    entries[prefix.upper()] = vendor.strip()
        return cls(entries)

    def vendor(self, mac: str) -> str:
        m = normalize_mac(mac)
        if not m:
            return ""
        if is_randomized(m):
            return ""
        return self.entries.get(m.replace(":", "")[:6], "")

    def __len__(self) -> int:
        return len(self.entries)


@lru_cache(maxsize=1)
def oui_database() -> OuiDatabase:
    from ...app import paths
    from ...windows import nmap

    bundled = paths.resource("oui.csv.gz")
    if bundled.exists():
        return OuiDatabase.from_gzip_csv(bundled)
    prefixes = nmap.mac_prefixes_file()
    if prefixes is not None:
        return OuiDatabase.from_nmap(prefixes)
    return OuiDatabase({})


def describe(mac: str, vendor: str, name: str) -> str:
    """A friendly one-line label for a device."""
    if name:
        return name
    if vendor:
        return f"{vendor} device"
    if is_randomized(mac):
        return "Device with a private address (likely a phone or tablet)"
    return "Unknown device"
