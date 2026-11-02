"""Optional nmap integration (never bundled: its license doesn't allow it).

Only used for the optional "deep scan" of a confirmed home network (`nmap -sV`), and for
nmap's MAC vendor list when the bundled OUI list is missing.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import ElementTree

from . import runner

CANDIDATES = [
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Nmap" / "nmap.exe",
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Nmap" / "nmap.exe",
]


def find() -> Path | None:
    on_path = shutil.which("nmap")
    if on_path:
        return Path(on_path)
    return next((p for p in CANDIDATES if p.exists()), None)


def mac_prefixes_file() -> Path | None:
    exe = find()
    if exe is None:
        return None
    f = exe.parent / "nmap-mac-prefixes"
    return f if f.exists() else None


@dataclass
class NmapService:
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""


@dataclass
class NmapHost:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    services: list[NmapService] = field(default_factory=list)


def parse_xml(xml_text: str | bytes) -> list[NmapHost]:
    root = ElementTree.fromstring(xml_text, forbid_dtd=False)  # nmap emits a DOCTYPE, no entities
    hosts = []
    for h in root.iter("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        host = NmapHost(ip="")
        for addr in h.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host.ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                host.mac = addr.get("addr", "")
                host.vendor = addr.get("vendor", "")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            host.hostname = hn.get("name", "")
        for p in h.iter("port"):
            st = p.find("state")
            svc = p.find("service")
            host.services.append(
                NmapService(
                    port=int(p.get("portid", "0")),
                    protocol=p.get("protocol", "tcp"),
                    state=st.get("state", "") if st is not None else "",
                    name=svc.get("name", "") if svc is not None else "",
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                )
            )
        if host.ip:
            hosts.append(host)
    return hosts


def service_scan(targets: list[str], ports: list[int], timeout: float = 600) -> list[NmapHost]:
    exe = find()
    if exe is None:
        raise FileNotFoundError("nmap is not installed")
    args = [
        str(exe),
        "-sV",
        "-Pn",
        "--open",
        "-T4",
        "-p",
        ",".join(map(str, ports)),
        "-oX",
        "-",
        *targets,
    ]
    res = runner.run(args, timeout=timeout, check=True)
    return parse_xml(res.stdout)
