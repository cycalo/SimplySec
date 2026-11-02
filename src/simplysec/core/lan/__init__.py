"""Home-network scan: devices, their services, the router (UPnP), only on confirmed networks."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import ipaddress
import logging
import socket
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .. import knowledge, scoring
from ..models import FindingStatus
from . import discovery, identify, ssdp
from .discovery import ScanTarget, scan_targets
from .inventory import Device, device_findings, router_findings

if TYPE_CHECKING:
    from ..engine import Engine, ScanResult

log = logging.getLogger(__name__)

OWNED_KEY = "owned_networks"

__all__ = ["ScanTarget", "is_owned", "owned_networks", "scan_network", "scan_targets", "set_owned"]


def owned_networks(history: Any) -> dict[str, dict[str, Any]]:
    return dict(history.get_setting(OWNED_KEY, {}) or {})


def is_owned(history: Any, target: ScanTarget) -> bool:
    return target.key in owned_networks(history)


def set_owned(history: Any, target: ScanTarget, owned: bool) -> None:
    nets = owned_networks(history)
    if owned:
        nets[target.key] = {
            "label": target.label,
            "confirmed": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        }
    else:
        nets.pop(target.key, None)
    history.set_setting(OWNED_KEY, nets)


def forget_network(history: Any, key: str) -> None:
    nets = owned_networks(history)
    nets.pop(key, None)
    history.set_setting(OWNED_KEY, nets)


def in_target(target: ScanTarget, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in target.network
    except ValueError:
        return False


def _reverse_dns(ips: list[str], timeout: float = 2.0) -> dict[str, str]:
    out: dict[str, str] = {}

    def lookup(ip: str) -> tuple[str, str]:
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except OSError:
            return ip, ""

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=32)
    futures = [pool.submit(lookup, ip) for ip in ips]
    done, _ = concurrent.futures.wait(futures, timeout=timeout + 3)
    pool.shutdown(wait=False, cancel_futures=True)
    for f in done:
        ip, name = f.result()
        if name and name != ip:
            out[ip] = name
    return out


def _ssdp_names(target: ScanTarget) -> dict[str, tuple[str, str]]:
    names: dict[str, tuple[str, str]] = {}
    try:
        responses = ssdp.search("ssdp:all", timeout=3, bind_ip=target.local_ip)
    except OSError as exc:
        log.info("SSDP search failed: %s", exc)
        return names
    for r in responses:
        if r.ip in names or not in_target(target, r.ip):
            continue
        try:
            _, body = ssdp.fetch(r.location, [target.network], timeout=3)
            friendly, maker, model = ssdp.device_name(body)
        except Exception as exc:
            log.debug("SSDP description from %s failed: %s", r.ip, exc)
            continue
        if friendly or model:
            names[r.ip] = (friendly, " ".join(x for x in (maker, model) if x))
    return names


def scan_network(
    engine: Engine,
    result: ScanResult,
    targets: list[ScanTarget] | None = None,
    progress: Callable[[str], None] | None = None,
    deep: bool = False,
) -> ScanResult:
    """Scan the confirmed networks and merge devices, router info and findings into ``result``."""
    from ...windows import network as win_network
    from ..router.upnp_igd import read_router

    kb = knowledge.get()
    history = engine.history
    say = progress or (lambda _t: None)
    candidates = targets if targets is not None else scan_targets(result.interfaces)
    targets = [t for t in candidates if is_owned(history, t)]
    known_before = {d["mac"] for d in history.devices()}
    this_pc_ips = {str(i.ip) for iface in result.interfaces for i in iface.ip_interfaces()}
    devices: list[Device] = []
    routers: list[dict[str, Any]] = []
    probe_ports = [p.port for p in kb.lan_probe_ports()]
    oui = identify.oui_database()

    for target in targets:
        say(f"Looking for devices on {target.label}…")
        alive = discovery.sweep(discovery.hosts_of(target), discovery.DISCOVERY_PORTS)
        try:
            neigh = {
                ip: mac
                for ip, mac in win_network.neighbors(target.interface_index).items()
                if in_target(target, ip) and not identify.is_multicast(mac)
            }
        except Exception as exc:
            log.warning("neighbour table unavailable: %s", exc)
            neigh = {}
        ips = sorted(
            (set(alive) | set(neigh)) - {target.local_ip},
            key=lambda s: tuple(int(x) for x in s.split(".")),
        )
        say(f"Checking which services {len(ips)} device(s) offer…")
        open_map = discovery.sweep(ips, probe_ports, timeout=0.8)
        say("Identifying devices…")
        rdns = _reverse_dns(ips)
        names = _ssdp_names(target)
        deep_map: dict[str, Any] = {}
        if deep:
            from ...windows import nmap

            say("Deep scan with nmap (this can take a few minutes)…")
            try:
                deep_map = {h.ip: h for h in nmap.service_scan(ips, probe_ports)}
            except Exception as exc:
                log.warning("nmap deep scan failed: %s", exc)
        for ip in ips:
            mac = identify.normalize_mac(neigh.get(ip, ""))
            friendly, model = names.get(ip, ("", ""))
            d = Device(
                ip=ip,
                mac=mac,
                vendor=oui.vendor(mac),
                hostname=rdns.get(ip, ""),
                ssdp_name=friendly,
                model=model,
                open_ports=sorted(set(open_map.get(ip, set())) | set(alive.get(ip, set()))),
                is_gateway=ip in target.gateways,
            )
            if ip in deep_map:
                d.services = [s.__dict__ for s in deep_map[ip].services]
                d.vendor = d.vendor or deep_map[ip].vendor
            devices.append(d)
        say("Reading your router's port forwards (UPnP)…")
        routers.append(read_router(list(target.gateways), [target.network]).to_dict())

    # Inventory: remember devices by MAC; flag new ones after the first network scan.
    first_scan = not known_before
    for d in devices:
        if not d.mac:
            continue
        d.new = history.upsert_device(
            d.mac, d.ip, d.name, d.vendor, {"open_ports": d.open_ports, "model": d.model}
        )
    stored = {x["mac"]: x for x in history.devices()}
    for d in devices:
        rec = stored.get(d.mac, {})
        d.first_seen, d.last_seen = rec.get("first_seen", ""), rec.get("last_seen", "")
        d.trusted, d.label = bool(rec.get("trusted")), rec.get("label") or ""

    findings = device_findings(devices, kb, first_scan)
    accepted = history.accepted_widths()
    for r in routers:
        findings += router_findings(r, this_pc_ips, accepted)

    result.findings = [f for f in result.findings if f.check not in ("lan", "router")] + findings
    result.findings.sort(
        key=lambda f: (f.status != FindingStatus.OPEN, -int(f.severity), f.area, f.title)
    )
    result.score = scoring.score(result.findings)
    result.grade = scoring.grade(result.score)
    result.extras["devices"] = [d.to_dict() for d in devices]
    result.extras["router"] = routers[0] if routers else {}
    result.extras["networks"] = [t.label for t in targets]
    return result
