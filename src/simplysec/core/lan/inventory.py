"""Device inventory (by MAC) and the findings about other devices (guidance only)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ..checks.base import finding
from ..knowledge import KnowledgeBase
from ..models import Finding, FindingStatus, Severity
from .identify import describe, is_randomized

AREA_LAN = "Home network"
AREA_ROUTER = "Router"


@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = ""
    hostname: str = ""
    ssdp_name: str = ""
    model: str = ""
    open_ports: list[int] = field(default_factory=list)
    is_gateway: bool = False
    first_seen: str = ""
    last_seen: str = ""
    trusted: bool = False
    label: str = ""
    new: bool = False
    services: list[dict[str, Any]] = field(default_factory=list)  # nmap deep scan

    @property
    def name(self) -> str:
        return self.label or self.ssdp_name or self.hostname or ""

    @property
    def display(self) -> str:
        base = describe(self.mac, self.vendor, self.name)
        return f"{base} ({self.ip})"

    @property
    def randomized(self) -> bool:
        return is_randomized(self.mac)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["name"] = self.name
        d["randomized"] = self.randomized
        return d


def risky_services(device: Device, kb: KnowledgeBase) -> list[tuple[int, str, Severity]]:
    """Open ports on another device that deserve attention (LAN exposure: one level lower)."""
    out = []
    for port in sorted(device.open_ports):
        info = kb.port("tcp", port)
        if info is None:
            continue
        if device.is_gateway and port in (53, 80, 443, 8080, 8443):
            continue  # the router's own admin page and DNS are expected
        sev = info.risk.shifted(-1)
        if sev >= Severity.MEDIUM:
            out.append((port, info.name, sev))
    return out


def device_findings(devices: list[Device], kb: KnowledgeBase, first_scan: bool) -> list[Finding]:
    out: list[Finding] = []
    for d in devices:
        risky = risky_services(d, kb)
        if risky:
            sev = max(s for _, _, s in risky)
            names = ", ".join(f"{n} ({p})" for p, n, _ in risky)
            infos = [kb.port("tcp", p) for p, _, _ in risky]
            details = [
                (f"Port {p}", f"{n}: {info.explain if info else ''}")
                for (p, n, _), info in zip(risky, infos, strict=True)
            ]
            details += [("MAC", d.mac), ("Vendor", d.vendor or "unknown")]
            advice = " ".join(info.advice for info in infos if info)
            out.append(
                finding(
                    id=f"lan.services.{d.mac}",
                    check="lan",
                    area=AREA_LAN,
                    title=f"{d.display} offers {names}",
                    severity=sev,
                    what=(
                        "Another device on your network accepts connections on services that are often "
                        "attacked. SimplySec doesn't change other devices; check its settings or app, "
                        "update its firmware, set a strong password, or turn the service off."
                    ),
                    details=details,
                    learn_more=advice,
                )
            )
        if d.new and not d.trusted and not first_scan:
            f = finding(
                id=f"lan.new_device.{d.mac}",
                check="lan",
                area=AREA_LAN,
                title=f"New device on your network: {d.display}",
                severity=Severity.LOW,
                what=(
                    "SimplySec hasn't seen this device before. If you don't recognise it, check your "
                    "router's device list and change your Wi-Fi password. Mark it as trusted on the "
                    "My network page if it's yours."
                ),
                details=[
                    ("MAC", d.mac),
                    ("Vendor", d.vendor or "unknown"),
                    ("First seen", d.first_seen),
                ],
            )
            out.append(f)
    return out


def router_findings(
    router: dict[str, Any], this_pc_ips: set[str], accepted: dict[str, int]
) -> list[Finding]:
    out: list[Finding] = []
    if not router.get("found"):
        f = finding(
            id="router.upnp_not_found",
            check="router",
            area=AREA_ROUTER,
            title="Your router does not offer UPnP port forwarding",
            severity=Severity.INFO,
            what="Programs on your network can't open ports on your router by themselves. That's the safer setting.",
        )
        f.status = FindingStatus.INFO
        return [f]
    name = router.get("friendly_name") or router.get("model") or "Your router"
    for m in router.get("mappings", []):
        if not m.get("enabled", True):
            continue
        to_me = m.get("internal_client") in this_pc_ips
        desc = m.get("description") or "no description"
        key = f"router.forward.{m.get('protocol')}.{m.get('external_port')}"
        f = finding(
            id=key,
            check="router",
            area=AREA_ROUTER,
            title=(
                f"Your router forwards internet port {m.get('protocol')} {m.get('external_port')} to this PC"
                if to_me
                else f"Your router forwards internet port {m.get('protocol')} {m.get('external_port')} to {m.get('internal_client')}"
            ),
            severity=Severity.CRITICAL if to_me else Severity.HIGH,
            what=(
                "Anyone on the internet can connect through your router to "
                + ("this PC" if to_me else "that device")
                + f" on port {m.get('internal_port')} ('{desc}'). Programs (often games or remote-access tools) "
                "open these with UPnP. If you don't need it, close the program or turn UPnP off in your router."
            ),
            details=[
                ("Internal", f"{m.get('internal_client')}:{m.get('internal_port')}"),
                ("Description", desc),
                ("Lease", f"{m.get('lease')} s" if m.get("lease") else "permanent"),
                ("Router", name),
            ],
        )
        f.keep_key = f"keep:{key}"
        f.width = 1
        if accepted.get(f.keep_key) is not None:
            f.status = FindingStatus.ACCEPTED
        out.append(f)
    out.append(
        finding(
            id="router.upnp_on",
            check="router",
            area=AREA_ROUTER,
            title=f"UPnP is on in {name}",
            severity=Severity.LOW,
            what=(
                "UPnP lets any program on your network open ports on your router to the internet, without "
                "asking. Games and video calls sometimes use it. If nothing needs it, turn UPnP off in your "
                "router's admin page (usually under Advanced or NAT)."
            ),
            details=[
                ("Router", f"{name} {router.get('model', '')}".strip()),
                ("Description", router.get("location", "")),
            ],
        )
    )
    if router.get("external_is_private"):
        f = finding(
            id="router.cgnat",
            check="router",
            area=AREA_ROUTER,
            title="Your internet provider shares your public address (CGNAT)",
            severity=Severity.INFO,
            what=(
                f"Your router's internet address ({router.get('external_ip')}) is a private one, so your "
                "provider blocks connections from the internet before they reach your router. Port forwards "
                "won't work from outside, which is safer."
            ),
        )
        f.status = FindingStatus.INFO
        out.append(f)
    return out
