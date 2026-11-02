"""Read the router's UPnP Internet Gateway Device: external IP and port forwards (read-only).

SSDP finds the gateway's description, then SOAP calls ``GetExternalIPAddress`` and loops
``GetGenericPortMappingEntry`` (at most 256 entries, stopping at fault 713,
SpecifiedArrayIndexInvalid). Nothing on the router is ever changed.
"""

from __future__ import annotations

import ipaddress
import logging
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any

from ..lan import ssdp

log = logging.getLogger(__name__)

IGD_TYPES = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
)
WAN_SERVICES = (
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
MAX_ENTRIES = 256
FAULT_ARRAY_INDEX_INVALID = "713"
CGNAT = ipaddress.ip_network("100.64.0.0/10")


@dataclass
class PortMapping:
    external_port: int
    protocol: str
    internal_client: str
    internal_port: int
    description: str = ""
    enabled: bool = True
    remote_host: str = ""
    lease: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RouterInfo:
    found: bool = False
    location: str = ""
    friendly_name: str = ""
    manufacturer: str = ""
    model: str = ""
    service_type: str = ""
    control_url: str = ""
    external_ip: str = ""
    mappings: list[PortMapping] = field(default_factory=list)
    error: str = ""

    @property
    def external_is_private(self) -> bool:
        try:
            ip = ipaddress.ip_address(self.external_ip)
        except ValueError:
            return False
        return ip.is_private or ip in CGNAT

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["external_is_private"] = self.external_is_private
        return d


def find_wan_service(description_xml: bytes, base_url: str) -> tuple[str, str]:
    """(serviceType, absolute controlURL) of the first WAN connection service."""
    root = ssdp.parse_xml(description_xml)
    url_base = ""
    for el in root.iter():
        if el.tag.endswith("URLBase") and el.text:
            url_base = el.text.strip()
    for svc in root.iter():
        if not svc.tag.endswith("service"):
            continue
        stype = control = ""
        for child in svc:
            if child.tag.endswith("serviceType") and child.text:
                stype = child.text.strip()
            elif child.tag.endswith("controlURL") and child.text:
                control = child.text.strip()
        if stype in WAN_SERVICES and control:
            return stype, urllib.parse.urljoin(url_base or base_url, control)
    return "", ""


def soap_envelope(service_type: str, action: str, args: dict[str, str] | None = None) -> bytes:
    from xml.sax.saxutils import escape

    body = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in (args or {}).items())
    return (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{escape(service_type)}">{body}</u:{action}></s:Body></s:Envelope>'
    ).encode()


class SoapFault(Exception):
    def __init__(self, code: str, description: str = "") -> None:
        super().__init__(f"UPnP error {code} {description}".strip())
        self.code = code


def parse_soap(body: bytes) -> dict[str, str]:
    """Return the action response's out-arguments, or raise SoapFault."""
    root = ssdp.parse_xml(body)
    for el in root.iter():
        if el.tag.endswith("UPnPError"):
            code = desc = ""
            for c in el:
                if c.tag.endswith("errorCode"):
                    code = (c.text or "").strip()
                elif c.tag.endswith("errorDescription"):
                    desc = (c.text or "").strip()
            raise SoapFault(code, desc)
    for el in root.iter():
        if el.tag.endswith("Body"):
            for resp in el:
                return {child.tag.split("}")[-1]: (child.text or "").strip() for child in resp}
    return {}


def call(
    control_url: str,
    service_type: str,
    action: str,
    args: dict[str, str] | None = None,
    allowed: list[Any] | None = None,
) -> dict[str, str]:
    status, body = ssdp.fetch(
        control_url,
        allowed,
        data=soap_envelope(service_type, action, args),
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service_type}#{action}"',
        },
    )
    out = parse_soap(body)
    if status >= 400 and not out:
        raise SoapFault(str(status), "HTTP error")
    return out


def mapping_from(values: dict[str, str]) -> PortMapping:
    def num(key: str) -> int:
        try:
            return int(values.get(key, "0") or 0)
        except ValueError:
            return 0

    return PortMapping(
        external_port=num("NewExternalPort"),
        protocol=values.get("NewProtocol", "").upper(),
        internal_client=values.get("NewInternalClient", ""),
        internal_port=num("NewInternalPort"),
        description=values.get("NewPortMappingDescription", "")[:120],
        enabled=values.get("NewEnabled", "1") in ("1", "true", "True"),
        remote_host=values.get("NewRemoteHost", ""),
        lease=num("NewLeaseDuration"),
    )


def read_router(gateways: list[str], allowed: list[Any], timeout: float = 3.0) -> RouterInfo:
    info = RouterInfo()
    responses: list[ssdp.SsdpResponse] = []
    for st in IGD_TYPES:
        responses = [
            r for r in ssdp.search(st, timeout=timeout) if not gateways or r.ip in gateways
        ]
        if responses:
            break
    if not responses:
        return info
    resp = responses[0]
    info.found = True
    info.location = resp.location
    try:
        _, desc = ssdp.fetch(resp.location, allowed)
        info.friendly_name, info.manufacturer, info.model = ssdp.device_name(desc)
        info.service_type, info.control_url = find_wan_service(desc, resp.location)
        if not info.control_url:
            info.error = "the router describes no WAN connection service"
            return info
        info.external_ip = call(
            info.control_url, info.service_type, "GetExternalIPAddress", allowed=allowed
        ).get("NewExternalIPAddress", "")
        for index in range(MAX_ENTRIES):
            try:
                values = call(
                    info.control_url,
                    info.service_type,
                    "GetGenericPortMappingEntry",
                    {"NewPortMappingIndex": str(index)},
                    allowed,
                )
            except SoapFault as fault:
                if fault.code not in (FAULT_ARRAY_INDEX_INVALID, "714", "402"):
                    info.error = str(fault)
                break
            info.mappings.append(mapping_from(values))
    except Exception as exc:
        log.warning("router UPnP read failed: %s", exc)
        info.error = str(exc)
    return info
