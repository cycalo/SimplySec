"""SSDP (UPnP discovery) and safe fetching of device description XML.

Used for device friendly names and for finding the router's Internet Gateway Device.
Safety: defusedxml only, 256 KB response cap, and only http URLs that point at a private
address on the scanned network.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from defusedxml import ElementTree

log = logging.getLogger(__name__)

MAX_BYTES = 256 * 1024
SSDP_ADDR = ("239.255.255.250", 1900)


class UnsafeUrl(ValueError):
    pass


def check_lan_url(url: str, allowed: list[ipaddress.IPv4Network] | None = None) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise UnsafeUrl(f"only plain http URLs on the local network are fetched: {url}")
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError as exc:
        raise UnsafeUrl(f"host must be an IP address: {url}") from exc
    if not ip.is_private or ip.is_loopback:
        raise UnsafeUrl(f"not a local network address: {url}")
    if allowed is not None and not any(ip in net for net in allowed):
        raise UnsafeUrl(f"outside the scanned network: {url}")


def fetch(
    url: str,
    allowed: list[ipaddress.IPv4Network] | None = None,
    timeout: float = 4,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    """GET/POST a LAN URL with a size cap. Returns (status, body). Never follows redirects."""
    check_lan_url(url, allowed)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            return None

    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        url, data=data, headers=headers or {}, method="POST" if data else "GET"
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(MAX_BYTES + 1)
            status = resp.status
    except urllib.error.HTTPError as exc:  # SOAP faults arrive as HTTP 500
        body = exc.read(MAX_BYTES + 1)
        status = exc.code
    if len(body) > MAX_BYTES:
        raise ValueError(f"response from {url} is larger than {MAX_BYTES // 1024} KB")
    return status, body


def parse_xml(body: bytes) -> Any:
    """defusedxml: entity expansion, external entities and DTDs are rejected."""
    return ElementTree.fromstring(body, forbid_dtd=True)


@dataclass
class SsdpResponse:
    ip: str
    location: str
    st: str
    server: str = ""
    usn: str = ""
    headers: dict[str, str] = field(default_factory=dict)


def parse_response(data: bytes, ip: str) -> SsdpResponse | None:
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    if not lines or ("200" not in lines[0] and not lines[0].upper().startswith("NOTIFY")):
        return None
    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    loc = headers.get("location", "")
    if not loc:
        return None
    return SsdpResponse(
        ip,
        loc,
        headers.get("st", headers.get("nt", "")),
        headers.get("server", ""),
        headers.get("usn", ""),
        headers,
    )


def search(st: str = "ssdp:all", timeout: float = 3.0, bind_ip: str = "") -> list[SsdpResponse]:
    """Send one M-SEARCH and collect responses until ``timeout``."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        f"ST: {st}\r\n\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    out: list[SsdpResponse] = []
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if bind_ip:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
            sock.bind((bind_ip, 0))
        sock.settimeout(0.5)
        sock.sendto(msg, SSDP_ADDR)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except TimeoutError:
                continue
            except OSError:
                break
            resp = parse_response(data, addr[0])
            if resp and not any(r.location == resp.location for r in out):
                out.append(resp)
    finally:
        sock.close()
    return out


def device_name(xml_body: bytes) -> tuple[str, str, str]:
    """(friendlyName, manufacturer, modelName) from a UPnP device description."""
    root = parse_xml(xml_body)

    def first(tag: str) -> str:
        for el in root.iter():
            if el.tag.endswith(tag) and el.text:
                return el.text.strip()[:120]
        return ""

    return first("friendlyName"), first("manufacturer"), first("modelName")
