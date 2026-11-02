"""Home network, router and Wi-Fi (M2): parsing on recorded fixtures, no network access."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
from defusedxml import DTDForbidden, EntitiesForbidden

from simplysec.core import knowledge
from simplysec.core.checks import wifi as wifi_check
from simplysec.core.engine import analyze_with_context
from simplysec.core.lan import discovery, identify, ssdp
from simplysec.core.lan.inventory import Device, device_findings, router_findings
from simplysec.core.models import FindingStatus, InterfaceKind, NetInterface, Profile, Severity
from simplysec.core.router import upnp_igd
from simplysec.windows import nmap, wifi

IGD = Path(__file__).parent.parent / "fixtures" / "igd"


def read(name: str) -> bytes:
    return (IGD / name).read_bytes()


# --------------------------------------------------------------------------- identify


def test_oui_lookup_and_randomized_macs():
    db = identify.oui_database()
    assert len(db) > 30000
    assert "Intel" in db.vendor("64-BC-58-C0-B0-70")  # this PC's Wi-Fi adapter
    assert "VMware" in db.vendor("00:50:56:C0:00:01")
    assert identify.is_randomized("DA:A1:19:00:00:01")
    assert not identify.is_randomized("64:BC:58:C0:B0:70")
    assert db.vendor("DA:A1:19:00:00:01") == ""
    assert identify.describe("DA:A1:19:00:00:01", "", "").startswith(
        "Device with a private address"
    )
    assert identify.normalize_mac("fc-34-97-a8-56-70") == "FC:34:97:A8:56:70"
    assert identify.is_multicast("01:00:5E:7F:FF:FA")


# --------------------------------------------------------------------------- scope


def _iface(alias, kind, addr, up=True, name=""):
    return NetInterface(
        index=1,
        alias=alias,
        kind=kind,
        addresses=[addr],
        up=up,
        profile=Profile.PUBLIC,
        network_name=name,
        gateways=["192.168.1.1"],
    )


def test_scan_targets_scope():
    targets = discovery.scan_targets(
        [
            _iface("Ethernet", InterfaceKind.ETHERNET, "192.168.1.71/24", name="EE-G9QKJQ"),
            _iface("Tailscale", InterfaceKind.VPN, "100.87.181.68/32"),
            _iface("VMnet1", InterfaceKind.VIRTUAL, "192.168.38.1/24"),
            _iface("Big", InterfaceKind.WIFI, "10.20.30.40/16"),
            _iface("Down", InterfaceKind.ETHERNET, "192.168.5.2/24", up=False),
            _iface("Public IP", InterfaceKind.ETHERNET, "81.2.69.142/24"),
        ]
    )
    nets = {t.interface: t.network for t in targets}
    assert nets == {
        "Ethernet": ipaddress.ip_network("192.168.1.0/24"),
        "Big": ipaddress.ip_network("10.20.28.0/22"),  # capped at /22 around this PC
    }
    eth = next(t for t in targets if t.interface == "Ethernet")
    assert eth.key == "EE-G9QKJQ|192.168.1.0/24"
    assert "192.168.1.71" not in discovery.hosts_of(eth) and len(discovery.hosts_of(eth)) == 253


# --------------------------------------------------------------------------- SSDP / IGD


def test_ssdp_response_parsing():
    raw = (
        b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        b"LOCATION: http://192.168.1.254:49152/rootDesc.xml\r\nSERVER: Linux UPnP/1.0\r\n\r\n"
    )
    r = ssdp.parse_response(raw, "192.168.1.254")
    assert r is not None and r.location.endswith("rootDesc.xml") and "InternetGateway" in r.st


def test_lan_url_safety():
    lan = [ipaddress.ip_network("192.168.1.0/24")]
    ssdp.check_lan_url("http://192.168.1.254:49152/x.xml", lan)
    for bad in (
        "https://192.168.1.254/x",
        "http://example.com/x",
        "http://8.8.8.8/x",
        "http://10.0.0.1/x",
        "file:///c:/x",
    ):
        with pytest.raises(ssdp.UnsafeUrl):
            ssdp.check_lan_url(bad, lan)


def test_entity_bomb_is_rejected():
    with pytest.raises((EntitiesForbidden, DTDForbidden)):
        ssdp.parse_xml(read("entity_bomb.xml"))
    with pytest.raises((EntitiesForbidden, DTDForbidden)):
        ssdp.device_name(read("entity_bomb.xml"))


def test_igd_description_and_soap():
    stype, control = upnp_igd.find_wan_service(
        read("description.xml"), "http://192.168.1.254:49152/rootDesc.xml"
    )
    assert stype == "urn:schemas-upnp-org:service:WANIPConnection:1"
    assert control == "http://192.168.1.254:49152/upnp/control/WANIPConn1"
    assert ssdp.device_name(read("description.xml")) == ("Smart Hub 2", "EE", "SH2")
    assert upnp_igd.parse_soap(read("external_ip.xml")) == {"NewExternalIPAddress": "81.2.69.142"}
    m = upnp_igd.mapping_from(upnp_igd.parse_soap(read("mapping_0.xml")))
    assert (m.external_port, m.protocol, m.internal_client, m.description) == (
        25565,
        "TCP",
        "192.168.1.71",
        "Minecraft server",
    )
    with pytest.raises(upnp_igd.SoapFault) as err:
        upnp_igd.parse_soap(read("fault_713.xml"))
    assert err.value.code == "713"
    env = upnp_igd.soap_envelope(stype, "GetGenericPortMappingEntry", {"NewPortMappingIndex": "0"})
    assert b"<NewPortMappingIndex>0</NewPortMappingIndex>" in env


def test_read_router_loops_until_fault_713(monkeypatch):
    calls = []

    def fake_search(st, timeout=3, bind_ip=""):
        return [ssdp.SsdpResponse("192.168.1.254", "http://192.168.1.254:49152/rootDesc.xml", st)]

    def fake_fetch(url, allowed=None, timeout=4, data=None, headers=None):
        ssdp.check_lan_url(url, allowed)
        if data is None:
            return 200, read("description.xml")
        action = headers["SOAPAction"].split("#")[1].strip('"')
        calls.append(action)
        if action == "GetExternalIPAddress":
            return 200, read("external_ip.xml")
        index = int(data.split(b"<NewPortMappingIndex>")[1].split(b"<")[0])
        return (200, read(f"mapping_{index}.xml")) if index < 2 else (500, read("fault_713.xml"))

    monkeypatch.setattr(ssdp, "search", fake_search)
    monkeypatch.setattr(ssdp, "fetch", fake_fetch)
    info = upnp_igd.read_router(["192.168.1.254"], [ipaddress.ip_network("192.168.1.0/24")])
    assert info.found and info.external_ip == "81.2.69.142" and not info.error
    assert [m.external_port for m in info.mappings] == [25565, 3074]
    assert calls.count("GetGenericPortMappingEntry") == 3


def test_router_findings():
    info = upnp_igd.RouterInfo(found=True, friendly_name="Smart Hub 2", external_ip="100.70.1.2")
    info.mappings = [
        upnp_igd.PortMapping(25565, "TCP", "192.168.1.71", 25565, "Minecraft server"),
        upnp_igd.PortMapping(3074, "UDP", "192.168.1.40", 3074, "Xbox"),
    ]
    fs = {f.id: f for f in router_findings(info.to_dict(), {"192.168.1.71"}, {})}
    assert fs["router.forward.TCP.25565"].severity == Severity.CRITICAL
    assert fs["router.forward.UDP.3074"].severity == Severity.HIGH
    assert fs["router.upnp_on"].severity == Severity.LOW
    assert fs["router.cgnat"].severity == Severity.INFO
    kept = {
        f.id: f
        for f in router_findings(
            info.to_dict(), {"192.168.1.71"}, {"keep:router.forward.TCP.25565": 1}
        )
    }
    assert kept["router.forward.TCP.25565"].status == FindingStatus.ACCEPTED
    none = router_findings({"found": False}, set(), {})
    assert none[0].id == "router.upnp_not_found" and none[0].severity == Severity.INFO


# --------------------------------------------------------------------------- inventory


def test_device_findings_and_new_devices():
    kb = knowledge.get()
    cam = Device(
        "192.168.1.20", "AC:DE:48:00:11:22", vendor="Hikvision", open_ports=[23, 80, 554], new=True
    )
    router = Device("192.168.1.254", "AA:BB:CC:00:00:01", open_ports=[53, 80, 443], is_gateway=True)
    phone = Device("192.168.1.30", "DA:A1:19:00:00:01", open_ports=[], new=True)
    fs = {f.id: f for f in device_findings([cam, router, phone], kb, first_scan=False)}
    telnet = fs["lan.services.AC:DE:48:00:11:22"]
    assert telnet.severity == Severity.HIGH and "Telnet" in telnet.title
    assert not telnet.fixes  # other devices only get guidance
    assert "lan.services.AA:BB:CC:00:00:01" not in fs  # router admin page is expected
    assert "lan.new_device.DA:A1:19:00:00:01" in fs
    first = device_findings([cam, phone], kb, first_scan=True)
    assert not [f for f in first if f.id.startswith("lan.new_device")]


def test_inventory_store(tmp_path):
    from simplysec.core.history import History

    h = History(tmp_path / "h.db")
    assert h.upsert_device("AA:BB:CC:00:00:01", "192.168.1.5", "tv", "LG", {}) is True
    assert (
        h.upsert_device("AA:BB:CC:00:00:01", "192.168.1.6", "", "", {"open_ports": [8008]}) is False
    )
    h.set_device_trusted("AA:BB:CC:00:00:01", True)
    d = h.devices()[0]
    assert (
        d["ip"] == "192.168.1.6"
        and d["name"] == "tv"
        and d["trusted"]
        and d["data"]["open_ports"] == [8008]
    )


def test_nmap_xml():
    hosts = nmap.parse_xml(read("nmap.xml"))
    assert len(hosts) == 1
    h = hosts[0]
    assert (h.ip, h.mac, h.hostname) == ("192.168.1.20", "AC:DE:48:00:11:22", "camera.home")
    assert {s.port for s in h.services} == {23, 554}


# --------------------------------------------------------------------------- Wi-Fi

PROFILE = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{name}</name><SSIDConfig><SSID><name>{name}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType><connectionMode>{mode}</connectionMode>
  <MSM><security><authEncryption><authentication>{auth}</authentication><encryption>{enc}</encryption>
  <useOneX>false</useOneX></authEncryption></security></MSM>
</WLANProfile>"""


def test_wifi_profile_parsing():
    p = wifi.parse_profile(PROFILE.format(name="Cafe", mode="auto", auth="open", enc="none"))
    assert p.weak.startswith("open") and p.connection_mode == "auto"
    assert (
        wifi.parse_profile(PROFILE.format(name="Home", mode="auto", auth="WPA3SAE", enc="AES")).weak
        is None
    )
    assert (
        "TKIP"
        in wifi.parse_profile(
            PROFILE.format(name="Old", mode="manual", auth="WPA2PSK", enc="TKIP")
        ).weak
    )


def test_wifi_check(this_pc_raw):
    _, ctx = analyze_with_context(this_pc_raw)
    ctx.facts.data["wifi"] = {
        "status": "ok",
        "value": [
            {
                "name": "VM3731498",
                "ssid": "VM3731498",
                "connection_mode": "auto",
                "weak": "TKIP (outdated encryption)",
            },
            {
                "name": "Cafe",
                "ssid": "Cafe",
                "connection_mode": "manual",
                "weak": "open (no password, no encryption)",
            },
            {"name": "Home", "ssid": "Home", "connection_mode": "auto", "weak": None},
        ],
    }
    fs = {f.id: f for f in wifi_check.run(ctx)}
    f = fs["wifi.weak_autoconnect"]
    assert f.severity == Severity.MEDIUM and f.fixes[0].params == {"profiles": ["VM3731498"]}
    spec = wifi_check.FIX_MANUAL.build(f.fixes[0].params)[0]
    assert spec.kind == "wifi.connection_mode" and spec.params["mode"] == "manual"
    # Connected to the open café network right now:
    wifi_if = NetInterface(
        index=4,
        alias="WiFi",
        kind=InterfaceKind.WIFI,
        addresses=["10.0.0.5/24"],
        network_name="Cafe",
        profile=Profile.PUBLIC,
    )
    ctx.interfaces.append(wifi_if)
    assert wifi_check.run(ctx)[-1].severity == Severity.HIGH
