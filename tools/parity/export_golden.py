"""Export golden data from the Python v2 implementation for the C# port.

Python v2 is the reference: every C# module must reproduce these results exactly.
Run from the repo root with the v2 venv:

    .venv\\Scripts\\python tools\\parity\\export_golden.py

Nondeterminism is pinned: firewall rule ids come from a fixed token, the clock is frozen at
FROZEN_NOW and ``file_exists`` is a fixed function. The C# tests inject the same values.
Output: tests/golden/*.json.gz (gzip keeps the repository small).
"""

from __future__ import annotations

import copy
import datetime as dt
import fnmatch
import gzip
import ipaddress
import json
import random
import sys
import types
from dataclasses import replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from simplysec.core import addrset, exposure, scoring, sddl  # noqa: E402
from simplysec.core import impact as impact_mod  # noqa: E402
from simplysec.core.checks import FIXES  # noqa: E402
from simplysec.core.checks import exposure as exposure_check  # noqa: E402
from simplysec.core.checks import updates as updates_check  # noqa: E402
from simplysec.core.engine import (  # noqa: E402
    Engine,
    RawScan,
    Selection,
    analyze_with_context,
    build_plan,
)
from simplysec.core.models import (  # noqa: E402
    Finding,
    FindingStatus,
    FirewallProfileState,
    FirewallRule,
    FirewallState,
    InterfaceKind,
    Listener,
    NetInterface,
    Profile,
    Severity,
)

OUT = ROOT / "tests" / "golden"
FIXTURE = ROOT / "tests" / "fixtures" / "this_pc_raw.json"

# --------------------------------------------------------------------------- pinning

FROZEN_NOW = dt.datetime(2026, 11, 2, 12, 0, 0, tzinfo=dt.UTC)
RULE_TOKEN = "0000abcd"


class _FrozenDateTime(dt.datetime):
    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        if tz is None:
            return FROZEN_NOW.astimezone().replace(tzinfo=None)
        return FROZEN_NOW.astimezone(tz)


class _FrozenDate(dt.date):
    @classmethod
    def today(cls):  # type: ignore[override]
        return FROZEN_NOW.date()


_FROZEN_DT = types.SimpleNamespace(
    datetime=_FrozenDateTime,
    date=_FrozenDate,
    timedelta=dt.timedelta,
    timezone=dt.timezone,
    UTC=dt.UTC,
)


def pin() -> None:
    exposure_check.secrets = types.SimpleNamespace(token_hex=lambda n=4: RULE_TOKEN)
    exposure_check.dt = _FROZEN_DT
    impact_mod.dt = _FROZEN_DT
    updates_check.dt = _FROZEN_DT


def file_exists(path: str) -> bool:
    """Fixed stand-in for os.path.exists: anything not under a 'missing' folder exists."""
    return "\\missing\\" not in path.lower()


# --------------------------------------------------------------------------- output


def write(name: str, data: Any) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{name}.json.gz"
    raw = json.dumps(data, indent=None, sort_keys=False, default=str).encode("utf-8")
    with gzip.GzipFile(path, "wb", mtime=0) as fh:
        fh.write(raw)
    print(f"  {path.relative_to(ROOT)}: {len(raw) // 1024} KB")


def load_raw() -> RawScan:
    return RawScan.from_dict(json.loads(FIXTURE.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- primitives

ALICE = "S-1-5-21-1-2-3-1001"
BOB = "S-1-5-21-1-2-3-1004"
ENV = {
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
    "PROGRAMFILES": r"C:\Program Files",
    "LOCALAPPDATA": r"C:\Users\alice\AppData\Local",
    "APPDATA": r"C:\Users\alice\AppData\Roaming",
    "USERPROFILE": r"C:\Users\alice",
    "PROGRAMDATA": r"C:\ProgramData",
    "TEMP": r"C:\Users\alice\AppData\Local\Temp",
}

ADDR_TOKENS = [
    "10.0.0.1",
    "10.0.0.0/8",
    "192.168.1.0/24",
    "192.168.1.77/24",
    "192.168.0.0/255.255.0.0",
    "10.0.0.0/0.0.0.255",
    "10.0.0.1-10.0.0.50",
    "10.0.0.50-10.0.0.1",
    "0.0.0.0-126.255.255.255",
    "128.0.0.0-255.255.255.255",
    "0.0.0.0",
    "255.255.255.255",
    "0.0.0.0/0",
    "127.0.0.1",
    "100.64.0.0/10",
    "fe80::/64",
    "fe80::1%12",
    "::1",
    "::",
    "::/0",
    "2001:db8::/32",
    "2001:db8::1-2001:db8::ff",
    "::ffff:1.2.3.4",
    "::ffff:0:0/96",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fd00::/8",
    "1.2.3",
    "01.2.3.4",
    "256.1.1.1",
    "10.0.0.1/33",
    "10.0.0.1/024",
    "1.2.3.4-::1",
    "LocalSubnet",
    "",
    " 10.1.2.3 ",
    "fe80::/ffff::",
    "10.0.0.0/ 8",
    "2001:db8::/129",
]


def _iv(s: addrset.AddrSet) -> dict[str, Any]:
    return {"family": s.family, "intervals": [[str(lo), str(hi)] for lo, hi in s.intervals]}


def _rand_set(rng: random.Random, fam: int) -> addrset.AddrSet:
    mx = addrset.MAX[fam]
    ivs = []
    for _ in range(rng.randint(0, 4)):
        kind = rng.random()
        if kind < 0.15:
            lo = 0
        elif kind < 0.3:
            lo = mx - rng.randint(0, 300)
        else:
            lo = rng.randint(0, mx)
        hi = min(mx, lo + rng.choice([0, 1, 2, 255, 256, 65535, rng.randint(0, mx // 7)]))
        ivs.append((lo, hi))
    if rng.random() < 0.05:
        ivs.append((0, mx))
    return addrset.AddrSet(fam, ivs)


def export_primitives() -> None:
    rng = random.Random(1234)
    sets = []
    for i in range(600):
        fam = 4 if i % 2 == 0 else 6
        a, b = _rand_set(rng, fam), _rand_set(rng, fam)
        probes = []
        for _ in range(4):
            v = rng.choice(
                [0, addrset.MAX[fam], rng.randint(0, addrset.MAX[fam])]
                + [lo for lo, _ in a.intervals]
                + [hi for _, hi in a.intervals]
            )
            ip = str(ipaddress.IPv4Address(v) if fam == 4 else ipaddress.IPv6Address(v))
            probes.append({"ip": ip, "in": a.contains_ip(ip)})
        sets.append(
            {
                "a": _iv(a),
                "b": _iv(b),
                "union": _iv(a.union(b)),
                "subtract": _iv(a.subtract(b)),
                "intersect": _iv(a.intersect(b)),
                "a_empty": a.is_empty(),
                "a_everything": a.is_everything(),
                "a_subset_b": a.issubset(b),
                "a_describe": a.describe(),
                "a_describe_2": a.describe(limit=2),
                "probes": probes,
            }
        )
    literals = [
        {"token": t, "result": (None if (r := addrset.parse_literal(t)) is None else _iv(r))}
        for t in ADDR_TOKENS
    ]
    for t in ADDR_TOKENS:
        if "/" in t or "-" in t:
            continue
        r = addrset.parse_literal(t)
        if r is not None:
            literals.append(
                {"token": t, "describe": r.describe(), "result": _iv(r)}
            )

    ip_info = []
    for t in [x for x in ADDR_TOKENS if "/" not in x and "-" not in x] + [
        "192.168.1.1",
        "172.16.0.1",
        "172.32.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "8.8.8.8",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "::ffff:192.168.1.1",
        "0.0.0.0",
        "192.0.0.8",
        "198.18.0.1",
        "240.0.0.1",
        "64:ff9b::1",
        "2001:10::1",
        "2002::1",
        "1:0:0:0:1:0:0:0",
        "1:0:0:1:0:0:0:1",
        "0:0:0:0:0:0:0:1",
        "1:2:3:4:5:6:7:8",
        "1::",
        "abcd:ef01:2345:6789:abcd:ef01:2345:6789",
        "224.0.0.1",
    ]:
        try:
            ip = ipaddress.ip_address(t.split("%")[0])
        except ValueError:
            ip_info.append({"text": t, "valid": False})
            continue
        ip_info.append(
            {
                "text": t,
                "valid": True,
                "version": ip.version,
                "value": str(int(ip)),
                "str": str(ip),
                "is_private": ip.is_private,
                "is_loopback": ip.is_loopback,
                "is_link_local": ip.is_link_local,
            }
        )
    iface_info = []
    for t in [
        "192.168.1.71/24",
        "10.1.2.3/8",
        "100.87.181.68/32",
        "fe80::1/64",
        "2001:db8::5/48",
        "192.168.1.5/255.255.255.0",
        "192.168.1.5",
        "fe80::1%12/64",
        "bogus",
        "10.0.0.1/33",
        "::1/128",
    ]:
        try:
            ii = ipaddress.ip_interface(t.split("%")[0])
        except ValueError:
            iface_info.append({"text": t, "valid": False})
            continue
        iface_info.append(
            {
                "text": t,
                "valid": True,
                "version": ii.version,
                "ip": str(ii.ip),
                "network": _iv(addrset.AddrSet.from_network(ii.network)),
                "network_str": str(ii.network),
            }
        )

    sddl_cases = []
    sddls = [
        "",
        "O:LSD:(A;;CC;;;S-1-5-21-1-2-3-1001)",
        "O:LSD:(A;;CC;;;s-1-5-21-1-2-3-1004)",
        "D:(A;;CC;;;WD)",
        "D:(A;;CC;;;AU)",
        "D:(A;;CC;;;BU)",
        "D:(A;;CC;;;BA)(D;;CC;;;S-1-5-21-1-2-3-1001)",
        "D:(D;;CC;;;S-1-5-21-1-2-3-1001)(A;;CC;;;AU)",
        "D:(A;;CC;;;IU)",
        "D:(A;;CC;;;AC)",
        "D:(A;;CC;;;SY)(A;;CC;;;LS)(A;;CC;;;NS)",
        "D:(A;;CC;;)",
        "(A;;CC;;;S-1-5-21-1-2-3-1001)",
        "O:SYG:SYD:(A;;CC;;; S-1-5-21-1-2-3-1004 )",
        "D:(a;;CC;;;S-1-5-21-1-2-3-1001)(d;;CC;;;BG)",
        "D:(XA;;CC;;;S-1-5-21-1-2-3-1001;(x))",
    ]
    for s in sddls:
        cond = sddl.parse_user_condition(s)
        for sid in [ALICE, BOB, None, "S-1-5-18", ALICE.lower(), "S-1-5-32-544"]:
            sddl_cases.append(
                {
                    "sddl": s,
                    "sid": sid,
                    "allow": sorted(cond.allow),
                    "deny": sorted(cond.deny),
                    "decide": cond.decide(sid),
                }
            )

    port_specs = [
        "",
        "*",
        "80",
        "80,443",
        "8000-9000",
        " 80 , 443 ",
        "RPC",
        "RPC-EPMap,135",
        "IPHTTPS",
        "Teredo",
        "Ply2Disc",
        "mDNS",
        "*,80",
        "80-",
        "abc",
        ",,",
        "49152-65535",
        "5353,RPC",
    ]
    ports = []
    for spec in port_specs:
        p = exposure.parse_ports(spec)
        ports.append(
            {"spec": spec, "any": p.any, "ranges": [list(r) for r in p.ranges], "keywords": p.keywords}
        )

    paths = []
    for p in [
        "",
        "  ",
        "System",
        "SYSTEM",
        r"C:\Tools\server.exe",
        r'"C:\Tools\server.exe"',
        r"c:/tools/./server.exe",
        r"C:\Tools\..\Tools\server.exe",
        r"%ProgramFiles%\App\app.exe",
        r"%programfiles%\App\app.exe",
        r"%UNKNOWN%\x.exe",
        r"%SystemRoot%\system32\svchost.exe",
        r"\??\C:\Windows\x.exe",
        r"C:\a\\b\\\c.exe",
        r"C:\a\b\..\..\..\c.exe",
        r"\\server\share\x.exe",
        r"x.exe",
        r"C:",
        r"C:\\",
        r"%TEMP%\..\y.exe",
        r"C:\Ünïcode\Prog.EXE",
        r"%A%B%",
        r"C:\trailing\.",
        r"C:\trailing\\",
        r"/forward/slash.exe",
        r"\\?\C:\long\path.exe",
    ]:
        paths.append({"path": p, "result": exposure.normalize_app_path(p, ENV)})

    titles = [
        {"text": t, "title": t.title()}
        for t in ["critical", "HIGH", "local_only", "domain", "hello world", "o'neil", "a1b2", ""]
    ]
    fn = []
    names = [
        "SimpleSec-Block-80",
        "x-simplesec",
        "blockport139-tcp-in",
        "restrictport5985",
        "simplesec-winrm-5985-allowlocal",
        "simplesec",
        "other",
        "blockpor",
        "[x]",
        "a?b",
    ]
    pats = ["simplesec-*", "*-simplesec", "blockport*", "restrictport*", "simplesec-winrm-*-allowlocal", "a?b", "[x]", "*"]
    for n in names:
        for p in pats:
            fn.append({"name": n, "pattern": p, "match": fnmatch.fnmatchcase(n, p)})

    # scoring
    sev_table = []
    for base in Severity:
        for width in range(0, 7):
            for unsigned in (False, True):
                for writable in (False, True):
                    for configured in (False, True):
                        sev_table.append(
                            {
                                "base": base.name.lower(),
                                "width": width,
                                "unsigned": unsigned,
                                "user_writable": writable,
                                "user_configured": configured,
                                "result": scoring.exposure_severity(
                                    base,
                                    width,
                                    unsigned=unsigned,
                                    user_writable=writable,
                                    user_configured=configured,
                                ).name.lower(),
                            }
                        )
    grades = []
    for _ in range(400):
        fs = []
        for i in range(rng.randint(0, 12)):
            fs.append(
                Finding(
                    id=f"f{i}",
                    check="c",
                    area="a",
                    title="t",
                    severity=rng.choice(list(Severity)),
                    what_it_means="",
                    status=rng.choice(list(FindingStatus)),
                )
            )
        value = scoring.score(fs)
        grades.append(
            {
                "findings": [
                    {"severity": f.severity.name.lower(), "status": f.status.value} for f in fs
                ],
                "score": value,
                "grade": scoring.grade(value, fs),
            }
        )
    for v in range(0, 101):
        grades.append({"findings": [], "score": v, "grade": scoring.grade(v, [])})

    write(
        "primitives",
        {
            "addrsets": sets,
            "literals": literals,
            "ip_info": ip_info,
            "iface_info": iface_info,
            "sddl": sddl_cases,
            "ports": ports,
            "paths": {"env": ENV, "cases": paths},
            "titles": titles,
            "fnmatch": fn,
            "exposure_severity": sev_table,
            "grades": grades,
        },
    )


# --------------------------------------------------------------------------- exposure


def _iface(rng: random.Random, n: int) -> NetInterface:
    t = rng.choice(["ethernet", "ethernet", "wifi", "vpn", "virtual", "other"])
    profile = rng.choice([Profile.PRIVATE, Profile.PUBLIC, Profile.DOMAIN, None])
    if t == "ethernet":
        addrs = [rng.choice(["192.168.1.10/24", "10.0.0.5/16", "172.16.4.2/12"]), "fe80::1/64"]
        if rng.random() < 0.3:
            addrs.append("2001:db8:1::10/64")
        return NetInterface(
            index=n,
            alias=rng.choice(["Ethernet", "Ethernet 2"]),
            description="Intel(R) Ethernet",
            kind=InterfaceKind.ETHERNET,
            up=rng.random() < 0.9,
            addresses=addrs,
            profile=profile,
            gateways=rng.choice([["192.168.1.1"], [], ["10.0.0.1", "fe80::1"]]),
            dns_servers=rng.choice([["192.168.1.1"], [], ["8.8.8.8"]]),
            dhcp_servers=rng.choice([["192.168.1.1"], []]),
        )
    if t == "wifi":
        return NetInterface(
            index=n,
            alias="WiFi",
            description="Wireless",
            kind=InterfaceKind.WIFI,
            up=rng.random() < 0.9,
            addresses=["192.168.1.20/24", "fe80::2/64"],
            profile=profile,
            network_name="Home",
            gateways=["192.168.1.1"],
        )
    if t == "vpn":
        return NetInterface(
            index=n,
            alias="Tailscale",
            kind=InterfaceKind.VPN,
            addresses=["100.87.181.68/32", "fd7a:115c:a1e0::1/128"],
            profile=Profile.PRIVATE,
        )
    if t == "virtual":
        return NetInterface(
            index=n,
            alias="VMnet8",
            description="VMware Virtual Ethernet Adapter",
            kind=InterfaceKind.VIRTUAL,
            addresses=["192.168.56.1/24"],
            profile=profile,
        )
    return NetInterface(
        index=n,
        alias="Other",
        kind=InterfaceKind.OTHER,
        addresses=["10.9.0.2/30"],
        profile=profile,
    )


APP = r"C:\Tools\server.exe"


def _rule(rng: random.Random, i: int) -> FirewallRule:
    return FirewallRule(
        name=f"rule {i % 5}",
        action=rng.choice(["allow", "allow", "block"]),
        direction="in" if rng.random() < 0.92 else "out",
        enabled=rng.random() < 0.95,
        protocol=rng.choice([256, 256, 6, 6, 17, 1]),
        local_ports=rng.choice(
            ["*", "*", "8765", "8000-9000", "80,443", "RPC", "RPC-EPMap", "IPHTTPS", "Teredo",
             "Ply2Disc", "mDNS", "135", "5353", "49152-65535", "weird", "445,139"]
        ),
        remote_ports=rng.choice(["*", "*", "*", "1234"]),
        local_addresses=rng.choice(
            ["*", "*", "*", "LocalSubnet", "192.168.1.10", "10.0.0.0/8", "Intranet", "fe80::1"]
        ),
        remote_addresses=rng.choice(
            ["*", "*", "LocalSubnet", "10.9.9.9", "192.168.1.0/24", "192.168.0.0/255.255.0.0",
             "10.0.0.1-10.0.0.50", "Internet", "Intranet", "DNS", "DHCP", "DefaultGateway",
             "LocalSubnet,10.1.1.1", "fe80::/64", "::1", "2001:db8::/32",
             "0.0.0.0-126.255.255.255", "127.0.0.1", "128.0.0.0-255.255.255.255",
             "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255"]
        ),
        application=rng.choice(
            ["", "", APP, r"C:\Other\x.exe", r"%ProgramFiles%\x\y.exe", "System",
             '"C:\\Tools\\server.exe"', "c:/tools/./server.exe", r"C:\Tools\..\Tools\server.exe"]
        ),
        service=rng.choice(["", "", "", "*", "svc1", "SVC2"]),
        profiles=rng.choice([0x7FFFFFFF, 0x7FFFFFFF, 1, 2, 4, 3, 6, 7, 0]),
        interface_types=rng.choice(["All", "All", "Lan", "Wireless", "RemoteAccess", "Lan,Wireless", ""]),
        interfaces=rng.choice([[], [], [], ["Ethernet"], ["Other"], ["intel(r) ethernet"]]),
        edge_traversal=rng.random() < 0.1,
        edge_traversal_options=rng.choice([0, 0, 0, 1, 2]),
        local_user_authorized=rng.choice(
            ["", "", "", f"O:LSD:(A;;CC;;;{ALICE})", f"O:LSD:(A;;CC;;;{BOB})", "D:(A;;CC;;;WD)",
             "D:(A;;CC;;;BU)", f"D:(D;;CC;;;{ALICE})(A;;CC;;;AU)"]
        ),
        local_user_owner=rng.choice(["", "", "", ALICE, BOB]),
        local_app_package_id=rng.choice(["", "", "", "S-1-15-2-1", "S-1-15-2-123"]),
        remote_user_authorized=rng.choice(["", "", "", "", "O:LSD:(A;;CC;;;AU)"]),
        secure_flags=rng.choice([0, 0, 0, 0, 1]),
        trust_tuples=rng.choice([[], [], [], [], ["UPnP"]]),
    )


def _listener(rng: random.Random) -> Listener:
    exe = rng.choice([APP, APP, "", r"C:\Other\x.exe", r"c:\tools\server.exe", r"C:\Program Files\x\y.exe"])
    pid = rng.choice([1234, 1234, 4, 0])
    return Listener(
        protocol=rng.choice(["tcp", "tcp", "udp"]),
        address=rng.choice(
            ["0.0.0.0", "0.0.0.0", "::", "127.0.0.1", "::1", "192.168.1.10", "100.87.181.68",
             "10.0.0.5", "fe80::1", "192.168.56.1", "8.8.8.8", ""]
        ),
        port=rng.choice([8765, 135, 445, 443, 5353, 50000, 3389, 137, 139]),
        pid=pid,
        process=exe.rsplit("\\", 1)[-1] if exe else ("System" if pid == 4 else ""),
        exe=exe,
        services=rng.choice([[], [], None, ["svc1"], ["Svc2", "x"]]),
        user_sid=rng.choice([ALICE, ALICE, BOB, None, "S-1-5-18"]),
        package_sid=rng.choice(["", "", "", None, "S-1-15-2-123"]),
    )


def _fw(rng: random.Random, rules: list[FirewallRule]) -> FirewallState:
    profiles = {}
    for p in (Profile.DOMAIN, Profile.PRIVATE, Profile.PUBLIC):
        if rng.random() < 0.03:
            continue  # unreadable profile
        profiles[p] = FirewallProfileState(
            p,
            enabled=rng.random() < 0.9,
            default_inbound_block=rng.random() < 0.85,
            block_all_inbound=rng.random() < 0.05,
        )
    return FirewallState(profiles=profiles, rules=rules)


def export_exposure() -> None:
    import tests.unit.test_exposure as tx  # the hand-written table

    cases = []

    def add(name: str, rules, fw: FirewallState, ifaces, lst: Listener, env=ENV) -> None:
        ctx = exposure.EvalContext(interfaces=list(ifaces), env=env)
        result = exposure.evaluate(lst, fw, ctx)
        cases.append(
            {
                "name": name,
                "interfaces": [i.to_dict() for i in ifaces],
                "env": env,
                "firewall": fw.to_dict(),
                "listener": lst.to_dict(),
                "result": result.to_dict(),
                "rules": result.rules,
            }
        )

    from tests.conftest import fw as fw_builder
    from tests.conftest import listener as lst_builder

    for case in tx.CASES:
        name, rules, fw_kw, iface, lst_kw, _v, _s = case
        add(f"table: {name}", rules, fw_builder(rules, **fw_kw), [iface], lst_builder(**lst_kw))

    rng = random.Random(4321)
    for n in range(2500):
        ifaces = [_iface(rng, k) for k in range(rng.randint(1, 3))]
        rules = [_rule(rng, i) for i in range(rng.randint(0, 8))]
        add(f"random {n}", rules, _fw(rng, rules), ifaces, _listener(rng))

    write("exposure_cases", cases)

    raw = load_raw()
    env = {k.upper(): v for k, v in raw.env.items()}
    ctx = exposure.EvalContext(interfaces=raw.interfaces, env=env)
    write(
        "exposure_fixture",
        [e.to_dict() for e in exposure.evaluate_all(raw.listeners, raw.firewall, ctx)],
    )


# --------------------------------------------------------------------------- scenarios


def _with_facts(raw: RawScan, **changes: Any) -> RawScan:
    facts = copy.deepcopy(raw.facts)
    for name, value in changes.items():
        if value is None:
            facts[name] = {"status": "needs_admin", "error": "Access is denied."}
        else:
            facts[name]["value"].update(value)
    return replace(raw, facts=facts)


USAGE_BASE = {
    "connections": [],
    "remote_session": False,
    "rdp_sessions": [],
    "msra_running": False,
    "mappings": [],
    "printers": [],
    "smb_sessions": [],
    "smb_sessions_status": "needs_admin",
    "last_logons": [],
}

WIFI = [
    {
        "name": "VM3731498",
        "ssid": "VM3731498",
        "connection_mode": "auto",
        "authentication": "WPA2PSK",
        "encryption": "TKIP",
        "weak": "TKIP (outdated encryption)",
    },
    {
        "name": "Cafe",
        "ssid": "Cafe",
        "connection_mode": "manual",
        "authentication": "open",
        "encryption": "none",
        "weak": "open (no password, no encryption)",
    },
    {
        "name": "Home",
        "ssid": "Home",
        "connection_mode": "auto",
        "authentication": "WPA2PSK",
        "encryption": "AES",
        "weak": None,
    },
]


def _usage(raw: RawScan, **usage: Any) -> RawScan:
    raw = copy.deepcopy(raw)
    base = copy.deepcopy(USAGE_BASE)
    base.update(usage)
    raw.facts["usage"] = {"status": "ok", "value": base}
    raw.facts["wifi"] = {"status": "ok", "value": copy.deepcopy(WIFI)}
    return raw


def _fw_edit(raw: RawScan, fn) -> RawScan:
    fw = copy.deepcopy(raw.firewall)
    fn(fw)
    return replace(raw, firewall=fw)


def _iface_edit(raw: RawScan, fn) -> RawScan:
    ifaces = copy.deepcopy(raw.interfaces)
    fn(ifaces)
    return replace(raw, interfaces=ifaces)


def scenarios() -> list[tuple[str, RawScan, dict[str, int], Any]]:
    raw = load_raw()
    out: list[tuple[str, RawScan, dict[str, int], Any]] = []

    def add(name: str, r: RawScan, accepted: dict[str, int] | None = None, fe: Any = file_exists):
        out.append((name, r, accepted or {}, fe))

    add("baseline", raw)
    full = _usage(raw)
    add("usage_wifi", full)
    spotify = next(
        x for x in raw.listeners if x.process == "SpotifyLauncher.exe" and x.protocol == "tcp"
    )
    busy = _usage(
        raw,
        connections=[
            {
                "protocol": "tcp",
                "local_port": spotify.port,
                "local_ip": "192.168.1.71",
                "remote_ip": "192.168.1.40",
                "pid": spotify.pid,
                "process": spotify.process,
            },
            {
                "protocol": "tcp",
                "local_port": 445,
                "local_ip": "192.168.1.71",
                "remote_ip": "192.168.1.41",
                "pid": 4,
                "process": "System",
            },
        ],
        remote_session=True,
        rdp_sessions=[{"session": 2, "station": "RDP-Tcp#0"}],
        msra_running=True,
        mappings=[{"local": "Z:", "remote": r"\\NAS\share", "status": "OK"}],
        printers=[{"name": "Office", "port": r"\\PRINTSRV\Office", "computer": "PRINTSRV"}],
        smb_sessions=[{"client": "192.168.1.50", "user": "bob", "dialect": "1.5"}],
        smb_sessions_status="ok",
        last_logons=[
            {"sid": "S-1-5-21-1-2-3-501", "last": "2026-10-20T10:00:00.0000000Z"},
        ],
    )
    add("usage_busy", busy)
    add("usage_busy_smb1_rdp", _with_facts(busy, smb={"smb1": True}, rdp={"deny": 0, "nla": 0}))

    for p in (Profile.DOMAIN, Profile.PRIVATE, Profile.PUBLIC):
        add(f"fw_off_{p.name.lower()}", _fw_edit(full, lambda fw, p=p: setattr(fw.profiles[p], "enabled", False)))
        add(
            f"fw_default_allow_{p.name.lower()}",
            _fw_edit(full, lambda fw, p=p: setattr(fw.profiles[p], "default_inbound_block", False)),
        )
    add("fw_block_all_public", _fw_edit(full, lambda fw: setattr(fw.profiles[Profile.PUBLIC], "block_all_inbound", True)))

    def managed(fw: FirewallState) -> None:
        fw.profiles[Profile.PUBLIC].enabled = False
        fw.managed_by_policy = True

    add("fw_managed", _fw_edit(full, managed))
    add("fw_profile_missing", _fw_edit(full, lambda fw: fw.profiles.pop(Profile.PUBLIC)))

    def eth(profile):
        def fn(ifaces):
            for i in ifaces:
                if i.alias == "Ethernet":
                    i.profile = profile

        return fn

    add("ethernet_private", _iface_edit(full, eth(Profile.PRIVATE)))
    add("ethernet_no_profile", _iface_edit(full, eth(None)))
    add("ethernet_domain", _iface_edit(full, eth(Profile.DOMAIN)))

    def wifi_cafe(ifaces):
        for i in ifaces:
            if i.kind == InterfaceKind.WIFI:
                i.up = True
                i.network_name = "Cafe"
                i.addresses = ["10.0.0.5/24"]
                i.profile = Profile.PUBLIC

    add("wifi_connected_cafe", _iface_edit(full, wifi_cafe))

    add("rdp_on_no_nla", _with_facts(full, rdp={"deny": 0, "nla": 0}))
    add("rdp_policy_wins", _with_facts(full, rdp={"deny": 0, "deny_policy": 1}))
    add(
        "rdp_on_fw_off",
        _fw_edit(
            _with_facts(full, rdp={"deny": 0, "nla": 1}),
            lambda fw: setattr(fw.profiles[Profile.PUBLIC], "enabled", False),
        ),
    )
    r = _with_facts(full, smb={"smb1": True}, uac={"enable_lua": 0}, accounts={"limit_blank_password_use": 0})
    for u in r.facts["accounts"]["value"]["users"]:
        if u["sid"].endswith("-501"):
            u["enabled"] = True
    add("smb1_guest_uac_blank", r)
    add("uac_no_prompt", _with_facts(full, uac={"enable_lua": 1, "consent_admin": 0}))

    r = copy.deepcopy(full)
    r.facts["antivirus"]["value"] = [{"name": "Windows Defender", "state": 0x060100}]
    r.facts["defender"]["value"]["antivirus"] = False
    add("no_antivirus", r)
    r = copy.deepcopy(full)
    r.facts["antivirus"]["value"] = [
        {"name": "Windows Defender", "state": 0x061100, "exe": "windowsdefender://"},
        {"name": "Other AV", "state": 0x041010, "exe": r"C:\Other\av.exe"},
    ]
    add("two_antivirus", r)
    r = copy.deepcopy(full)
    r.facts["antivirus"]["value"] = {}
    add("antivirus_empty", r)
    add(
        "defender_old_realtime_off",
        _with_facts(full, defender={"signature_age_days": 20, "realtime": False, "tamper": False}),
    )
    add("cfa_on", _with_facts(full, defender_prefs={"controlled_folder_access": 1}))
    add("cfa_audit", _with_facts(full, defender_prefs={"controlled_folder_access": 2}))
    for days in (10, 35, 60, 400):
        last = (FROZEN_NOW - dt.timedelta(days=days)).isoformat()
        add(f"updates_{days}d", _with_facts(full, updates={"last_history_install": last, "last_hotfix": last}))
    add(
        "updates_paused_reboot",
        _with_facts(
            full,
            updates={
                "pause": {"updates": "2026-12-01T00:00:00Z", "quality": None, "feature": None},
                "reboot_pending": True,
            },
        ),
    )
    add("updates_unknown", _with_facts(full, updates={"last_history_install": None, "last_hotfix": None}))
    add("bitlocker_laptop", _with_facts(full, system={"chassis": [10], "has_battery": True}))
    add("bitlocker_on", _with_facts(full, bitlocker={"protection": 1}))
    add("autorun_on", _with_facts(full, autorun={"hklm": None, "hkcu": None, "no_autorun_hklm": None}))
    add("autorun_255", _with_facts(full, autorun={"hklm": 255}))
    add("llmnr_policy_off", _with_facts(full, llmnr={"enable_multicast_policy": 0}))
    r = copy.deepcopy(full)
    r.facts["shares"] = {
        "status": "ok",
        "value": [
            {
                "name": "Public",
                "path": r"C:\Public",
                "access": [{"account": "Everyone", "sid": "S-1-1-0", "right": 0, "allow": True}],
            },
            {
                "name": "Docs",
                "path": r"C:\Docs",
                "access": [{"account": "Everyone", "sid": "S-1-1-0", "right": 2, "allow": True}],
            },
        ],
    }
    add("shares_everyone", r)
    r = copy.deepcopy(full)
    r.facts["shares"] = {
        "status": "ok",
        "value": {
            "name": "Single",
            "path": r"C:\S",
            "access": {"account": "Everyone", "sid": "S-1-1-0", "right": 1, "allow": True},
        },
    }
    add("shares_single_object", r)

    def v1_rules(fw: FirewallState) -> None:
        fw.rules.append(
            FirewallRule(
                name="SimpleSec-WinRM-5985-AllowLocal",
                action="allow",
                protocol=6,
                local_ports="5985",
                remote_addresses="LocalSubnet",
            )
        )
        fw.rules.append(
            FirewallRule(name="BlockPort139-TCP-in", action="block", protocol=6, local_ports="139")
        )

    add("v1_rules", _fw_edit(full, v1_rules))

    def sec_rules(fw: FirewallState) -> None:
        fw.rules.append(
            FirewallRule(
                name="SimplySec:block_program:1234abcd",
                action="block",
                application=r"C:\Program Files\x\y.exe",
                grouping="SimplySec",
            )
        )

    add("simplysec_rule_present", _fw_edit(full, sec_rules))
    add("admin", replace(full, is_admin=True))
    add("files_missing", full, fe=lambda p: False)
    add("errors", replace(full, errors=["listeners: boom", "firewall: bang"]))

    base_result, _ = analyze_with_context(full, file_exists=file_exists)
    keep_all = {f.keep_key: 0 for f in base_result.findings if f.keep_key}
    keep_wide = {f.keep_key: 99 for f in base_result.findings if f.keep_key}
    add("keep_narrow", full, keep_all)
    add("keep_wide", full, keep_wide)

    fact_names = [k for k in full.facts if k != "collected"]
    for name in fact_names:
        add(f"fact_{name}_needs_admin", _with_facts(full, **{name: None}))
        r = copy.deepcopy(full)
        r.facts[name] = {"status": "error", "error": f"{name} broke"}
        add(f"fact_{name}_error", r)
        r = copy.deepcopy(full)
        del r.facts[name]
        add(f"fact_{name}_missing", r)

    def no_listeners(r: RawScan) -> RawScan:
        return replace(r, listeners=[])

    add("no_listeners", no_listeners(full))

    def kitchen_sink(fw: FirewallState) -> None:
        fw.rules.append(FirewallRule(name="Open everything", action="allow", edge_traversal=True))

    add("edge_traversal_everything", _fw_edit(full, kitchen_sink))
    return out


def _warning(w: Any) -> dict[str, Any]:
    return {
        "text": w.text,
        "offer_fix": w.offer_fix,
        "offer_params": w.offer_params,
        "offer_label": w.offer_label,
    }


def _plan(plan: Any) -> dict[str, Any]:
    return {
        "items": [
            {
                "fix_id": i.fix.id,
                "params": i.params,
                "finding_id": i.finding_id,
                "specs": [s.to_dict() for s in i.specs],
                "warnings": [_warning(w) for w in i.warnings],
                "impact": i.impact.to_dict() if i.impact else None,
            }
            for i in plan.items
        ],
        "refused": plan.refused,
        "might_break": plan.might_break,
        "touches_firewall": plan.touches_firewall,
    }


def raw_patch(base: dict[str, Any], cur: dict[str, Any]) -> dict[str, Any]:
    """Two-level diff of a RawScan dict against the fixture: {"set": {...}, "facts": {...},
    "facts_removed": [...], "firewall": {...}}. Applied in order by the C# tests."""
    patch: dict[str, Any] = {"set": {}, "facts": {}, "facts_removed": [], "firewall": {}}
    for key, value in cur.items():
        if key == "facts":
            for fk, fv in value.items():
                if base["facts"].get(fk) != fv:
                    patch["facts"][fk] = fv
            patch["facts_removed"] = [k for k in base["facts"] if k not in value]
        elif key == "firewall":
            for fk, fv in value.items():
                if base["firewall"].get(fk) != fv:
                    patch["firewall"][fk] = fv
        elif base.get(key) != value:
            patch["set"][key] = value
    return patch


def export_analysis() -> None:
    engine = Engine(collector=lambda progress=None: None, is_admin=lambda: False, backups_dir=OUT)
    raw = load_raw()
    base_dict = raw.to_dict()
    write("rawscan_roundtrip", base_dict)
    analyses = []
    plans = []
    for name, r, accepted, fe in scenarios():
        result, ctx = analyze_with_context(r, accepted=accepted, file_exists=fe)
        d = result.to_dict(include_facts=False)
        analyses.append(
            {
                "name": name,
                "raw_patch": raw_patch(base_dict, r.to_dict()),
                "accepted": accepted,
                "files_missing": name == "files_missing",
                "result": d,
            }
        )
        sels, skipped = engine.recommended_split(result)
        items = []
        for f in result.findings:
            for opt in f.fixes:
                plan = build_plan([Selection(opt.fix_id, opt.params, f.id)], ctx)
                items.append({"finding_id": f.id, "fix_id": opt.fix_id, "plan": _plan(plan)})
        extra = [
            Selection("no.such_fix", {}, None),
            Selection("sharing.review", {}, None),
            Selection("network.mark_private", {"index": 9, "alias": "Ethernet", "name": "EE-G9QKJQ"}, None),
            Selection("exposure.block_program_public", {"exe": r"C:\x\a.exe", "label": "A"}, None),
        ]
        plans.append(
            {
                "name": name,
                "per_option": items,
                "extra": _plan(build_plan(extra, ctx)),
                "extra_no_ctx": _plan(build_plan(extra[:2], None)),
                "recommended": [
                    {"fix_id": s.fix_id, "params": s.params, "finding_id": s.finding_id} for s in sels
                ],
                "skipped": [list(x) for x in skipped],
            }
        )
    write("analyze", analyses)
    write("plans", plans)


def main() -> None:
    pin()
    print("Exporting golden data from Python v2 …")
    export_primitives()
    export_exposure()
    export_analysis()
    print("done")


if __name__ == "__main__":
    main()
