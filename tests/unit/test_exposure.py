"""Table-driven tests for the firewall exposure evaluator."""

from __future__ import annotations

import pytest

from simplysec.core.exposure import evaluate, normalize_app_path, parse_ports
from simplysec.core.models import FirewallRule, Profile, Scope, Verdict
from tests.conftest import ALICE, BOB, ENV, ctx, ethernet, fw, listener, tailscale

APP = r"C:\Tools\server.exe"


def allow(**kw):
    kw.setdefault("name", "allow")
    return FirewallRule(action="allow", **kw)


def block(**kw):
    kw.setdefault("name", "block")
    return FirewallRule(action="block", **kw)


CASES = [
    # (id, rules, firewall kwargs, interface, listener kwargs, expected verdict, expected scope)
    ("no rule + default block", [], {}, ethernet(), {}, Verdict.BLOCKED, Scope.NONE),
    ("firewall off", [], {"enabled": False}, ethernet(), {}, Verdict.REACHABLE, Scope.ANYONE),
    (
        "default allow",
        [],
        {"default_block": False},
        ethernet(),
        {},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "block all inbound wins",
        [allow(application=APP)],
        {"block_all": True},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "app allow rule",
        [allow(application=APP)],
        {},
        ethernet(),
        {},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "app rule, other program",
        [allow(application=r"C:\Other\x.exe")],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "port rule",
        [allow(protocol=6, local_ports="8765")],
        {},
        ethernet(),
        {},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "port range rule",
        [allow(protocol=6, local_ports="8000-9000")],
        {},
        ethernet(),
        {},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "port rule wrong protocol",
        [allow(protocol=17, local_ports="8765")],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "LocalSubnet only",
        [allow(application=APP, remote_addresses="LocalSubnet")],
        {},
        ethernet(),
        {},
        Verdict.REACHABLE,
        Scope.LOCAL_SUBNET,
    ),
    (
        "specific address",
        [allow(application=APP, remote_addresses="10.9.9.9")],
        {},
        ethernet(),
        {},
        Verdict.REACHABLE,
        Scope.SPECIFIC,
    ),
    (
        "block overrides allow",
        [allow(application=APP), block(protocol=6, local_ports="8765")],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "blocking the LAN still leaves everyone else",
        [allow(application=APP), block(application=APP, remote_addresses="LocalSubnet")],
        {},
        ethernet(),
        {},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "block even with default allow",
        [block(application=APP)],
        {"default_block": False},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "profile mismatch (rule Private, net Public)",
        [allow(application=APP, profiles=int(Profile.PRIVATE))],
        {},
        ethernet(Profile.PUBLIC),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "profile bitmask Private+Public",
        [allow(application=APP, profiles=6)],
        {},
        ethernet(Profile.PUBLIC),
        {},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "all-profiles mask",
        [allow(application=APP, profiles=0x7FFFFFFF)],
        {},
        ethernet(Profile.DOMAIN),
        {},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "unknown profile treated as Public",
        [allow(application=APP, profiles=int(Profile.PUBLIC))],
        {},
        ethernet(None),
        {},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "disabled rule ignored",
        [allow(application=APP, enabled=False)],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "outbound rule ignored",
        [allow(application=APP, direction="out")],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "loopback listener",
        [allow(application=APP)],
        {},
        ethernet(),
        {"address": "127.0.0.1"},
        Verdict.LOCAL_ONLY,
        Scope.NONE,
    ),
    (
        "env vars in rule path",
        [allow(application=r"%ProgramFiles%\App\a.exe")],
        {},
        ethernet(),
        {"exe": r"C:\PROGRAM FILES\app\A.EXE"},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "System rule matches PID 4",
        [allow(application="System", protocol=6, local_ports="445")],
        {},
        ethernet(),
        {"pid": 4, "exe": "", "port": 445},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "System rule does not match programs",
        [allow(application="System")],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "service rule matches hosted service",
        [allow(application=r"%SystemRoot%\system32\svchost.exe", service="CDPSvc")],
        {},
        ethernet(),
        {"exe": r"C:\Windows\System32\svchost.exe", "services": ["CDPSvc"]},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "service rule, other service",
        [allow(application=r"%SystemRoot%\system32\svchost.exe", service="Spooler")],
        {},
        ethernet(),
        {"exe": r"C:\Windows\System32\svchost.exe", "services": ["CDPSvc"]},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "service '*' needs a service",
        [allow(service="*")],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "unknown services -> uncertain",
        [allow(service="CDPSvc")],
        {},
        ethernet(),
        {"services": None},
        Verdict.UNCERTAIN,
        Scope.NONE,
    ),
    (
        "RPC-EPMap keyword",
        [allow(protocol=6, local_ports="RPC-EPMap", service="RpcSs")],
        {},
        ethernet(),
        {"port": 135, "services": ["RpcSs"]},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "RPC-EPMap keyword is only 135",
        [allow(protocol=6, local_ports="RPC-EPMap")],
        {},
        ethernet(),
        {"port": 49666},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "RPC keyword: dynamic port",
        [allow(protocol=6, local_ports="RPC", service="Schedule")],
        {},
        ethernet(),
        {"port": 49666, "services": ["Schedule"]},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "RPC keyword never matches 135",
        [allow(protocol=6, local_ports="RPC")],
        {},
        ethernet(),
        {"port": 135},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "RPC keyword below dynamic range is uncertain",
        [allow(protocol=6, local_ports="RPC")],
        {},
        ethernet(),
        {"port": 5040},
        Verdict.UNCERTAIN,
        Scope.NONE,
    ),
    (
        "Ply2Disc keyword (UDP) is uncertain",
        [allow(protocol=17, local_ports="Ply2Disc")],
        {},
        ethernet(),
        {"proto": "udp", "port": 59800},
        Verdict.UNCERTAIN,
        Scope.NONE,
    ),
    (
        "trust-tuple rules never match normal traffic",
        [allow(application="System", trust_tuples=["WFDKmDriver"])],
        {},
        ethernet(),
        {"pid": 4, "exe": "", "port": 445},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "user-scoped block applies to that user",
        [allow(application=APP), block(local_user_authorized=f"O:LSD:(A;;CC;;;{BOB})")],
        {},
        ethernet(),
        {"user": BOB},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "user-scoped block skips other users",
        [allow(application=APP), block(local_user_authorized=f"O:LSD:(A;;CC;;;{BOB})")],
        {},
        ethernet(),
        {"user": ALICE},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "user-scoped block, unknown user -> uncertain",
        [allow(application=APP), block(local_user_authorized=f"O:LSD:(A;;CC;;;{BOB})")],
        {},
        ethernet(),
        {"user": None},
        Verdict.UNCERTAIN,
        Scope.NONE,
    ),
    (
        "Store-app owner rule skips normal programs",
        [allow(local_user_owner=ALICE)],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "package rule matches its AppContainer",
        [allow(local_app_package_id="S-1-15-2-9")],
        {},
        ethernet(),
        {"package": "S-1-15-2-9"},
        Verdict.UNCERTAIN,
        Scope.NONE,
    ),
    (
        "IPsec-only allow rule doesn't open it",
        [allow(application=APP, secure_flags=1)],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "local address condition",
        [allow(application=APP, local_addresses="192.168.1.10")],
        {},
        ethernet(),
        {},
        Verdict.REACHABLE,
        Scope.ANYONE,
    ),
    (
        "local address mismatch",
        [allow(application=APP, local_addresses="10.0.0.1")],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "interface type Wireless vs Ethernet",
        [allow(application=APP, interface_types="Wireless")],
        {},
        ethernet(),
        {},
        Verdict.BLOCKED,
        Scope.NONE,
    ),
    (
        "unresolved address keyword -> uncertain",
        [allow(application=APP, remote_addresses="Intranet")],
        {},
        ethernet(),
        {},
        Verdict.UNCERTAIN,
        Scope.NONE,
    ),
]


@pytest.mark.parametrize(
    ("rules", "fwkw", "iface", "lkw", "verdict", "scope"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_evaluator(rules, fwkw, iface, lkw, verdict, scope):
    exp = evaluate(listener(**lkw), fw(rules, **fwkw), ctx(iface))
    assert exp.verdict == verdict, exp.reason
    if verdict == Verdict.REACHABLE:
        assert exp.scope == scope


def test_rule_names_and_reason_are_reported():
    exp = evaluate(
        listener(), fw([allow(name="My server", application=APP)]), ctx(ethernet(Profile.PUBLIC))
    )
    assert exp.rules == ["My server"]
    assert "My server" in exp.reason and "Public" in exp.reason


def test_blocking_rule_named_in_reason():
    exp = evaluate(
        listener(),
        fw([allow(application=APP), block(name="Stop it", application=APP)]),
        ctx(ethernet()),
    )
    assert exp.verdict == Verdict.BLOCKED
    assert "Stop it" in exp.reason


def test_bound_to_one_interface_only_evaluates_that_interface():
    # Cursor-style: bound to the Tailscale address only.
    exp = evaluate(
        listener(address="100.87.181.68", port=3000),
        fw([allow(application=APP, profiles=6)]),
        ctx(ethernet(Profile.PUBLIC), tailscale()),
    )
    assert exp.verdict == Verdict.REACHABLE
    assert [ie.interface for ie in exp.per_interface] == ["Tailscale"]


def test_wildcard_listener_evaluated_per_interface_profile():
    exp = evaluate(
        listener(),
        fw([allow(application=APP, profiles=int(Profile.PRIVATE))]),
        ctx(ethernet(Profile.PUBLIC), tailscale()),
    )
    by_iface = {ie.interface: ie.verdict for ie in exp.per_interface}
    assert by_iface == {"Ethernet": Verdict.BLOCKED, "Tailscale": Verdict.REACHABLE}


def test_ipv6_listener_uses_ipv6_addresses():
    exp = evaluate(
        listener(address="::"),
        fw([allow(application=APP, remote_addresses="LocalSubnet")]),
        ctx(ethernet()),
    )
    assert exp.verdict == Verdict.REACHABLE and exp.scope == Scope.LOCAL_SUBNET


def test_never_claims_blocked_when_unsure():
    # A block rule we can't evaluate must not turn "reachable" into "blocked".
    exp = evaluate(
        listener(user=None),
        fw([allow(application=APP), block(local_user_authorized=f"O:LSD:(A;;CC;;;{BOB})")]),
        ctx(ethernet()),
    )
    assert exp.verdict == Verdict.UNCERTAIN
    assert "not reported as protected" in exp.reason


def test_parse_ports_and_paths():
    spec = parse_ports("80,443,5000-5010,RPC")
    assert spec.ranges == [(80, 80), (443, 443), (5000, 5010)] and spec.keywords == ["rpc"]
    assert parse_ports("*").any
    assert (
        normalize_app_path(r"%SystemRoot%\System32\svchost.exe", ENV)
        == r"c:\windows\system32\svchost.exe"
    )
    assert normalize_app_path("System", ENV) == "system"
