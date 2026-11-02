"""Address sets, SDDL, scoring, history comparisons and serialisation."""

from __future__ import annotations

import ipaddress

from simplysec.core.addrset import AddrSet, parse_literal
from simplysec.core.checks.exposure import is_user_writable, user_configured
from simplysec.core.engine import ScanResult, analyze
from simplysec.core.history import History, compare
from simplysec.core.knowledge import load
from simplysec.core.models import Finding, FindingStatus, Severity
from simplysec.core.scoring import (
    WIDTH_PRIVATE_ANY,
    WIDTH_PUBLIC_ANY,
    WIDTH_VPN,
    exposure_severity,
    grade,
    score,
)
from simplysec.core.sddl import parse_user_condition


def test_addrset_algebra():
    everything = AddrSet.everything(4)
    lan = AddrSet.from_network(ipaddress.ip_network("192.168.1.0/24"))
    rest = everything.subtract(lan)
    assert not rest.contains_ip("192.168.1.5") and rest.contains_ip("8.8.8.8")
    assert rest.union(lan).is_everything()
    assert lan.issubset(everything) and not everything.issubset(lan)
    assert parse_literal("10.0.0.0/255.0.0.0") == AddrSet.from_network(
        ipaddress.ip_network("10.0.0.0/8")
    )
    assert parse_literal("1.1.1.1-1.1.1.9").contains_ip("1.1.1.5")
    assert parse_literal("LocalSubnet") is None
    codex = parse_literal("0.0.0.0-126.255.255.255").union(
        parse_literal("128.0.0.0-255.255.255.255")
    )
    assert everything.subtract(codex) == AddrSet.loopback(4)


def test_sddl_condition():
    cond = parse_user_condition("O:LSD:(A;;CC;;;S-1-5-21-1-1004)(D;;CC;;;S-1-5-21-1-1005)")
    assert cond.decide("S-1-5-21-1-1004") is True
    assert cond.decide("S-1-5-21-1-1005") is False
    assert cond.decide("S-1-5-21-1-1001") is False
    assert cond.decide(None) is None
    assert parse_user_condition("D:(A;;CC;;;WD)").decide("S-1-5-21-9") is True
    assert parse_user_condition("D:(A;;CC;;;BA)").decide("S-1-5-21-9") is None


def test_exposure_severity_weighting():
    assert exposure_severity(Severity.HIGH, WIDTH_PUBLIC_ANY) == Severity.HIGH
    assert exposure_severity(Severity.HIGH, WIDTH_PRIVATE_ANY) == Severity.MEDIUM
    assert exposure_severity(Severity.HIGH, WIDTH_VPN) == Severity.LOW
    assert (
        exposure_severity(Severity.MEDIUM, WIDTH_PUBLIC_ANY, unsigned=True, user_writable=True)
        == Severity.CRITICAL
    )
    assert (
        exposure_severity(Severity.MEDIUM, WIDTH_PUBLIC_ANY, user_configured=True) == Severity.LOW
    )
    assert (
        exposure_severity(Severity.MEDIUM, WIDTH_PRIVATE_ANY, user_configured=True) == Severity.INFO
    )
    assert exposure_severity(Severity.INFO, WIDTH_PUBLIC_ANY, unsigned=True) == Severity.INFO


def _f(sev, status=FindingStatus.OPEN):
    return Finding("x", "c", "a", "t", sev, "w", status=status)


def test_score_and_grade():
    assert score([]) == 100
    assert (
        score([_f(Severity.CRITICAL), _f(Severity.HIGH), _f(Severity.MEDIUM), _f(Severity.LOW)])
        == 100 - 25 - 12 - 5 - 2
    )
    assert score([_f(Severity.HIGH, FindingStatus.ACCEPTED), _f(Severity.INFO)]) == 100
    assert [grade(v) for v in (95, 85, 75, 65, 55, 10)] == ["A", "B", "C", "D", "E", "F"]


def test_intent_and_paths():
    ollama = load().program_by_id("ollama")
    assert user_configured(ollama, {"OLLAMA_HOST": "0.0.0.0:11434"})
    assert user_configured(ollama, {"OLLAMA_HOST": "[::]:11434"})
    assert not user_configured(ollama, {"OLLAMA_HOST": "127.0.0.1:11434"})
    assert not user_configured(ollama, {})
    env = {"LOCALAPPDATA": r"C:\Users\a\AppData\Local"}
    assert is_user_writable(r"C:\Users\a\AppData\Local\Programs\x.exe", env)
    assert not is_user_writable(r"C:\Program Files\x.exe", env)


def test_scan_result_round_trip(this_pc_raw):
    r = analyze(this_pc_raw)
    again = ScanResult.from_dict(r.to_dict())
    assert again.score == r.score and len(again.findings) == len(r.findings)
    assert again.ports[0].verdict == r.ports[0].verdict


def test_history_compare_and_keep(tmp_path, this_pc_raw):
    h = History(tmp_path / "h.db")
    r1 = analyze(this_pc_raw)
    h.save_scan(r1)
    d1 = r1.to_dict(include_facts=False)
    d2 = dict(
        d1,
        score=d1["score"] - 12,
        findings=[
            *d1["findings"],
            {"id": "new", "title": "New", "severity": "high", "status": "open"},
        ],
    )
    diff = compare(d1, d2)
    assert diff.score_change == -12 and [f["id"] for f in diff.new_findings] == ["new"]
    assert compare(d2, d1).resolved_findings[0]["id"] == "new"
    assert compare(None, d1).empty
    h.accept("keep:x", 3, "X")
    assert h.accepted_widths() == {"keep:x": 3}
    h.unaccept("keep:x")
    assert h.accepted_widths() == {}
    assert h.scans()[0].score == r1.score


def test_keep_hides_until_wider(this_pc_raw):
    plain = analyze(this_pc_raw)
    f = plain.finding("exposure.program:spotifylauncher.exe")
    kept = analyze(this_pc_raw, accepted={f.keep_key: f.width})
    assert kept.finding(f.id).status == FindingStatus.ACCEPTED
    assert kept.score > plain.score
    narrower = analyze(this_pc_raw, accepted={f.keep_key: f.width - 1})
    assert narrower.finding(f.id).status == FindingStatus.OPEN
