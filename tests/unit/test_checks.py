"""Checks run against real facts from this PC, and against edited copies of them."""

from __future__ import annotations

import copy
import datetime as dt
from dataclasses import replace

import pytest

from simplysec.core.checks import FIXES, is_allowed
from simplysec.core.checks import updates as updates_check
from simplysec.core.engine import RawScan, Selection, analyze, analyze_with_context, build_plan
from simplysec.core.models import FindingStatus, FirewallRule, Profile, Severity


def _with_facts(raw: RawScan, **changes) -> RawScan:
    facts = copy.deepcopy(raw.facts)
    for name, value in changes.items():
        if value is None:
            facts[name] = {"status": "needs_admin", "error": "Access is denied."}
        else:
            facts[name]["value"].update(value)
    return replace(raw, facts=facts)


def ids(result):
    return {f.id for f in result.findings}


def test_this_pc_baseline(this_pc_raw):
    r = analyze(this_pc_raw)
    found = ids(r)
    assert "rdp.remote_assistance_on" in found
    assert "legacy.llmnr_on" in found and "legacy.netbios_on" in found
    assert "system.bitlocker_off" in found
    assert "rdp.enabled" not in found  # Remote Desktop is off on this PC
    assert "legacy.smb1_on" not in found
    assert "malware.no_antivirus" not in found
    bl = r.finding("system.bitlocker_off")
    assert bl.severity == Severity.LOW  # a desktop, not a laptop


def test_firewall_off_is_critical(this_pc_raw):
    fw = copy.deepcopy(this_pc_raw.firewall)
    fw.profiles[Profile.PUBLIC].enabled = False
    r = analyze(replace(this_pc_raw, firewall=fw))
    f = r.finding("firewall.off.public")
    assert f.severity == Severity.CRITICAL
    assert f.fixes[0].fix_id == "firewall.enable" and f.fixes[0].recommended
    # With the firewall off, SMB becomes reachable on the Public Ethernet.
    row = next(p for p in r.ports if p.port == 445 and p.protocol == "tcp")
    assert "Ethernet" in row.reachable_from


def test_managed_firewall_is_report_only(this_pc_raw):
    fw = copy.deepcopy(this_pc_raw.firewall)
    fw.profiles[Profile.PUBLIC].enabled = False
    fw.managed_by_policy = True
    r = analyze(replace(this_pc_raw, firewall=fw))
    assert r.finding("firewall.off.public").status == FindingStatus.MANAGED
    assert r.finding("housekeeping.managed") is not None


def test_rdp_on_without_nla(this_pc_raw):
    r = analyze(_with_facts(this_pc_raw, rdp={"deny": 0, "nla": 0}))
    assert r.finding("rdp.enabled").severity == Severity.LOW  # on, but blocked by the firewall here
    nla = r.finding("rdp.nla_off")
    assert nla.severity == Severity.HIGH and nla.fixes[0].fix_id == "rdp.require_nla"


def test_rdp_policy_value_wins(this_pc_raw):
    r = analyze(_with_facts(this_pc_raw, rdp={"deny": 0, "deny_policy": 1}))
    assert r.finding("rdp.enabled") is None


def test_smb1_guest_uac_blank_passwords(this_pc_raw):
    raw = _with_facts(
        this_pc_raw,
        smb={"smb1": True},
        uac={"enable_lua": 0},
        accounts={"limit_blank_password_use": 0},
    )
    users = raw.facts["accounts"]["value"]["users"]
    for u in users:
        if u["sid"].endswith("-501"):
            u["enabled"] = True
    r = analyze(raw)
    for fid in (
        "legacy.smb1_on",
        "accounts.guest_on",
        "accounts.uac_off",
        "accounts.blank_passwords",
    ):
        f = r.finding(fid)
        assert f is not None and f.severity == Severity.HIGH, fid
        assert f.fixes[0].recommended


def test_missing_permission_is_unknown_not_safe(this_pc_raw):
    r = analyze(_with_facts(this_pc_raw, smb=None))
    f = r.finding("legacy.unavailable.smb")
    assert f is not None and f.severity == Severity.INFO
    assert "unknown, not as safe" in f.what_it_means


def test_no_antivirus_is_critical(this_pc_raw):
    raw = copy.deepcopy(this_pc_raw)
    raw.facts["antivirus"]["value"] = [{"name": "Windows Defender", "state": 0x060100}]
    raw.facts["defender"]["value"]["antivirus"] = False
    assert analyze(raw).finding("malware.no_antivirus").severity == Severity.CRITICAL


def test_old_signatures_and_realtime_off(this_pc_raw):
    r = analyze(_with_facts(this_pc_raw, defender={"signature_age_days": 20, "realtime": False}))
    assert r.finding("malware.signatures_old").severity == Severity.HIGH
    assert r.finding("malware.realtime_off").severity == Severity.HIGH


@pytest.mark.parametrize(
    ("days", "severity"), [(10, None), (35, Severity.MEDIUM), (60, Severity.HIGH)]
)
def test_update_age(this_pc_raw, days, severity):
    now = dt.datetime(2026, 11, 2, tzinfo=dt.UTC)
    last = (now - dt.timedelta(days=days)).isoformat()
    raw = _with_facts(this_pc_raw, updates={"last_history_install": last, "last_hotfix": last})
    _, ctx = analyze_with_context(raw)
    found = {f.id: f for f in updates_check.run(ctx, now=now)}
    if severity is None:
        assert "updates.stale" not in found
    else:
        assert found["updates.stale"].severity == severity


def test_v1_leftover_rules_found(this_pc_raw):
    fw = copy.deepcopy(this_pc_raw.firewall)
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
    r = analyze(replace(this_pc_raw, firewall=fw))
    f = r.finding("housekeeping.v1_rules")
    assert f.severity == Severity.MEDIUM  # one of them OPENS a port
    plan = build_plan([Selection(f.fixes[0].fix_id, f.fixes[0].params, f.id)])
    assert [s.kind for s in plan.specs] == ["firewall.remove_rule", "firewall.remove_rule"]


def test_every_offered_fix_builds_allowed_actions(this_pc_raw):
    raw = _with_facts(this_pc_raw, smb={"smb1": True}, rdp={"deny": 0, "nla": 0})
    r = analyze(raw)
    seen = 0
    for f in r.findings:
        for opt in f.fixes:
            fix = FIXES[opt.fix_id]
            if fix.build is None:
                continue
            for spec in fix.build(opt.params):
                assert is_allowed(spec.kind, spec.params), (opt.fix_id, spec)
                seen += 1
    assert seen > 10


def test_block_rules_are_inbound_named_and_grouped():
    spec = FIXES["exposure.block_program_public"].build(
        {"exe": r"C:\x\ollama.exe", "label": "Ollama"}
    )[0]
    rule = spec.params["rule"]
    assert rule["name"].startswith("SimplySec:block_program_public:")
    assert (
        rule["grouping"] == "SimplySec" and rule["action"] == "block" and rule["direction"] == "in"
    )
    assert rule["profiles"] == int(Profile.PUBLIC)
    assert "Ollama" in rule["description"]
    assert not is_allowed("firewall.add_rule", {"rule": {**rule, "action": "allow"}})
    assert not is_allowed("firewall.add_rule", {"rule": {**rule, "name": "Other"}})
    assert not is_allowed(
        "registry.value",
        {"path": r"HKLM\SOFTWARE\Evil", "name": "x", "value": 1, "type": "REG_DWORD"},
    )


def test_public_network_warning_offers_mark_private(this_pc_raw):
    _, ctx = analyze_with_context(this_pc_raw)
    plan = build_plan(
        [Selection("exposure.block_program_public", {"exe": r"C:\x\a.exe", "label": "A"})], ctx
    )
    warnings = plan.items[0].warnings
    assert warnings and warnings[0].offer_fix == "network.mark_private"
    assert warnings[0].offer_params["alias"] == "Ethernet"
