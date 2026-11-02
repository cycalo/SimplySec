"""Real cases from this PC (fixture captured read-only with ``simplysec`` on 2026-11-02).

* the Ollama allow rule on Private and Public (with OLLAMA_HOST=0.0.0.0 set on purpose);
* the user-scoped Codex sandbox block rule, which must not cover other users' programs;
* Cursor bound only to the Tailscale address.
"""

from __future__ import annotations

from dataclasses import replace

from simplysec.core.engine import analyze
from simplysec.core.exposure import EvalContext, evaluate
from simplysec.core.models import FindingStatus, Profile, Severity, Verdict
from simplysec.core.scoring import WIDTH_PUBLIC_ANY, WIDTH_VPN
from tests.conftest import listener

OLLAMA = r"C:\Users\micha\AppData\Local\Programs\Ollama\ollama.exe"
MICHA = "S-1-5-21-828318626-1834032441-4028443802-1001"
CODEX_USER = "S-1-5-21-828318626-1834032441-4028443802-1004"


def _ctx(raw):
    return EvalContext(raw.interfaces, env={k.upper(): v for k, v in raw.env.items()})


def test_ollama_reachable_on_private_and_public(this_pc_raw):
    exp = evaluate(
        listener(port=11434, exe=OLLAMA, user=MICHA), this_pc_raw.firewall, _ctx(this_pc_raw)
    )
    assert exp.verdict == Verdict.REACHABLE
    reach = {ie.interface: ie for ie in exp.reachable}
    assert reach["Ethernet"].profile == Profile.PUBLIC
    assert "ollama.exe" in reach["Ethernet"].allow_rules
    assert "Tailscale" in reach  # Private profile


def test_ollama_finding_is_user_configured_not_a_threat(this_pc_raw):
    ollama = listener(port=11434, exe=OLLAMA, user=MICHA)
    raw = replace(this_pc_raw, listeners=[*this_pc_raw.listeners, ollama])
    result = analyze(raw)
    f = result.finding("exposure.program:ollama.exe")
    assert f is not None
    assert f.user_configured
    assert "you set this up" in f.title
    assert f.severity <= Severity.LOW
    assert {o.fix_id for o in f.fixes} >= {
        "exposure.block_program_public",
        "exposure.block_program",
    }
    assert f.keep_key
    row = next(p for p in result.ports if p.port == 11434)
    assert row.verdict == Verdict.REACHABLE and "ollama.exe" in row.rules


def test_ollama_rule_only_when_not_running(this_pc_raw):
    result = analyze(this_pc_raw)
    f = result.finding("exposure.rule:ollama.exe")
    assert f is not None and f.user_configured and f.severity == Severity.INFO


def test_codex_rule_does_not_cover_other_users(this_pc_raw):
    # The rule blocks everything for the sandbox user only.
    rules = [
        r for r in this_pc_raw.firewall.rules if r.name == "codex_sandbox_offline_block_inbound"
    ]
    assert rules and rules[0].local_user_authorized
    mine = evaluate(
        listener(port=11434, exe=OLLAMA, user=MICHA), this_pc_raw.firewall, _ctx(this_pc_raw)
    )
    sandbox = evaluate(
        listener(port=11434, exe=OLLAMA, user=CODEX_USER), this_pc_raw.firewall, _ctx(this_pc_raw)
    )
    unknown = evaluate(
        listener(port=11434, exe=OLLAMA, user=None), this_pc_raw.firewall, _ctx(this_pc_raw)
    )
    assert mine.verdict == Verdict.REACHABLE
    assert sandbox.verdict == Verdict.BLOCKED
    assert unknown.verdict == Verdict.UNCERTAIN


def test_cursor_bound_to_tailscale_only(this_pc_raw):
    result = analyze(this_pc_raw)
    row = next(p for p in result.ports if p.port == 3000 and p.process.lower() == "cursor.exe")
    assert row.verdict == Verdict.REACHABLE
    assert row.reachable_from == "Tailscale network"
    exp = next(e for e in result.exposures if e.listener.port == 3000)
    assert [ie.interface for ie in exp.per_interface] == ["Tailscale"]
    f = result.finding("exposure.program:cursor.exe")
    assert f is not None and f.width == WIDTH_VPN


def test_smb_and_rpc_blocked_on_public_ethernet(this_pc_raw):
    result = analyze(this_pc_raw)
    for port in (135, 445, 5357):
        exp = [
            e for e in result.exposures if e.listener.port == port and e.listener.protocol == "tcp"
        ]
        eth = [ie for e in exp for ie in e.per_interface if ie.interface == "Ethernet"]
        assert eth and all(ie.verdict == Verdict.BLOCKED for ie in eth), port


def test_whole_scan_is_sane(this_pc_raw):
    result = analyze(this_pc_raw)
    assert 0 <= result.score <= 100
    assert not result.errors
    assert result.network_status()[0].startswith("Ethernet: Public network")
    assert result.counts()["critical"] == 0
    # Spotify Connect is genuinely reachable on the Public Ethernet.
    f = result.finding("exposure.program:spotifylauncher.exe")
    assert f is not None and f.width == WIDTH_PUBLIC_ANY
    # Unknown programs with Public allow rules are grouped into one finding.
    grouped = result.finding("exposure.public_rules")
    assert grouped is not None and len(grouped.details) > 5
    assert result.finding("exposure.protected").status == FindingStatus.INFO
