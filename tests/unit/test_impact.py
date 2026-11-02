"""Impact analysis: what each fix would affect, from simulation and live usage evidence."""

from __future__ import annotations

import copy
import datetime as dt

import pytest

from simplysec.core.checks import FIXES
from simplysec.core.engine import Engine, Selection, analyze, analyze_with_context, build_plan
from simplysec.core.impact import Level, assess, short_name_dependencies


def _ctx(raw, **usage):
    raw = copy.deepcopy(raw)
    base = {
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
    base.update(usage)
    raw.facts["usage"] = {"status": "ok", "value": base}
    return analyze_with_context(raw)


def _impact(ctx, fix_id, params):
    fix = FIXES[fix_id]
    return assess(fix_id, params, fix.build(params) if fix.build else [], ctx)


def _spotify(raw):
    return next(
        x for x in raw.listeners if x.process == "SpotifyLauncher.exe" and x.protocol == "tcp"
    )


def test_blocking_a_program_someone_is_connected_to_is_in_use(this_pc_raw):
    lst = _spotify(this_pc_raw)
    conn = {
        "protocol": "tcp",
        "local_port": lst.port,
        "local_ip": "192.168.1.71",
        "remote_ip": "192.168.1.40",
        "pid": lst.pid,
        "process": lst.process,
    }
    _, ctx = _ctx(this_pc_raw, connections=[conn])
    imp = _impact(ctx, "exposure.block_program", {"exe": lst.exe, "label": "Spotify"})
    assert imp.level == Level.IN_USE
    assert any("192.168.1.40" in e for e in imp.evidence)
    assert any("would stop being reachable from Ethernet (Public)" in e for e in imp.evidence)


def test_blocking_without_connections_lists_what_stops_being_reachable(this_pc_raw):
    lst = _spotify(this_pc_raw)
    _, ctx = _ctx(this_pc_raw)
    pub = _impact(ctx, "exposure.block_program_public", {"exe": lst.exe, "label": "Spotify"})
    assert pub.level == Level.MAY_AFFECT
    assert any("Ethernet (Public)" in e for e in pub.evidence)
    assert not any("Tailscale" in e for e in pub.evidence)  # Private/VPN access stays
    everywhere = _impact(ctx, "exposure.block_program", {"exe": lst.exe, "label": "Spotify"})
    assert any("Tailscale" in e for e in everywhere.evidence)


def test_program_not_running_affects_nothing_today(this_pc_raw):
    _, ctx = _ctx(this_pc_raw)
    exe = r"C:\Users\micha\AppData\Local\Programs\Ollama\ollama.exe"
    imp = _impact(ctx, "exposure.block_program", {"exe": exe})
    assert imp.level == Level.NONE_FOUND and "isn't accepting connections" in imp.headline


def test_marking_network_private_shows_what_becomes_reachable(this_pc_raw):
    _, ctx = _ctx(this_pc_raw)
    imp = _impact(ctx, "network.mark_private", {"index": 9, "alias": "Ethernet", "name": "EE"})
    assert imp.level == Level.MAY_AFFECT
    assert any("would become reachable from Ethernet (Private)" in e for e in imp.evidence)


def test_rdp_in_use_when_connected_remotely(this_pc_raw):
    _, ctx = _ctx(this_pc_raw, remote_session=True)
    imp = _impact(ctx, "rdp.disable", {})
    assert imp.level == Level.IN_USE
    assert "You are using this PC through Remote Desktop" in imp.evidence[0]
    _, ctx = _ctx(this_pc_raw)
    assert _impact(ctx, "rdp.disable", {}).level == Level.NONE_FOUND


def test_netbios_and_llmnr_short_name_dependencies(this_pc_raw):
    _, ctx = _ctx(
        this_pc_raw,
        mappings=[
            {"local": "Z:", "remote": r"\\NAS\media"},
            {"local": "Y:", "remote": r"\\nas.home\x"},
        ],
        printers=[{"name": "Office", "port": r"\\OLDPC\HP", "computer": "OLDPC"}],
    )
    deps = short_name_dependencies(ctx)
    assert len(deps) == 2 and "NAS" in deps[0] and "OLDPC" in deps[1]
    assert _impact(ctx, "legacy.netbios_off", {"adapters": []}).level == Level.MAY_AFFECT
    assert _impact(ctx, "legacy.llmnr_off", {}).level == Level.MAY_AFFECT


def test_smb1_needs_admin_or_shows_clients(this_pc_raw):
    _, ctx = _ctx(this_pc_raw)
    assert _impact(ctx, "legacy.smb1_off", {}).level == Level.UNKNOWN
    _, ctx = _ctx(
        this_pc_raw,
        smb_sessions_status="ok",
        smb_sessions=[{"client": "192.168.1.9", "user": "x", "dialect": "1.5"}],
    )
    assert _impact(ctx, "legacy.smb1_off", {}).level == Level.IN_USE


def test_guest_and_remote_assistance(this_pc_raw):
    recent = (dt.datetime.now(dt.UTC) - dt.timedelta(days=3)).isoformat()
    _, ctx = _ctx(
        this_pc_raw, last_logons=[{"sid": "S-1-5-21-1-501", "last": recent}], msra_running=True
    )
    assert _impact(ctx, "accounts.guest_off", {}).level == Level.IN_USE
    assert _impact(ctx, "rdp.remote_assistance_off", {}).level == Level.IN_USE


def test_missing_usage_is_unknown_not_safe(this_pc_raw):
    _, ctx = analyze_with_context(this_pc_raw)  # this fixture predates the usage fact
    assert _impact(ctx, "rdp.remote_assistance_off", {}).level == Level.UNKNOWN
    assert _impact(ctx, "system.autorun_off", {}).level == Level.NONE_FOUND


def test_fix_recommended_leaves_out_fixes_in_use(this_pc_raw):
    result, _ = _ctx(this_pc_raw, msra_running=True)
    sels, skipped = Engine(is_admin=lambda: False).recommended_split(result)
    assert "rdp.remote_assistance_off" not in {s.fix_id for s in sels}
    assert skipped and "Remote Assistance" in skipped[0][0]


def test_scan_attaches_impacts_and_plan_carries_them(this_pc_raw):
    result, ctx = _ctx(this_pc_raw)
    f = result.finding("rdp.remote_assistance_on")
    assert f.fixes[0].impact["level"] == "none_found"
    plan = build_plan([Selection("rdp.remote_assistance_off", {}, f.id)], ctx)
    assert plan.items[0].impact.level == Level.NONE_FOUND


@pytest.mark.parametrize("fix_id", sorted(FIXES))
def test_every_fix_has_an_impact_answer(this_pc_raw, fix_id):
    _, ctx = _ctx(this_pc_raw)
    fix = FIXES[fix_id]
    if fix.build is None:
        return
    params = {
        "exe": r"C:\x\a.exe",
        "protocol": "tcp",
        "port": 8765,
        "profile": 4,
        "index": 9,
        "names": [],
        "profiles": [],
        "adapters": [],
        "exes": [r"C:\x\a.exe"],
        "rid": 501,
    }
    assert assess(fix_id, params, fix.build(params), ctx).headline


def test_connected_column(this_pc_raw):
    lst = _spotify(this_pc_raw)
    raw = copy.deepcopy(this_pc_raw)
    conns = [{"local_port": lst.port, "pid": lst.pid, "remote_ip": "192.168.1.40"}]
    raw.facts["usage"] = {"status": "ok", "value": {"connections": conns}}
    row = next(p for p in analyze(raw).ports if p.port == lst.port and p.pid == lst.pid)
    assert row.connected == ["192.168.1.40"]
