"""CLI output shape, using the real-data fixture instead of touching the OS."""

from __future__ import annotations

import json

import pytest

from simplysec import cli
from simplysec.core import engine as engine_mod


@pytest.fixture
def fake_engine(monkeypatch, this_pc_raw):
    def make():
        return engine_mod.Engine(
            collector=lambda progress=None: this_pc_raw, is_admin=lambda: False
        )

    monkeypatch.setattr(cli, "_engine", make)


def test_scan_json_shape(fake_engine, capsys):
    assert cli.main(["scan", "--json", "--no-save"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) >= {
        "version",
        "score",
        "grade",
        "counts",
        "network",
        "findings",
        "ports",
        "exposures",
        "firewall",
        "interfaces",
        "errors",
    }
    assert "facts" not in data
    f = data["findings"][0]
    assert set(f) >= {
        "id",
        "check",
        "area",
        "title",
        "severity",
        "what_it_means",
        "details",
        "fixes",
        "status",
    }
    p = data["ports"][0]
    assert set(p) >= {
        "protocol",
        "port",
        "process",
        "listening_on",
        "reachable_from",
        "verdict",
        "risk",
        "rules",
    }
    assert data["counts"].keys() == {"critical", "high", "medium", "low"}


def test_scan_text(fake_engine, capsys):
    assert cli.main(["scan", "--no-save"]) == 0
    out = capsys.readouterr().out
    assert "Risk score" in out and "Ports other devices can reach" in out


def test_fix_needs_admin(fake_engine, monkeypatch, capsys):
    monkeypatch.setattr(cli.elevation, "is_admin", lambda: False)
    assert cli.main(["fix", "recommended", "--yes"]) == cli.EXIT_NEEDS_ADMIN


def test_changes_empty(capsys):
    assert cli.main(["changes"]) == 0
    assert "has not changed anything" in capsys.readouterr().out


def test_fix_flow_end_to_end_with_fakes(monkeypatch, this_pc_raw, tmp_path, capsys):
    from simplysec.core.actions import Adapters
    from simplysec.core.journal import Journal
    from tests.unit.test_engine_undo import FakeFirewall, FakeRegistry, FakeSystem

    registry = FakeRegistry()
    path = r"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    registry.values[(path, "fAllowToGetHelp")] = ("REG_DWORD", 1)
    adapters = Adapters(FakeFirewall(), registry, None, None, FakeSystem(), None)

    def make():
        return engine_mod.Engine(
            adapters=adapters,
            journal=Journal(tmp_path / "j.db"),
            collector=lambda progress=None: this_pc_raw,
            is_admin=lambda: True,
            backups_dir=tmp_path,
        )

    monkeypatch.setattr(cli, "_engine", make)
    monkeypatch.setattr(cli.elevation, "is_admin", lambda: True)
    code = cli.main(
        [
            "fix",
            "--finding",
            "rdp.remote_assistance_on",
            "--fix",
            "rdp.remote_assistance_off",
            "--yes",
        ]
    )
    out = capsys.readouterr().out
    assert "SimplySec will make these changes" in out and "What might stop working" in out
    assert "Verified ✓" in out
    # The fixture doesn't change, so the fresh scan honestly still reports the finding.
    assert "STILL PRESENT" in out and code == cli.EXIT_FAIL
    assert registry.values[(path, "fAllowToGetHelp")] == ("REG_DWORD", 0)
