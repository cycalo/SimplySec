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
    assert "Score" in out and "Ports other devices can reach" in out


def test_fix_needs_admin(fake_engine, monkeypatch, capsys):
    monkeypatch.setattr(cli.elevation, "is_admin", lambda: False)
    assert cli.main(["fix", "recommended", "--yes"]) == cli.EXIT_NEEDS_ADMIN


def test_changes_empty(capsys):
    assert cli.main(["changes"]) == 0
    assert "has not changed anything" in capsys.readouterr().out
