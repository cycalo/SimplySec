"""HTML report (M3): escaping of untrusted names, control areas, CLI command."""

from __future__ import annotations

import pytest

from simplysec import cli
from simplysec.core import engine as engine_mod
from simplysec.core.engine import analyze
from simplysec.core.report.html import CONTROL_AREAS, build_context, control_area, render


def test_report_escapes_untrusted_device_names(this_pc_raw):
    r = analyze(this_pc_raw)
    r.extras["devices"] = [
        {
            "ip": "192.168.1.9",
            "mac": "AA:BB:CC:00:00:01",
            "vendor": "<b>Evil</b>",
            "name": "<script>alert(1)</script>",
            "open_ports": [23],
            "randomized": False,
            "trusted": False,
            "is_gateway": False,
        }
    ]
    r.extras["router"] = {
        "found": True,
        "friendly_name": "<img src=x onerror=alert(2)>",
        "mappings": [],
    }
    html = render(build_context(r))
    assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)" in html
    assert "<img src=x" not in html and "&lt;img src=x" in html
    assert "<b>Evil</b>" not in html


def test_report_sections(this_pc_raw):
    r = analyze(this_pc_raw)
    ctx = build_context(r, changes=[], accepted=[], trend=[("2026-10-01", 60), ("2026-11-01", 72)])
    names = [g["name"] for g in ctx["groups"]]
    assert names == [c[0] for c in CONTROL_AREAS]
    assert sum(len(g["findings"]) for g in ctx["groups"]) == len(r.findings)
    html = render(ctx)
    for heading in (
        "Findings by control area",
        "Ports other devices can reach",
        "Changes made by SimplySec",
        "Accepted risks",
        "<polyline",
    ):
        assert heading in html
    assert control_area("Accounts") == "User access control"
    assert control_area("Wi-Fi") == "Secure configuration"


@pytest.fixture
def fake_engine(monkeypatch, this_pc_raw):
    monkeypatch.setattr(
        cli,
        "_engine",
        lambda: engine_mod.Engine(
            collector=lambda progress=None: this_pc_raw, is_admin=lambda: False
        ),
    )


def test_cli_report(fake_engine, tmp_path, capsys):
    out = tmp_path / "r.html"
    assert cli.main(["report", "--html", str(out)]) == 0
    assert out.exists() and "Security report for" in out.read_text(encoding="utf-8")
    assert cli.main(["history"]) == 0
    assert "#1" in capsys.readouterr().out
