"""Elevated end-to-end tests. They change this PC (and undo it). Opt-in:

    pytest -m admin        (from an elevated prompt)

1. Firewall: start ``python -m http.server 8765 --bind 0.0.0.0``, apply "Only this PC"
   (block the program), check the verdict becomes Blocked, that exactly one readable rule
   exists in the SimplySec group, then undo everything and check the group is empty.
2. Registry: apply the Remote Assistance fix, check the value, undo, and check the original
   value (or its absence) is back.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from simplysec.app import elevation
from simplysec.core.engine import Engine, Selection
from simplysec.core.models import Verdict

pytestmark = [
    pytest.mark.admin,
    pytest.mark.skipif(not elevation.is_admin(), reason="needs an elevated prompt"),
]


@pytest.fixture
def http_server():
    proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", "8765", "--bind", "0.0.0.0"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    yield proc
    proc.terminate()
    proc.wait(10)


def _row(result, port):
    return next(p for p in result.ports if p.port == port and p.protocol == "tcp")


def test_firewall_fix_and_undo(http_server):
    from simplysec.windows import firewall

    engine = Engine()
    before = engine.scan(save=False)
    row = _row(before, 8765)
    exe = row.exe
    assert exe.lower().endswith(("python.exe", "pythonw.exe"))

    plan = engine.plan(
        [
            Selection(
                "exposure.block_program",
                {"exe": exe, "label": "Python test server"},
                row.finding_id,
            )
        ]
    )
    result = engine.apply(plan)
    assert result.ok, result.outcomes
    assert result.backup

    after = engine.scan(save=False)
    assert _row(after, 8765).verdict in (Verdict.BLOCKED, Verdict.LOCAL_ONLY)
    group = firewall.group_rules()
    assert len(group) == 1
    assert group[0].name.startswith("SimplySec:block_program:")
    assert "Added by SimplySec" in group[0].description

    outcomes = engine.undo(everything=True)
    assert outcomes and all(o.ok for o in outcomes)
    assert firewall.group_rules() == []


def test_registry_fix_and_undo():
    from simplysec.windows import registry

    path = r"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    original = registry.read(path, "fAllowToGetHelp")
    engine = Engine()
    engine.scan(save=False)
    result = engine.apply(engine.plan([Selection("rdp.remote_assistance_off", {}, None)]))
    assert result.ok
    now = registry.read(path, "fAllowToGetHelp")
    assert now.exists and now.value == 0
    assert all(o.ok for o in engine.undo(batch_id=result.batch_id))
    restored = registry.read(path, "fAllowToGetHelp")
    assert (restored.exists, restored.value) == (original.exists, original.value)
