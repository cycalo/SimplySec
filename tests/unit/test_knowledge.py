"""The knowledge base is the single source of truth: valid, no duplicates, every fix exists."""

from __future__ import annotations

import tomllib

from simplysec.core import checks, knowledge
from simplysec.core.actions import SERVICE_ALLOWLIST
from simplysec.core.knowledge import HERE
from simplysec.core.models import Severity


def test_loads_without_errors():
    kb = knowledge.load()
    assert kb.errors == []
    assert len(kb.ports) > 60 and kb.programs and kb.services


def test_no_duplicate_ports_in_source():
    data = tomllib.loads((HERE / "ports.toml").read_text(encoding="utf-8"))
    keys = [(p["protocol"], p["port"]) for p in data["port"]]
    assert len(keys) == len(set(keys))


def test_every_fix_id_exists():
    kb = knowledge.load()
    missing = kb.all_fix_ids() - set(checks.FIXES)
    assert not missing, missing


def test_v1_errors_are_corrected():
    kb = knowledge.load()
    assert "WSD" in kb.port("tcp", 5357).name  # v1 called this WinRM
    assert kb.port("tcp", 10000).risk == Severity.HIGH  # v1 had it as both High and Medium
    assert kb.port("tcp", 2179).risk == Severity.LOW  # Hyper-V vmrdp is not Remote Desktop
    assert kb.port("tcp", 11434) is not None  # Ollama, outside nmap's top 1000


def test_program_lookup_by_path():
    kb = knowledge.load()
    assert kb.program(r"C:\Users\x\AppData\Local\Programs\Ollama\ollama.exe").id == "ollama"
    assert kb.program("CURSOR.EXE").id == "cursor"
    assert kb.program("") is None


def test_never_touch_services_cannot_be_changed():
    kb = knowledge.load()
    assert {"rpcss", "mpssvc", "windefend", "dnscache", "bfe"} <= kb.never_touch
    assert not (SERVICE_ALLOWLIST & kb.never_touch)


def test_lan_probe_ports():
    kb = knowledge.load()
    probes = {p.port for p in kb.lan_probe_ports()}
    assert {23, 445, 554, 2375, 3389, 6379} <= probes
    assert 25 < len(probes) < 60
