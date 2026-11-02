"""Apply, verify and undo with fake OS adapters: order, before-states, refusals."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

import pytest

from simplysec.core.actions import Adapters
from simplysec.core.engine import Engine, NeedsAdmin, Selection, build_plan
from simplysec.core.journal import Journal
from simplysec.core.models import FirewallProfileState, FirewallRule, Profile


class FakeFirewall:
    def __init__(self) -> None:
        self.rules: list[FirewallRule] = []
        self.profiles = {
            p: FirewallProfileState(p) for p in (Profile.DOMAIN, Profile.PRIVATE, Profile.PUBLIC)
        }
        self.exports = 0
        self.log: list[str] = []

    def find_rules(self, name: str) -> list[FirewallRule]:
        return [r for r in self.rules if r.name == name]

    def add_rule(self, rule: FirewallRule) -> None:
        self.log.append(f"add {rule.name}")
        self.rules.append(rule)

    def remove_rules_named(self, name: str) -> int:
        self.log.append(f"remove {name}")
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.name != name]
        return before - len(self.rules)

    def group_rules(self) -> list[FirewallRule]:
        return [r for r in self.rules if r.grouping == "SimplySec"]

    def read_profile(self, p: Profile) -> FirewallProfileState:
        return self.profiles[p]

    def set_profile(
        self, p: Profile, enabled: bool | None = None, default_inbound_block: bool | None = None
    ) -> None:
        st = self.profiles[p]
        if enabled is not None:
            st.enabled = enabled
        if default_inbound_block is not None:
            st.default_inbound_block = default_inbound_block

    def export_policy(self, folder: Any) -> str:
        self.exports += 1
        return f"{folder}/firewall-{self.exports}.wfw"


@dataclass
class Snap:
    key_existed: bool
    exists: bool
    type: str | None = None
    value: Any = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class FakeRegistry:
    values: dict[tuple[str, str], tuple[str, Any]] = field(default_factory=dict)
    fail_on: str | None = None

    def read(self, path: str, name: str) -> Snap:
        if (path, name) in self.values:
            t, v = self.values[(path, name)]
            return Snap(True, True, t, v)
        return Snap(any(p == path for p, _ in self.values), False)

    def write(self, path: str, name: str, value: Any, vtype: str) -> None:
        if self.fail_on == name:
            raise PermissionError("access denied")
        self.values[(path, name)] = (vtype, value)

    def restore(self, path: str, name: str, before: dict[str, Any]) -> None:
        if before["exists"]:
            self.values[(path, name)] = (before["type"], before["value"])
        else:
            self.values.pop((path, name), None)


class FakeSystem:
    def __init__(self) -> None:
        self.smb1 = True

    def smb_server_get(self) -> dict[str, Any]:
        return {"smb1": self.smb1}

    def smb_server_set(self, smb1: bool) -> None:
        self.smb1 = smb1

    def create_restore_point(self, _d: str) -> None:
        raise RuntimeError("restore points are off")


def make_engine(tmp_path, admin: bool = True) -> tuple[Engine, Adapters]:
    adapters = Adapters(FakeFirewall(), FakeRegistry(), None, None, FakeSystem(), None)
    engine = Engine(
        adapters=adapters,
        journal=Journal(tmp_path / "data" / "simplysec.db"),
        is_admin=lambda: admin,
        backups_dir=tmp_path / "backups",
    )
    return engine, adapters


RA = r"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance"


def test_apply_verify_and_undo_in_reverse_order(tmp_path):
    engine, a = make_engine(tmp_path)
    a.registry.values[(RA, "fAllowToGetHelp")] = ("REG_DWORD", 1)
    plan = build_plan(
        [
            Selection("rdp.remote_assistance_off", {}, "rdp.remote_assistance_on"),
            Selection("exposure.block_program", {"exe": r"C:\t\a.exe", "label": "A"}, "x"),
            Selection("legacy.smb1_off", {}, "legacy.smb1_on"),
        ]
    )
    res = engine.apply(plan, restore_point=True)
    assert [o.status for o in res.outcomes] == ["applied"] * 3
    assert all(o.verified for o in res.outcomes)
    assert res.backup and a.firewall.exports == 1
    assert any("Restore point" in w for w in res.warnings)
    assert a.registry.values[(RA, "fAllowToGetHelp")] == ("REG_DWORD", 0)
    assert a.system.smb1 is False and len(a.firewall.group_rules()) == 1

    undone = engine.undo(everything=True)
    assert [u.change.kind for u in undone] == [
        "smb.server_setting",
        "firewall.add_rule",
        "registry.value",
    ]
    assert all(u.ok for u in undone)
    assert a.registry.values[(RA, "fAllowToGetHelp")] == ("REG_DWORD", 1)
    assert a.system.smb1 is True and not a.firewall.rules
    assert {c.status for c in engine.journal.changes()} == {"reverted"}


def test_value_we_created_is_deleted_on_undo(tmp_path):
    engine, a = make_engine(tmp_path)
    plan = build_plan([Selection("legacy.llmnr_off", {}, "legacy.llmnr_on")])
    engine.apply(plan)
    key = (r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast")
    assert a.registry.values[key] == ("REG_DWORD", 0)
    engine.undo(batch_id=1)
    assert key not in a.registry.values


def test_failed_apply_is_recorded_and_others_continue(tmp_path):
    engine, a = make_engine(tmp_path)
    a.registry.fail_on = "fAllowToGetHelp"
    plan = build_plan(
        [
            Selection("rdp.remote_assistance_off", {}, "f1"),
            Selection("legacy.smb1_off", {}, "f2"),
        ]
    )
    res = engine.apply(plan)
    assert [o.status for o in res.outcomes] == ["failed", "applied"]
    assert "access denied" in res.outcomes[0].error
    assert not res.ok
    statuses = [c.status for c in engine.journal.changes()]
    assert statuses == ["failed", "applied"]


def test_needs_admin(tmp_path):
    engine, _ = make_engine(tmp_path, admin=False)
    with pytest.raises(NeedsAdmin):
        engine.apply(build_plan([Selection("legacy.smb1_off", {}, None)]))
    with pytest.raises(NeedsAdmin):
        engine.undo(everything=True)


def test_tampered_journal_is_refused(tmp_path):
    engine, a = make_engine(tmp_path)
    engine.apply(build_plan([Selection("legacy.smb1_off", {}, None)]))
    db = sqlite3.connect(tmp_path / "data" / "simplysec.db")
    # Point the change at an arbitrary registry value.
    evil = {
        "path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "name": "x",
        "value": "evil.exe",
        "type": "REG_SZ",
    }
    db.execute("UPDATE changes SET kind='registry.value', params=?", (json.dumps(evil),))
    db.commit()
    db.close()
    out = engine.undo(everything=True)
    assert not out[0].ok and "allow-list" in out[0].error
    assert (evil["path"], "x") not in a.registry.values


def test_tampered_before_state_is_refused(tmp_path):
    engine, a = make_engine(tmp_path)
    plan = build_plan(
        [Selection("housekeeping.remove_v1_rules", {"names": ["BlockPort139-TCP-in"]}, None)]
    )
    a.firewall.rules.append(FirewallRule(name="BlockPort139-TCP-in", action="block"))
    engine.apply(plan)
    db = sqlite3.connect(tmp_path / "data" / "simplysec.db")
    before = {"rules": [FirewallRule(name="Allow everything", action="allow").to_dict()]}
    db.execute("UPDATE changes SET before=?", (json.dumps(before),))
    db.commit()
    db.close()
    out = engine.undo(everything=True)
    assert not out[0].ok
    assert not a.firewall.find_rules("Allow everything")


def test_remove_rule_undo_recreates_definition(tmp_path):
    engine, a = make_engine(tmp_path)
    original = FirewallRule(
        name="SimpleSec-WinRM-5985-AllowLocal",
        action="allow",
        protocol=6,
        local_ports="5985",
        remote_addresses="LocalSubnet",
    )
    a.firewall.rules.append(original)
    engine.apply(
        build_plan([Selection("housekeeping.remove_v1_rules", {"names": [original.name]}, None)])
    )
    assert not a.firewall.rules
    engine.undo(everything=True)
    assert a.firewall.rules == [original]


def test_remove_all_rules_also_clears_unjournaled_group_rules(tmp_path):
    engine, a = make_engine(tmp_path)
    engine.apply(build_plan([Selection("exposure.block_program", {"exe": r"C:\a.exe"}, None)]))
    a.firewall.rules.append(
        FirewallRule(name="SimplySec:orphan:1", action="block", grouping="SimplySec")
    )
    outcomes, leftovers = engine.remove_all_rules()
    assert len(outcomes) == 1 and outcomes[0].ok
    assert leftovers == ["SimplySec:orphan:1"]
    assert not a.firewall.group_rules()


def test_firewall_profile_round_trip(tmp_path):
    engine, a = make_engine(tmp_path)
    a.firewall.profiles[Profile.PUBLIC].enabled = False
    engine.apply(build_plan([Selection("firewall.enable", {"profile": 4}, None)]))
    assert a.firewall.profiles[Profile.PUBLIC].enabled
    engine.undo(everything=True)
    assert not a.firewall.profiles[Profile.PUBLIC].enabled


def test_readonly_journal_refuses_writes(tmp_path):
    Journal(tmp_path / "j.db")
    ro = Journal(tmp_path / "j.db", readonly=True)
    with pytest.raises(PermissionError):
        ro.begin_batch("x", [])
    assert ro.changes() == []
