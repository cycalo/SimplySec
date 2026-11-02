"""Background monitoring (M4): notification triggers, task XML, journaled enable/disable."""

from __future__ import annotations

import datetime as dt
from xml.etree import ElementTree

from simplysec.core import monitor
from simplysec.core.actions import Adapters
from simplysec.core.engine import Engine, analyze
from simplysec.core.journal import Journal
from simplysec.windows import scheduler, toast


def _scan(score, findings=(), devices=()):
    return {
        "score": score,
        "findings": list(findings),
        "ports": [],
        "extras": {"devices": list(devices)},
    }


def _f(fid, sev="medium", title=None):
    return {"id": fid, "severity": sev, "status": "open", "title": title or fid}


def test_quiet_when_nothing_changed():
    s = _scan(80, [_f("a")])
    assert monitor.triggers(s, s) == []


def test_risk_rise_of_five():
    assert monitor.triggers(_scan(20), _scan(24)) == []
    assert monitor.triggers(_scan(20), _scan(10)) == []  # lower risk: quiet
    assert "rose from 20 to 25" in monitor.triggers(_scan(20), _scan(25))[0]


def test_new_high_or_critical_only():
    prev = _scan(80, [_f("a", "high")])
    cur = _scan(80, [_f("a", "high"), _f("b", "medium"), _f("c", "critical", "Telnet is open")])
    assert monitor.triggers(prev, cur) == ["New: Telnet is open."]


def test_protection_turned_off():
    prev = _scan(90)
    cur = _scan(
        90, [_f("firewall.off.public", "critical", "The firewall is off for Public networks")]
    )
    assert monitor.triggers(prev, cur) == ["The firewall is off for Public networks."]
    cur2 = _scan(
        90, [_f("malware.no_antivirus", "critical", "No antivirus is actively protecting this PC")]
    )
    assert monitor.triggers(None, cur2) == ["No antivirus is actively protecting this PC."]


def test_new_device():
    prev = _scan(90, devices=[{"mac": "AA"}])
    cur = _scan(90, devices=[{"mac": "AA"}, {"mac": "BB", "name": "Unknown camera"}])
    assert monitor.triggers(prev, cur) == ["New device on your network: Unknown camera."]


def test_task_xml_is_valid_and_escaped():
    xml = scheduler.build_xml(
        "07:30",
        r"C:\Program Files\SimplySec\SimplySec.exe",
        "monitor --run",
        "S-1-5-21-1-1001",
        dt.date(2026, 11, 2),
    )
    root = ElementTree.fromstring(xml.split("?>", 1)[1])
    ns = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
    assert (
        root.find(f"{ns}Triggers/{ns}CalendarTrigger/{ns}StartBoundary").text
        == "2026-11-02T07:30:00"
    )
    principal = root.find(f"{ns}Principals/{ns}Principal")
    assert principal.find(f"{ns}RunLevel").text == "HighestAvailable"
    assert principal.find(f"{ns}LogonType").text == "InteractiveToken"
    assert root.find(f"{ns}Actions/{ns}Exec/{ns}Arguments").text == "monitor --run"
    try:
        scheduler.build_xml("25:00", "x", "y", "z")
    except ValueError:
        pass
    else:
        raise AssertionError("bad time accepted")


def test_toast_xml_escapes():
    xml = toast.toast_xml("SimplySec", ["New device: <script>"])
    assert "&lt;script&gt;" in xml and "<script>" not in xml


class FakeScheduler:
    def __init__(self) -> None:
        self.tasks: dict[str, str] = {}

    def export_xml(self, name):
        return self.tasks.get(name)

    def exists(self, name):
        return name in self.tasks

    def create(self, name, time):
        self.tasks[name] = f"<Task>SimplySec {time}</Task>"

    def restore(self, name, xml):
        if xml:
            self.tasks[name] = xml
        else:
            self.tasks.pop(name, None)

    def delete(self, name):
        self.tasks.pop(name, None)


class FakeFirewall:
    def export_policy(self, folder):
        return "x"


def _engine(tmp_path, raw=None):
    sched = FakeScheduler()
    adapters = Adapters(FakeFirewall(), None, None, None, None, None, None, sched)
    eng = Engine(
        adapters=adapters,
        journal=Journal(tmp_path / "j.db"),
        is_admin=lambda: True,
        collector=(lambda progress=None: raw) if raw else None,
        backups_dir=tmp_path,
    )
    return eng, sched


def test_enable_move_and_disable_are_journaled(tmp_path):
    eng, sched = _engine(tmp_path)
    assert monitor.enable(eng, "12:00").ok
    assert sched.tasks[monitor.TASK_NAME].endswith("12:00</Task>")
    assert monitor.enable(eng, "08:15").ok  # moving it undoes the old change first
    assert sched.tasks[monitor.TASK_NAME].endswith("08:15</Task>")
    kinds = [(c.kind, c.status) for c in eng.journal.changes()]
    assert kinds == [("task.schedule", "reverted"), ("task.schedule", "applied")]
    assert monitor.disable(eng)
    assert monitor.TASK_NAME not in sched.tasks
    assert eng.history.get_setting(monitor.SETTING)["enabled"] is False


def test_monitor_run_saves_and_notifies(tmp_path, this_pc_raw):
    eng, _ = _engine(tmp_path, this_pc_raw)
    shown = []
    assert monitor.run_once(eng, notify=lambda title, lines: shown.append((title, lines))) == 0
    assert eng.history.scans()[0].kind == "monitor"
    assert shown == []  # first run on a PC with no protection gaps: quiet
    # Make the stored previous scan look much better, so the risk score "rises".
    data = analyze(this_pc_raw).to_dict(include_facts=False)
    data["score"] = 0
    import json
    import sqlite3

    db = sqlite3.connect(eng.history.path)
    db.execute("UPDATE scans SET data=?, score=0", (json.dumps(data),))
    db.commit()
    db.close()
    monitor.run_once(eng, notify=lambda title, lines: shown.append((title, lines)))
    assert shown and "rose from 0" in shown[0][1][0]
