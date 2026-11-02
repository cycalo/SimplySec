"""Per-user history: scans, devices, settings and accepted risks ("Keep").

Lives in ``%LOCALAPPDATA%\\SimplySec\\history.db`` so read-only (non-admin) scans and the
daily check (which runs as the signed-in user) share one history. Nothing here is replayed
with administrator rights, so it does not need the admin-only folder.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accepted(
    keep_key TEXT PRIMARY KEY,
    width INTEGER NOT NULL,
    title TEXT,
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices(
    mac TEXT PRIMARY KEY,
    ip TEXT,
    name TEXT,
    vendor TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    trusted INTEGER NOT NULL DEFAULT 0,
    label TEXT,
    data TEXT
);
"""

KEEP_SCANS = 365


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class ScanSummary:
    id: int
    ts: str
    kind: str
    score: int
    grade: str


@dataclass
class Comparison:
    score_change: int = 0
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = field(default_factory=list)
    new_listeners: list[str] = field(default_factory=list)
    gone_listeners: list[str] = field(default_factory=list)
    new_devices: list[dict[str, Any]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (
            self.score_change
            or self.new_findings
            or self.resolved_findings
            or self.new_listeners
            or self.gone_listeners
            or self.new_devices
        )

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _scored(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        f["id"]: f for f in findings if f.get("status") == "open" and f.get("severity") != "info"
    }


def _listener_keys(d: dict[str, Any]) -> set[str]:
    return {
        f"{p['protocol'].upper()} {p['port']} ({p['process']})"
        for p in d.get("ports", [])
        if p.get("verdict") in ("reachable", "uncertain")
    }


def compare(old: dict[str, Any] | None, new: dict[str, Any]) -> Comparison:
    """What changed between two stored scans (dicts from ScanResult.to_dict)."""
    if old is None:
        return Comparison()
    a, b = _scored(old.get("findings", [])), _scored(new.get("findings", []))
    sev_order = ["info", "low", "medium", "high", "critical"]
    new_f = [
        b[k]
        for k in b
        if k not in a or sev_order.index(b[k]["severity"]) > sev_order.index(a[k]["severity"])
    ]
    resolved = [a[k] for k in a if k not in b]
    la, lb = _listener_keys(old), _listener_keys(new)
    old_dev = {d.get("mac") for d in old.get("extras", {}).get("devices", [])}
    new_dev = [
        d
        for d in new.get("extras", {}).get("devices", [])
        if d.get("mac") not in old_dev and old_dev
    ]
    return Comparison(
        score_change=int(new.get("score", 0)) - int(old.get("score", 0)),
        new_findings=new_f,
        resolved_findings=resolved,
        new_listeners=sorted(lb - la),
        gone_listeners=sorted(la - lb),
        new_devices=new_dev,
    )


class History:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db, db:
            db.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    # ----------------------------------------------------------------- scans
    def save_scan(self, result: ScanResult, kind: str = "manual") -> int:
        data = result.to_dict(include_facts=False)
        with closing(self._connect()) as db, db:
            cur = db.execute(
                "INSERT INTO scans(ts, kind, score, grade, data) VALUES (?, ?, ?, ?, ?)",
                (result.started, kind, result.score, result.grade, json.dumps(data)),
            )
            db.execute(
                "DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
                (KEEP_SCANS,),
            )
            return int(cur.lastrowid or 0)

    def scans(self, limit: int = 200) -> list[ScanSummary]:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT id, ts, kind, score, grade FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            )
            return [ScanSummary(r["id"], r["ts"], r["kind"], r["score"], r["grade"]) for r in rows]

    def scan_data(self, scan_id: int) -> dict[str, Any] | None:
        with closing(self._connect()) as db:
            row = db.execute("SELECT data FROM scans WHERE id=?", (scan_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def latest(self, n: int = 2) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT data FROM scans ORDER BY id DESC LIMIT ?", (n,)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def previous_to(self, scan_id: int) -> dict[str, Any] | None:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT data FROM scans WHERE id < ? ORDER BY id DESC LIMIT 1", (scan_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    # ----------------------------------------------------------------- accepted risks
    def accept(self, keep_key: str, width: int, title: str = "") -> None:
        with closing(self._connect()) as db, db:
            db.execute(
                "INSERT INTO accepted(keep_key, width, title, created) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(keep_key) DO UPDATE SET width=excluded.width, title=excluded.title",
                (keep_key, int(width), title, _now()),
            )

    def unaccept(self, keep_key: str) -> None:
        with closing(self._connect()) as db, db:
            db.execute("DELETE FROM accepted WHERE keep_key=?", (keep_key,))

    def accepted(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            return [dict(r) for r in db.execute("SELECT * FROM accepted ORDER BY created")]

    def accepted_widths(self) -> dict[str, int]:
        return {a["keep_key"]: int(a["width"]) for a in self.accepted()}

    # ----------------------------------------------------------------- settings
    def get_setting(self, key: str, default: Any = None) -> Any:
        with closing(self._connect()) as db:
            row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        with closing(self._connect()) as db, db:
            db.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )

    # ----------------------------------------------------------------- devices (M2)
    def upsert_device(
        self, mac: str, ip: str, name: str, vendor: str, data: dict[str, Any]
    ) -> bool:
        """Insert or refresh a device. Returns True if it was never seen before."""
        now = _now()
        with closing(self._connect()) as db, db:
            row = db.execute("SELECT mac FROM devices WHERE mac=?", (mac,)).fetchone()
            if row is None:
                db.execute(
                    "INSERT INTO devices(mac, ip, name, vendor, first_seen, last_seen, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (mac, ip, name, vendor, now, now, json.dumps(data)),
                )
                return True
            db.execute(
                "UPDATE devices SET ip=?, name=COALESCE(NULLIF(?, ''), name), vendor=COALESCE(NULLIF(?, ''), vendor),"
                " last_seen=?, data=? WHERE mac=?",
                (ip, name, vendor, now, json.dumps(data), mac),
            )
            return False

    def devices(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM devices ORDER BY last_seen DESC")]
        for r in rows:
            r["data"] = json.loads(r["data"] or "{}")
            r["trusted"] = bool(r["trusted"])
        return rows

    def set_device_trusted(self, mac: str, trusted: bool) -> None:
        with closing(self._connect()) as db, db:
            db.execute("UPDATE devices SET trusted=? WHERE mac=?", (1 if trusted else 0, mac))

    def set_device_label(self, mac: str, label: str) -> None:
        with closing(self._connect()) as db, db:
            db.execute("UPDATE devices SET label=? WHERE mac=?", (label, mac))
