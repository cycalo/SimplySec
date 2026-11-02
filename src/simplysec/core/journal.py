"""The change journal: every change with its before-state, so everything can be undone.

Stored in ``%ProgramData%\\SimplySec\\simplysec.db``. Only Administrators and SYSTEM can write
that folder (see ``app.paths.harden_data_dir``); a standard user can read it so the Changes
page works without elevation. Undo replays stored before-values elevated, which is why the
store must not be writable by standard users, and why every replayed kind and parameter set
is checked against the allow-lists declared by the check modules.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import ActionSpec

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches(
    id INTEGER PRIMARY KEY,
    created TEXT NOT NULL,
    title TEXT NOT NULL,
    fixes TEXT NOT NULL,
    backup TEXT,
    user TEXT
);
CREATE TABLE IF NOT EXISTS changes(
    id INTEGER PRIMARY KEY,
    batch_id INTEGER NOT NULL REFERENCES batches(id),
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    params TEXT NOT NULL,
    summary TEXT NOT NULL,
    fix_id TEXT,
    finding_id TEXT,
    before TEXT,
    status TEXT NOT NULL,
    verified INTEGER,
    error TEXT,
    applied_at TEXT,
    reverted_at TEXT
);
CREATE INDEX IF NOT EXISTS changes_batch ON changes(batch_id);
"""

PENDING, APPLIED, FAILED, REVERTED, REVERT_FAILED = (
    "pending",
    "applied",
    "failed",
    "reverted",
    "revert_failed",
)


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class ChangeRecord:
    id: int
    batch_id: int
    seq: int
    kind: str
    params: dict[str, Any]
    summary: str
    fix_id: str | None
    finding_id: str | None
    before: dict[str, Any] | None
    status: str
    verified: bool | None
    error: str | None
    applied_at: str | None
    reverted_at: str | None

    @property
    def spec(self) -> ActionSpec:
        return ActionSpec(self.kind, self.params, self.summary)

    @property
    def active(self) -> bool:
        return self.status == APPLIED

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class BatchRecord:
    id: int
    created: str
    title: str
    fixes: list[str]
    backup: str | None
    user: str | None


class Journal:
    def __init__(self, path: Path, readonly: bool = False) -> None:
        self.path = Path(path)
        self.readonly = readonly
        if not readonly:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as db, db:
                db.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        if self.readonly:
            db = sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True)
        else:
            db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    @property
    def available(self) -> bool:
        return not self.readonly or self.path.exists()

    def _write(self, sql: str, args: tuple[Any, ...]) -> int:
        if self.readonly:
            raise PermissionError("the change journal is read-only without administrator rights")
        with closing(self._connect()) as db, db:
            cur = db.execute(sql, args)
            return int(cur.lastrowid or 0)

    # ----------------------------------------------------------------- writing
    def begin_batch(self, title: str, fixes: list[str], user: str = "") -> int:
        return self._write(
            "INSERT INTO batches(created, title, fixes, user) VALUES (?, ?, ?, ?)",
            (_now(), title, json.dumps(fixes), user),
        )

    def set_backup(self, batch_id: int, path: str) -> None:
        self._write("UPDATE batches SET backup=? WHERE id=?", (path, batch_id))

    def add_change(
        self,
        batch_id: int,
        seq: int,
        spec: ActionSpec,
        before: dict[str, Any] | None,
        fix_id: str | None = None,
        finding_id: str | None = None,
    ) -> int:
        return self._write(
            "INSERT INTO changes(batch_id, seq, kind, params, summary, fix_id, finding_id, before, status)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                batch_id,
                seq,
                spec.kind,
                json.dumps(spec.params),
                spec.summary,
                fix_id,
                finding_id,
                json.dumps(before),
                PENDING,
            ),
        )

    def mark_applied(self, change_id: int) -> None:
        self._write(
            "UPDATE changes SET status=?, applied_at=?, error=NULL WHERE id=?",
            (APPLIED, _now(), change_id),
        )

    def mark_failed(self, change_id: int, error: str) -> None:
        self._write(
            "UPDATE changes SET status=?, error=? WHERE id=?", (FAILED, error[:2000], change_id)
        )

    def set_verified(self, change_id: int, ok: bool) -> None:
        self._write("UPDATE changes SET verified=? WHERE id=?", (1 if ok else 0, change_id))

    def mark_reverted(self, change_id: int) -> None:
        self._write(
            "UPDATE changes SET status=?, reverted_at=?, error=NULL WHERE id=?",
            (REVERTED, _now(), change_id),
        )

    def mark_revert_failed(self, change_id: int, error: str) -> None:
        self._write(
            "UPDATE changes SET status=?, error=? WHERE id=?",
            (REVERT_FAILED, error[:2000], change_id),
        )

    # ----------------------------------------------------------------- reading
    def _rows(self, sql: str, args: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        if not self.available:
            return []
        with closing(self._connect()) as db:
            return list(db.execute(sql, args))

    @staticmethod
    def _change(row: sqlite3.Row) -> ChangeRecord:
        verified = row["verified"]
        return ChangeRecord(
            id=row["id"],
            batch_id=row["batch_id"],
            seq=row["seq"],
            kind=row["kind"],
            params=json.loads(row["params"]),
            summary=row["summary"],
            fix_id=row["fix_id"],
            finding_id=row["finding_id"],
            before=json.loads(row["before"]) if row["before"] else None,
            status=row["status"],
            verified=None if verified is None else bool(verified),
            error=row["error"],
            applied_at=row["applied_at"],
            reverted_at=row["reverted_at"],
        )

    def changes(self, batch_id: int | None = None) -> list[ChangeRecord]:
        if batch_id is None:
            rows = self._rows("SELECT * FROM changes ORDER BY id")
        else:
            rows = self._rows("SELECT * FROM changes WHERE batch_id=? ORDER BY id", (batch_id,))
        return [self._change(r) for r in rows]

    def change(self, change_id: int) -> ChangeRecord | None:
        rows = self._rows("SELECT * FROM changes WHERE id=?", (change_id,))
        return self._change(rows[0]) if rows else None

    def active_changes(self) -> list[ChangeRecord]:
        return [c for c in self.changes() if c.status in (APPLIED, REVERT_FAILED)]

    def batches(self) -> list[BatchRecord]:
        return [
            BatchRecord(
                r["id"], r["created"], r["title"], json.loads(r["fixes"]), r["backup"], r["user"]
            )
            for r in self._rows("SELECT * FROM batches ORDER BY id")
        ]
