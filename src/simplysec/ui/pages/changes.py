"""Changes: every change SimplySec made, with Undo, Undo all and the firewall backups."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QHeaderView, QPushButton, QTreeWidget, QTreeWidgetItem

from ...app import paths
from ...core.journal import APPLIED, REVERT_FAILED
from ..controller import Controller
from ..widgets import label
from . import Page

STATUS = {
    "applied": "Active",
    "reverted": "Undone",
    "failed": "Failed",
    "revert_failed": "Undo failed",
    "pending": "Interrupted",
}


class ChangesPage(Page):
    def __init__(self, ctl: Controller) -> None:
        super().__init__(
            "Changes",
            "Everything SimplySec changed on this PC. Each change keeps its previous value, so it can be undone.",
        )
        self.ctl = ctl
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Change", "Status", "Verified", "When"])
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.tree.setMinimumHeight(380)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.itemSelectionChanged.connect(self._selection)
        self.body.addWidget(self.tree)

        row = QHBoxLayout()
        self.undo_btn = QPushButton("Undo selected")
        self.undo_btn.setEnabled(False)
        self.undo_btn.clicked.connect(self._undo_selected)
        row.addWidget(self.undo_btn)
        self.undo_all = QPushButton("Undo everything SimplySec changed")
        self.undo_all.clicked.connect(lambda: ctl.undo(everything=True))
        row.addWidget(self.undo_all)
        self.rules_btn = QPushButton("Remove all SimplySec rules")
        self.rules_btn.clicked.connect(lambda: ctl.undo(rules=True))
        row.addWidget(self.rules_btn)
        row.addStretch(1)
        backups = QPushButton("Open firewall backups")
        backups.clicked.connect(self._open_backups)
        row.addWidget(backups)
        self.body.addLayout(row)
        self.note = label("", object_name="Dim")
        self.body.addWidget(self.note)
        ctl.changes_updated.connect(self.refresh)
        ctl.busy_changed.connect(lambda busy, _t: self._busy(busy))
        self.refresh()

    def _busy(self, busy: bool) -> None:
        for b in (self.undo_all, self.rules_btn):
            b.setEnabled(not busy)
        self.undo_btn.setEnabled(not busy and bool(self._selected_ids()))

    def refresh(self) -> None:
        self.tree.clear()
        journal = self.ctl.journal()
        batches = {b.id: b for b in journal.batches()}
        items: dict[int, QTreeWidgetItem] = {}
        changes = journal.changes()
        for c in changes:
            parent = items.get(c.batch_id)
            if parent is None:
                b = batches.get(c.batch_id)
                parent = QTreeWidgetItem(
                    [
                        f"Batch {c.batch_id}: {b.title if b else ''}",
                        "",
                        "",
                        (b.created if b else "")[:16].replace("T", " "),
                    ]
                )
                parent.setData(0, Qt.ItemDataRole.UserRole, ("batch", c.batch_id))
                font = parent.font(0)
                font.setBold(True)
                parent.setFont(0, font)
                self.tree.addTopLevelItem(parent)
                items[c.batch_id] = parent
            verified = {True: "✓", False: "✗", None: ""}[c.verified]
            when = (c.reverted_at or c.applied_at or "")[:16].replace("T", " ")
            child = QTreeWidgetItem([c.summary, STATUS.get(c.status, c.status), verified, when])
            child.setData(0, Qt.ItemDataRole.UserRole, ("change", c.id))
            if c.error:
                child.setToolTip(0, c.error)
                child.setToolTip(1, c.error)
            parent.addChild(child)
        self.tree.expandAll()
        active = sum(1 for c in changes if c.status in (APPLIED, REVERT_FAILED))
        if not changes:
            self.note.setText("SimplySec has not changed anything on this PC yet.")
        else:
            self.note.setText(
                f"{active} active change(s). Firewall backups are kept in {paths.backups_dir()} (newest 10)."
                + ("" if self.ctl.is_admin else " Undo will ask for administrator permission.")
            )
        self.undo_all.setEnabled(active > 0)

    def _selected_ids(self) -> tuple[list[int], list[int]]:
        changes, batches = [], []
        for item in self.tree.selectedItems():
            kind, value = item.data(0, Qt.ItemDataRole.UserRole)
            (changes if kind == "change" else batches).append(value)
        return changes, batches

    def _selection(self) -> None:
        changes, batches = self._selected_ids()
        self.undo_btn.setEnabled(bool(changes or batches) and not self.ctl.busy)

    def _undo_selected(self) -> None:
        changes, batches = self._selected_ids()
        if batches and not changes and len(batches) == 1:
            self.ctl.undo(batch_id=batches[0])
        elif changes:
            self.ctl.undo(change_ids=changes)

    def _open_backups(self) -> None:
        folder = paths.backups_dir()
        if folder.exists():
            os.startfile(folder)
        else:
            self.note.setText(
                "No firewall backups yet: one is made before the first firewall change."
            )
