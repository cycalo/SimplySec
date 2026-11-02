"""Open ports: Port, Program (publisher), Listening on, Reachable from, Risk, Action."""

from __future__ import annotations

import html
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QTableView,
)

from ...core.engine import PortRow
from ...core.models import Verdict
from .. import theme
from ..controller import Controller
from ..widgets import label
from . import Page

COLUMNS = ["Port", "Program (publisher)", "Listening on", "Reachable from", "Risk", "Action"]


class PortModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self.rows: list[PortRow] = []

    def set_rows(self, rows: list[PortRow]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | None = None) -> int:
        return len(self.rows)

    def columnCount(self, parent: QModelIndex | None = None) -> int:
        return len(COLUMNS)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        r = self.rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return f"{r.protocol.upper()} {r.port}"
            if col == 1:
                pub = f" ({r.publisher})" if r.publisher else ""
                svc = f" [{', '.join(r.services)}]" if r.services else ""
                return f"{r.process}{svc}{pub}"
            if col == 2:
                return r.listening_on
            if col == 3:
                return r.reachable_from
            if col == 4:
                return r.risk.label if r.verdict == Verdict.REACHABLE else "–"
            if col == 5:
                if r.finding_id:
                    return "Review…"
                return "Details…"
        if role == Qt.ItemDataRole.UserRole:  # sort keys
            if col == 0:
                return (r.port, r.protocol)
            if col == 4:
                return int(r.risk) if r.verdict == Verdict.REACHABLE else -1
            return self.data(index, Qt.ItemDataRole.DisplayRole)
        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 4 and r.verdict == Verdict.REACHABLE:
                return QColor(theme.SEVERITY_COLORS[r.risk])
            if col == 3 and r.verdict == Verdict.UNCERTAIN:
                return QColor(theme.SEVERITY_COLORS[r.risk.MEDIUM])
            if col == 5:
                return QColor(theme.colors().accent)
        if role == Qt.ItemDataRole.ToolTipRole:
            return r.reason
        return None


class PortFilter(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self.reachable_only = True
        self.setSortRole(Qt.ItemDataRole.UserRole)

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        model = self.sourceModel()
        assert isinstance(model, PortModel)
        r = model.rows[row]
        if self.reachable_only:
            return r.verdict in (Verdict.REACHABLE, Verdict.UNCERTAIN)
        return True

    def lessThan(self, a: QModelIndex, b: QModelIndex) -> bool:
        va, vb = a.data(Qt.ItemDataRole.UserRole), b.data(Qt.ItemDataRole.UserRole)
        try:
            return bool(va < vb)
        except TypeError:
            return str(va) < str(vb)


class PortsPage(Page):
    def __init__(self, ctl: Controller) -> None:
        super().__init__(
            "Open ports",
            "Programs that listen for connections, and who can actually reach them through the firewall.",
        )
        self.ctl = ctl
        row = QHBoxLayout()
        self.only = QCheckBox("Reachable only")
        self.only.setChecked(True)
        self.only.toggled.connect(self._toggle)
        row.addWidget(self.only)
        self.count = label("", object_name="Dim")
        row.addWidget(self.count, 1)
        self.body.addLayout(row)

        self.model = PortModel()
        self.proxy = PortFilter()
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(4, Qt.SortOrder.DescendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        self.table.setMinimumHeight(460)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setStretchLastSection(False)
        for col, width in enumerate([90, 260, 180, 330, 80, 90]):
            self.table.setColumnWidth(col, width)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.clicked.connect(self._clicked)
        self.table.doubleClicked.connect(self._details)
        self.body.addWidget(self.table)
        self.body.addWidget(
            label(
                "Click 'Review…' to see the finding and its fixes, or double-click a row for the exact firewall rules and reasons.",
                object_name="Dim",
            )
        )
        ctl.scan_finished.connect(self.show_result)

    def _toggle(self, on: bool) -> None:
        self.proxy.reachable_only = on
        self.proxy.invalidateFilter()
        self._update_count()

    def _update_count(self) -> None:
        total = len(self.model.rows)
        reach = sum(1 for r in self.model.rows if r.verdict == Verdict.REACHABLE)
        unc = sum(1 for r in self.model.rows if r.verdict == Verdict.UNCERTAIN)
        self.count.setText(
            f"{total} listening, {reach} reachable from other devices, {unc} uncertain"
        )

    def show_result(self, result: object) -> None:
        from ...core.engine import ScanResult

        assert isinstance(result, ScanResult)
        self.model.set_rows(result.ports)
        self._update_count()

    def _row(self, index: QModelIndex) -> PortRow:
        return self.model.rows[self.proxy.mapToSource(index).row()]

    def _clicked(self, index: QModelIndex) -> None:
        if index.column() != 5:
            return
        r = self._row(index)
        if r.finding_id and self.ctl.result:
            f = self.ctl.result.finding(r.finding_id)
            if f and f.fixes:
                from PySide6.QtWidgets import QDialog, QVBoxLayout

                from ..widgets.finding_card import FindingCard

                dlg = QDialog(self)
                dlg.setWindowTitle(f.title)
                dlg.setMinimumWidth(620)
                lay = QVBoxLayout(dlg)
                c = FindingCard(f)
                c.fix_requested.connect(
                    lambda fi, opt: (dlg.accept(), self.ctl.request_fix(fi, opt))
                )
                c.keep_requested.connect(lambda fi: (dlg.accept(), self.ctl.keep(fi)))
                lay.addWidget(c)
                dlg.exec()
                return
        self._details(index)

    def _details(self, index: QModelIndex) -> None:
        r = self._row(index)
        rules = "".join(f"<li>{html.escape(n)}</li>" for n in r.rules) or "<li>none</li>"
        text = (
            f"<b>{html.escape(r.protocol.upper())} {r.port}</b> – {html.escape(r.process)} (PID {r.pid})<br>"
            f"{html.escape(r.exe)}<br><br><b>Listening on:</b> {html.escape(r.listening_on)}<br>"
            f"<b>Reachable from:</b> {html.escape(r.reachable_from)}<br><br>{html.escape(r.reason)}<br><br>"
            f"<b>Firewall rules involved:</b><ul>{rules}</ul>"
        )
        box = QMessageBox(self)
        box.setWindowTitle("Port details")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(text)
        box.exec()
