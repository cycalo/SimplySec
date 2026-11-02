"""History: score trend, past scans with new and resolved findings, and the HTML report."""

from __future__ import annotations

import html
import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
)

from ...core.history import compare
from ..controller import Controller
from ..widgets import card, label
from ..widgets.trend_chart import TrendChart
from . import Page


class HistoryPage(Page):
    def __init__(self, ctl: Controller) -> None:
        super().__init__(
            "History", "How this PC's score changed over time, and what each scan found."
        )
        self.ctl = ctl
        chart_card, cl = card()
        cl.addWidget(label("Score over time", object_name="SectionTitle"))
        self.chart = TrendChart()
        cl.addWidget(self.chart)
        self.body.addWidget(chart_card)

        row = QHBoxLayout()
        self.export = QPushButton("Export HTML report…")
        self.export.setObjectName("Primary")
        self.export.clicked.connect(self._export)
        row.addWidget(self.export)
        row.addStretch(1)
        self.body.addLayout(row)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Scan", "Type", "Score", "Change"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.setMinimumHeight(220)
        self.tree.currentItemChanged.connect(lambda cur, _prev: self._show(cur))
        self.body.addWidget(self.tree)
        self.detail_card, self.detail = card()
        self.body.addWidget(self.detail_card)
        ctl.scan_finished.connect(lambda _r: self.refresh())
        self.refresh()

    def refresh(self) -> None:
        history = self.ctl.engine.history
        scans = history.scans(limit=200)
        self.chart.set_points([(s.ts[:10], s.score) for s in reversed(scans[:60])])
        self.tree.clear()
        for i, s in enumerate(scans):
            change = ""
            if i + 1 < len(scans):
                delta = s.score - scans[i + 1].score
                change = f"{delta:+d}" if delta else "–"
            item = QTreeWidgetItem(
                [s.ts[:16].replace("T", " "), s.kind, f"{s.score} ({s.grade})", change]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, s.id)
            self.tree.addTopLevelItem(item)
        if scans:
            self.tree.setCurrentItem(self.tree.topLevelItem(0))
        else:
            self.clear(self.detail)
            self.detail.addWidget(label("No scans saved yet.", object_name="Dim"))

    def _show(self, item: QTreeWidgetItem | None) -> None:
        self.clear(self.detail)
        if item is None:
            return
        history = self.ctl.engine.history
        scan_id = item.data(0, Qt.ItemDataRole.UserRole)
        data = history.scan_data(scan_id)
        if data is None:
            return
        diff = compare(history.previous_to(scan_id), data)
        self.detail.addWidget(
            label(
                f"Scan of {html.escape(item.text(0))}: score {data.get('score')} ({data.get('grade')})",
                object_name="SectionTitle",
            )
        )
        if diff.empty:
            self.detail.addWidget(
                label(
                    "Nothing changed compared with the scan before."
                    if history.previous_to(scan_id)
                    else "The first saved scan.",
                    object_name="Dim",
                )
            )
        for f in diff.new_findings:
            self.detail.addWidget(
                label(f"<b>New:</b> {html.escape(f['title'])} ({f['severity']})", rich=True)
            )
        for f in diff.resolved_findings:
            self.detail.addWidget(label(f"<b>Resolved:</b> {html.escape(f['title'])}", rich=True))
        for x in diff.new_listeners:
            self.detail.addWidget(label(f"<b>Newly reachable:</b> {html.escape(x)}", rich=True))
        for x in diff.gone_listeners:
            self.detail.addWidget(label(f"<b>No longer reachable:</b> {html.escape(x)}", rich=True))
        for d in diff.new_devices:
            self.detail.addWidget(
                label(
                    f"<b>New device:</b> {html.escape(str(d.get('name') or d.get('ip')))}",
                    rich=True,
                )
            )

    def _export(self) -> None:
        result = self.ctl.result
        if result is None:
            QMessageBox.information(self, "Scan first", "Run a scan first, then export the report.")
            return
        default = str(Path.home() / "Documents" / f"SimplySec-report-{result.started[:10]}.html")
        path, _ = QFileDialog.getSaveFileName(self, "Save report", default, "HTML report (*.html)")
        if not path:
            return
        from ...core.report.html import write_report

        try:
            out = write_report(Path(path), result, self.ctl.engine)
        except Exception as exc:
            QMessageBox.warning(self, "Report", f"Could not write the report: {exc}")
            return
        os.startfile(out)
