"""Overview: score ring, Scan & Protect, counts, top fixes, network status, what changed."""

from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QPushButton, QVBoxLayout

from ...core.models import Severity
from .. import theme
from ..controller import Controller
from ..widgets import card, label
from ..widgets.finding_card import FindingCard
from ..widgets.score_ring import ScoreRing
from . import Page


class OverviewPage(Page):
    def __init__(self, ctl: Controller) -> None:
        super().__init__(
            "Overview", "What other devices can reach on this PC, and how to make it safer."
        )
        self.ctl = ctl

        top, tl = card()
        row = QHBoxLayout()
        tl.addLayout(row)
        self.ring = ScoreRing()
        row.addWidget(self.ring)
        right = QVBoxLayout()
        row.addLayout(right, 1)
        self.headline = label("Run a scan to see how this PC is doing.", object_name="SectionTitle")
        right.addWidget(self.headline)
        self.sub = label(
            "The scan is read-only: nothing changes until you choose a fix and confirm it.",
            object_name="Dim",
        )
        right.addWidget(self.sub)
        self.counts = QGridLayout()
        right.addLayout(self.counts)
        buttons = QHBoxLayout()
        self.scan_btn = QPushButton("Scan && Protect")
        self.scan_btn.setObjectName("Primary")
        self.scan_btn.setMinimumHeight(34)
        self.scan_btn.clicked.connect(lambda: ctl.start_scan())
        buttons.addWidget(self.scan_btn)
        self.fix_btn = QPushButton("Fix recommended")
        self.fix_btn.setToolTip(
            "Applies only safe, non-disruptive fixes (you see a preview first)."
        )
        self.fix_btn.clicked.connect(ctl.request_recommended)
        self.fix_btn.setEnabled(False)
        buttons.addWidget(self.fix_btn)
        buttons.addStretch(1)
        right.addLayout(buttons)
        right.addStretch(1)
        self.body.addWidget(top)

        self.network_card, self.network_layout = card()
        self.body.addWidget(self.network_card)
        self.network_card.hide()

        self.body.addWidget(label("Top things to look at", object_name="SectionTitle"))
        self.top_box = QVBoxLayout()
        self.body.addLayout(self.top_box)
        self.top_box.addWidget(label("No scan yet.", object_name="Dim"))

        self.changes_title = label("What changed since the last scan", object_name="SectionTitle")
        self.body.addWidget(self.changes_title)
        self.changes_card, self.changes_layout = card()
        self.body.addWidget(self.changes_card)
        self.changes_title.hide()
        self.changes_card.hide()

        ctl.busy_changed.connect(self._busy)
        ctl.scan_finished.connect(self.show_result)

    def _busy(self, busy: bool, text: str) -> None:
        self.scan_btn.setEnabled(not busy)
        self.fix_btn.setEnabled(
            not busy and bool(self.ctl.result and self.ctl.engine.recommended(self.ctl.result))
        )
        if busy and text:
            self.sub.setText(text)

    def show_result(self, result: object) -> None:
        from ...core.engine import ScanResult

        assert isinstance(result, ScanResult)
        self.ring.set_score(result.score, result.grade)
        opened = result.open_findings
        if not opened:
            self.headline.setText("Nothing needs your attention right now.")
        elif result.counts()["critical"] or result.counts()["high"]:
            self.headline.setText(f"{len(opened)} things to look at, some of them important.")
        else:
            self.headline.setText(f"{len(opened)} things you could improve.")
        mode = (
            ""
            if result.is_admin
            else " Read-only mode: fixes will ask for administrator permission."
        )
        self.sub.setText(
            f"Last scan {result.started.replace('T', ' ')[:16]} on {result.computer}.{mode}"
        )

        self.clear(self.counts)  # type: ignore[arg-type]
        for col, (name, n) in enumerate(result.counts().items()):
            sev = Severity[name.upper()]
            lbl = label(
                f"<span style='font-size:16pt; font-weight:600; color:{theme.SEVERITY_COLORS[sev]}'>{n}</span><br>{sev.label}",
                rich=True,
            )
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.counts.addWidget(lbl, 0, col)
        self.fix_btn.setEnabled(bool(self.ctl.engine.recommended(result)))

        self.clear(self.network_layout)
        lines = result.network_status()
        if lines:
            self.network_layout.addWidget(label("Network status", object_name="SectionTitle"))
            for line in lines:
                self.network_layout.addWidget(label(html.escape(line)))
            self.network_card.show()

        self.clear(self.top_box)
        top = opened[:5]
        if not top:
            self.top_box.addWidget(
                label("Nothing needs your attention. Well done.", object_name="Dim")
            )
        for f in top:
            c = FindingCard(f, compact=True)
            c.fix_requested.connect(self.ctl.request_fix)
            c.keep_requested.connect(self.ctl.keep)
            self.top_box.addWidget(c)

        self.clear(self.changes_layout)
        diff = self.ctl.comparison()
        if diff is None or self.ctl.previous is None:
            self.changes_title.hide()
            self.changes_card.hide()
            return
        self.changes_title.show()
        self.changes_card.show()
        if diff.empty:
            self.changes_layout.addWidget(
                label("No changes since the previous scan.", object_name="Dim")
            )
            return
        if diff.score_change:
            self.changes_layout.addWidget(
                label(
                    f"Risk score {'up' if diff.score_change > 0 else 'down'} by {abs(diff.score_change)}."
                )
            )
        for f in diff.new_findings:
            self.changes_layout.addWidget(label(f"New: {html.escape(f['title'])}", rich=True))
        for f in diff.resolved_findings:
            self.changes_layout.addWidget(label(f"Resolved: {html.escape(f['title'])}", rich=True))
        for item in diff.new_listeners:
            self.changes_layout.addWidget(label(f"Newly reachable: {html.escape(item)}", rich=True))
        for item in diff.gone_listeners:
            self.changes_layout.addWidget(
                label(f"No longer reachable: {html.escape(item)}", rich=True)
            )
        for d in diff.new_devices:
            self.changes_layout.addWidget(
                label(f"New device: {html.escape(str(d.get('name') or d.get('ip')))}", rich=True)
            )
