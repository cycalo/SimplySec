"""This PC: every finding as a card, grouped by area."""

from __future__ import annotations

from PySide6.QtWidgets import QCheckBox

from ...core.models import FindingStatus
from ..controller import Controller
from ..widgets import label
from ..widgets.finding_card import FindingCard
from . import Page

AREA_ORDER = [
    "Firewall",
    "Exposure",
    "Remote access",
    "Legacy protocols",
    "File sharing",
    "Malware protection",
    "Updates",
    "Accounts",
    "System",
    "Home network",
    "Wi-Fi",
    "Router",
    "Housekeeping",
]


class ThisPcPage(Page):
    def __init__(self, ctl: Controller) -> None:
        super().__init__(
            "This PC",
            "Each finding explains what it means. Nothing changes until you choose a fix and confirm it.",
        )
        self.ctl = ctl
        self.show_info = QCheckBox("Show informational items and kept risks")
        self.show_info.setChecked(True)
        self.show_info.toggled.connect(lambda _: self.refresh())
        self.layout_.insertWidget(2, self.show_info)
        self.body.addWidget(label("Run a scan from the Overview page.", object_name="Dim"))
        ctl.scan_finished.connect(lambda _r: self.refresh())

    def refresh(self) -> None:
        result = self.ctl.result
        if result is None:
            return
        self.clear()
        findings = [
            f
            for f in result.findings
            if self.show_info.isChecked() or (f.status == FindingStatus.OPEN and f.scored)
        ]
        if not findings:
            self.body.addWidget(
                label("No findings. Nothing needs your attention.", object_name="Dim")
            )
            return
        areas = sorted(
            {f.area for f in findings}, key=lambda a: AREA_ORDER.index(a) if a in AREA_ORDER else 99
        )
        for area in areas:
            items = [f for f in findings if f.area == area]
            open_n = sum(1 for f in items if f.scored)
            suffix = f" – {open_n} to look at" if open_n else ""
            self.body.addWidget(label(f"{area}{suffix}", object_name="SectionTitle"))
            for f in items:
                c = FindingCard(f)
                c.fix_requested.connect(self.ctl.request_fix)
                c.keep_requested.connect(self.ctl.keep)
                c.unkeep_requested.connect(lambda fi: self.ctl.unkeep(fi.keep_key))
                self.body.addWidget(c)
