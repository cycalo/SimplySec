"""This PC: every finding as a card, most serious first (topic shown on each card)."""

from __future__ import annotations

from PySide6.QtWidgets import QCheckBox

from ...core.models import FindingStatus, Severity
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
        self.show_info = QCheckBox("Also show informational items and risks you chose to keep")
        self.show_info.setChecked(False)
        self.show_info.toggled.connect(lambda _: self.refresh())
        self.layout_.insertWidget(2, self.show_info)
        self.body.addWidget(label("Run a scan from the Overview page.", object_name="Dim"))
        ctl.scan_finished.connect(lambda _r: self.refresh())

    def refresh(self) -> None:
        result = self.ctl.result
        if result is None:
            return
        self.clear()
        self.cards: dict[str, FindingCard] = {}
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
        other = ("lan", "router")  # advice about other devices, not this PC's settings
        groups = [
            (
                "Needs attention",
                lambda f: f.scored and f.severity >= Severity.HIGH and f.check not in other,
            ),
            (
                "Worth fixing",
                lambda f: f.scored and f.severity == Severity.MEDIUM and f.check not in other,
            ),
            ("Minor", lambda f: f.scored and f.severity == Severity.LOW and f.check not in other),
            (
                "Other devices on your network and your router",
                lambda f: f.scored and f.check in other,
            ),
            ("For information and kept risks", lambda f: not f.scored),
        ]
        for title, test in groups:
            items = sorted(
                (f for f in findings if test(f)),
                key=lambda f: (
                    -int(f.severity),
                    AREA_ORDER.index(f.area) if f.area in AREA_ORDER else 99,
                    f.title,
                ),
            )
            if not items:
                continue
            self.body.addWidget(label(f"{title} ({len(items)})", object_name="SectionTitle"))
            for f in items:
                c = FindingCard(f, show_area=True)
                c.fix_requested.connect(self.ctl.request_fix)
                c.keep_requested.connect(self.ctl.keep)
                c.unkeep_requested.connect(lambda fi: self.ctl.unkeep(fi.keep_key))
                self.cards[f.id] = c
                self.body.addWidget(c)
