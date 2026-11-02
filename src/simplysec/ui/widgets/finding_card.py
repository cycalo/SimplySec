"""A finding as a card: plain title, what it means, technical details, Fix / Keep / Learn more."""

from __future__ import annotations

import html

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QMenu, QToolButton, QVBoxLayout, QWidget

from ...core.impact import Impact
from ...core.models import Finding, FindingStatus, FixOption, Severity
from .. import theme
from . import label
from .fix_dialogs import IMPACT_COLORS

STATUS_TEXT = {
    FindingStatus.ACCEPTED: ("Kept", "#5D5D5D"),
    FindingStatus.MANAGED: ("Managed by your organisation", "#5D5D5D"),
    FindingStatus.INFO: ("For information", "#5D5D5D"),
}


class FindingCard(QFrame):
    """``compact`` (Overview): title, what it means, Fix, Keep, and "Show more" for the rest."""

    fix_requested = Signal(object, object)  # Finding, FixOption
    keep_requested = Signal(object)  # Finding
    unkeep_requested = Signal(object)  # Finding

    def __init__(
        self,
        finding: Finding,
        parent: QWidget | None = None,
        compact: bool = False,
        show_area: bool = False,
        show_advice: bool = False,
    ) -> None:
        super().__init__(parent)
        self.finding = finding
        self.setObjectName("Card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(6)

        sev_color = theme.SEVERITY_COLORS[finding.severity]
        head = QHBoxLayout()
        chip = QLabel(theme.chip(finding.severity.label, sev_color))
        chip.setTextFormat(Qt.TextFormat.RichText)
        head.addWidget(chip, 0, Qt.AlignmentFlag.AlignTop)
        title = label(html.escape(finding.title), rich=True)
        title.setStyleSheet("font-weight:600; font-size:11pt;")
        head.addWidget(title, 1)
        if finding.status in STATUS_TEXT:
            text, color = STATUS_TEXT[finding.status]
            st = QLabel(theme.chip(text, color))
            st.setTextFormat(Qt.TextFormat.RichText)
            head.addWidget(st, 0, Qt.AlignmentFlag.AlignTop)
        if show_area:
            area = QLabel(finding.area)
            area.setObjectName("Dim")
            head.addWidget(area, 0, Qt.AlignmentFlag.AlignTop)
        if finding.user_configured:
            st = QLabel(theme.chip("You set this up", "#0F6CBD"))
            st.setTextFormat(Qt.TextFormat.RichText)
            head.addWidget(st, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(head)

        what = label(f"<b>What this means:</b> {html.escape(finding.what_it_means)}", rich=True)
        outer.addWidget(what)

        # Extra sections. On the full card the impact line is always shown and the rest is
        # behind its own link; on a compact card everything extra sits behind "Show more".
        self.impact = self._impact_label()
        self.details = label(self._details_html(), rich=True) if finding.details else None
        if self.details is not None:
            self.details.setObjectName("Dim")
            self.details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.learn = (
            label(f"<b>What to do:</b> {html.escape(finding.learn_more)}", rich=True)
            if finding.learn_more
            else None
        )
        for w in (self.impact, self.learn, self.details):
            if w is not None:
                outer.addWidget(w)
                w.setVisible(False)
        if self.impact is not None and not compact:
            self.impact.setVisible(True)
        if self.learn is not None and show_advice:
            self.learn.setVisible(True)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        actionable = [f for f in finding.fixes if f is not None]
        if actionable and finding.status in (FindingStatus.OPEN, FindingStatus.ACCEPTED):
            buttons.addWidget(self._fix_button(actionable))
        if finding.keep_key and finding.status == FindingStatus.OPEN:
            keep = QToolButton()
            keep.setText("Keep: I need this")
            keep.setToolTip(
                "Stop scoring this. It comes back only if it becomes reachable more widely."
            )
            keep.clicked.connect(lambda: self.keep_requested.emit(self.finding))
            buttons.addWidget(keep)
        elif finding.keep_key and finding.status == FindingStatus.ACCEPTED:
            unkeep = QToolButton()
            unkeep.setText("Score again")
            unkeep.clicked.connect(lambda: self.unkeep_requested.emit(self.finding))
            buttons.addWidget(unkeep)
        extras = [w for w in (self.impact, self.learn, self.details) if w is not None]
        if compact and extras:
            more = QToolButton()
            more.setObjectName("Link")
            closed = "Show more" if actionable else "How to fix"
            opened = "Show less" if actionable else "Hide advice"
            more.setText(closed)
            more.setCheckable(True)
            more.setToolTip("What uses this, advice and technical details")

            def toggle(on: bool) -> None:
                for w in extras:
                    w.setVisible(on)
                more.setText(opened if on else closed)

            more.toggled.connect(toggle)
            buttons.addWidget(more)
        elif not compact:
            if self.details is not None:
                tech = QToolButton()
                tech.setObjectName("Link")
                tech.setText("Technical details")
                tech.setCheckable(True)
                tech.toggled.connect(self.details.setVisible)
                buttons.addWidget(tech)
            if self.learn is not None and not show_advice:
                learn_btn = QToolButton()
                learn_btn.setObjectName("Link")
                learn_btn.setText("Learn more")
                learn_btn.setCheckable(True)
                learn_btn.toggled.connect(self.learn.setVisible)
                buttons.addWidget(learn_btn)
        buttons.addStretch(1)
        outer.addLayout(buttons)

    def _impact_label(self) -> QLabel | None:
        f = self.finding
        primary = next((o for o in f.fixes if o.impact), None)
        if primary is None or f.status != FindingStatus.OPEN:
            return None
        imp = Impact.from_dict(primary.impact)
        color = IMPACT_COLORS[imp.level.value]
        text = (
            f"<b>What uses this:</b> <span style='color:{color}'>{html.escape(imp.level.label)}</span>"
            f" – {html.escape(imp.headline)}"
        )
        if imp.evidence:
            text += "<br>" + "<br>".join(f"• {html.escape(e)}" for e in imp.evidence[:3])
            if len(imp.evidence) > 3:
                text += f"<br>• …and {len(imp.evidence) - 3} more (shown before you apply)"
        return label(text, rich=True)

    def _fix_button(self, fixes: list[FixOption]) -> QToolButton:
        btn = QToolButton()
        btn.setObjectName("Primary" if self.finding.severity >= Severity.MEDIUM else "")
        first = fixes[0]
        btn.setText(_fix_text(first))
        btn.clicked.connect(lambda: self.fix_requested.emit(self.finding, first))
        if len(fixes) > 1:
            menu = QMenu(btn)
            for opt in fixes:
                act = QAction(_fix_text(opt), menu)
                act.triggered.connect(
                    lambda _=False, o=opt: self.fix_requested.emit(self.finding, o)
                )
                menu.addAction(act)
            btn.setMenu(menu)
            btn.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        return btn

    def _details_html(self) -> str:
        rows = "".join(
            f"<tr><td style='padding-right:12px; vertical-align:top;'><b>{html.escape(k)}</b></td>"
            f"<td>{html.escape(v)}</td></tr>"
            for k, v in self.finding.details
        )
        return f"<table cellspacing='2'>{rows}</table><div>Finding id: {html.escape(self.finding.id)}</div>"


def _fix_text(opt: FixOption) -> str:
    if opt.guidance_only:
        return opt.label
    return f"Fix: {opt.label}"
