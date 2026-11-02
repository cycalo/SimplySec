"""The fix flow: preview the exact changes, then show each change Verified or not."""

from __future__ import annotations

import html
from dataclasses import dataclass, field

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...core.checks.base import Warning_
from ...core.engine import Plan
from ...core.impact import Impact, Level
from ...core.models import Finding
from . import label

IMPACT_COLORS = {
    "in_use": "#C42B1C",
    "may_affect": "#B76E00",
    "none_found": "#0F7B0F",
    "unknown": "#6B6B6B",
}


def impact_html(impact: Impact, limit: int = 8) -> str:
    color = IMPACT_COLORS[impact.level.value]
    lines = "".join(f"<li>{html.escape(e)}</li>" for e in impact.evidence[:limit])
    more = (
        f"<li>…and {len(impact.evidence) - limit} more</li>" if len(impact.evidence) > limit else ""
    )
    return (
        f"<b>What uses this: <span style='color:{color}'>{html.escape(impact.level.label)}</span></b>"
        f"<br>{html.escape(impact.headline)}"
        + (f"<ul style='margin-top:2px; margin-bottom:0'>{lines}{more}</ul>" if lines else "")
    )


@dataclass
class PreviewChoice:
    accepted: bool
    restore_point: bool
    extra: list[Warning_]  # warnings whose offered fix the user ticked (e.g. mark network Private)
    included: list[int] = field(default_factory=list)  # indexes into plan.items the user kept


class PreviewDialog(QDialog):
    """Lists each fix with why it's suggested, exactly what changes, what uses it now, and
    what might stop working. Each fix has its own tick box; fixes that are in use right now
    start unticked."""

    def __init__(
        self,
        plan: Plan,
        is_admin: bool,
        parent: QWidget | None = None,
        findings: dict[str, Finding] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Review changes")
        self.setMinimumWidth(680)
        self.resize(720, 640)
        self.plan = plan
        self._offers: list[tuple[QCheckBox, Warning_]] = []
        self._items: list[QCheckBox] = []
        layout = QVBoxLayout(self)
        intro = "Review each change. Untick anything you want to keep as it is."
        layout.addWidget(label(intro, object_name="SectionTitle"))

        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(10)
        seen_offers: set[str] = set()
        for item in plan.items:
            card, cl = card_frame()
            box = QCheckBox(f"{item.fix.label}")
            box.setStyleSheet("font-weight:600; font-size:11pt;")
            in_use = item.impact is not None and item.impact.level == Level.IN_USE
            box.setChecked(not in_use)
            self._items.append(box)
            cl.addWidget(box)
            finding = (findings or {}).get(item.finding_id or "")
            if finding is not None:
                cl.addWidget(
                    label(
                        f"<b>Why:</b> {html.escape(finding.title)}. {html.escape(finding.what_it_means)}",
                        rich=True,
                    )
                )
            changes = "".join(f"<li>{html.escape(s.summary)}</li>" for s in item.specs)
            cl.addWidget(
                label(
                    f"<b>What changes:</b> {html.escape(item.fix.description)}"
                    f"<ul style='margin-top:2px; margin-bottom:0'>{changes}</ul>",
                    rich=True,
                )
            )
            if item.impact is not None:
                imp = label(impact_html(item.impact), rich=True)
                imp.setObjectName("Banner")
                cl.addWidget(imp)
            if item.fix.might_break:
                cl.addWidget(
                    label(
                        f"<b>Might stop working:</b> {html.escape(item.fix.might_break)}", rich=True
                    )
                )
            for w in item.warnings:
                warn = label(f"<b>Heads-up:</b> {html.escape(w.text)}", rich=True)
                warn.setObjectName("Banner")
                cl.addWidget(warn)
                if w.offer_fix:
                    key = f"{w.offer_fix}:{sorted(w.offer_params.items())}"
                    if key in seen_offers:
                        continue
                    seen_offers.add(key)
                    offer = QCheckBox(w.offer_label or "Do this first")
                    offer.setChecked(False)
                    cl.addWidget(offer)
                    self._offers.append((offer, w))
            if in_use:
                cl.addWidget(
                    label(
                        "Left unticked because something is using it right now. Tick it only if you're sure.",
                        object_name="Dim",
                    )
                )
            bl.addWidget(card)
        for r in plan.refused:
            bl.addWidget(label(f"Not included: {html.escape(r)}", object_name="Dim"))
        bl.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(body)
        scroll.setMinimumHeight(300)
        layout.addWidget(scroll, 1)

        self.restore = QCheckBox("Also create a System Restore point first (takes a minute)")
        layout.addWidget(self.restore)
        note = "Every change is recorded with its previous value and can be undone on the Changes page."
        if not is_admin:
            note += " Windows will ask for administrator permission to apply them."
        layout.addWidget(label(note, object_name="Dim"))

        buttons = QDialogButtonBox()
        self.apply_btn = buttons.addButton(
            "Apply ticked changes", QDialogButtonBox.ButtonRole.AcceptRole
        )
        self.apply_btn.setObjectName("Primary")
        buttons.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        for box in self._items:
            box.toggled.connect(self._update_apply)
        self._update_apply()

    def _update_apply(self) -> None:
        n = sum(b.isChecked() for b in self._items)
        self.apply_btn.setEnabled(n > 0)
        self.apply_btn.setText(
            f"Apply {n} change{'s' if n != 1 else ''}" if n else "Nothing ticked"
        )

    def choice(self) -> PreviewChoice:
        return PreviewChoice(
            accepted=self.result() == QDialog.DialogCode.Accepted,
            restore_point=self.restore.isChecked(),
            extra=[w for box, w in self._offers if box.isChecked()],
            included=[i for i, b in enumerate(self._items) if b.isChecked()],
        )


def card_frame() -> tuple[QFrame, QVBoxLayout]:
    from . import card

    return card(margins=12, spacing=6)


@dataclass
class ResultLine:
    summary: str
    status: str
    verified: bool | None
    error: str = ""


class ResultDialog(QDialog):
    def __init__(
        self,
        lines: list[ResultLine],
        resolved: dict[str, bool],
        titles: dict[str, str],
        score_before: int | None,
        score_after: int | None,
        warnings: list[str],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Changes applied")
        self.setMinimumWidth(600)
        layout = QVBoxLayout(self)
        layout.addWidget(
            label("Each change was checked again after applying it:", object_name="SectionTitle")
        )
        for line in lines:
            if line.status == "applied" and line.verified:
                mark, color = "Verified ✓", "#0F7B0F"
            elif line.status == "applied":
                mark, color = "Not verified ✗", "#C42B1C"
            else:
                mark, color = f"{line.status.title()} ✗", "#C42B1C"
            text = f"<span style='color:{color}; font-weight:600'>{mark}</span>&nbsp; {html.escape(line.summary)}"
            if line.error:
                text += f"<br><span style='color:{color}'>{html.escape(line.error)}</span>"
            layout.addWidget(label(text, rich=True))
        if resolved:
            layout.addWidget(label("Fresh scan", object_name="SectionTitle"))
            for fid, ok in resolved.items():
                mark = (
                    "<span style='color:#0F7B0F'>Resolved ✓</span>"
                    if ok
                    else "<span style='color:#C42B1C'>Still present ✗</span>"
                )
                layout.addWidget(
                    label(f"{mark}&nbsp; {html.escape(titles.get(fid, fid))}", rich=True)
                )
        if score_before is not None and score_after is not None:
            layout.addWidget(label(f"Score: {score_before} → {score_after}"))
        for w in warnings:
            layout.addWidget(label(f"Note: {html.escape(w)}", object_name="Dim", rich=True))
        layout.addWidget(label("You can undo any of this on the Changes page.", object_name="Dim"))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


def info_label(text: str) -> QLabel:
    lbl = label(text)
    lbl.setAlignment(Qt.AlignmentFlag.AlignLeft)
    return lbl
