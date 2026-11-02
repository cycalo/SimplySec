"""The fix flow: preview the exact changes, then show each change Verified or not."""

from __future__ import annotations

import html
from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...core.checks.base import Warning_
from ...core.engine import Plan
from . import label


@dataclass
class PreviewChoice:
    accepted: bool
    restore_point: bool
    extra: list[Warning_]  # warnings whose offered fix the user ticked (e.g. mark network Private)


class PreviewDialog(QDialog):
    def __init__(self, plan: Plan, is_admin: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Review changes")
        self.setMinimumWidth(620)
        self.plan = plan
        self._offers: list[tuple[QCheckBox, Warning_]] = []
        layout = QVBoxLayout(self)
        layout.addWidget(
            label("SimplySec will make exactly these changes:", object_name="SectionTitle")
        )

        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 0, 0, 0)
        seen_offers: set[str] = set()
        for item in plan.items:
            bl.addWidget(
                label(
                    f"<b>{html.escape(item.fix.label)}</b> – {html.escape(item.fix.description)}",
                    rich=True,
                )
            )
            items = "".join(f"<li>{html.escape(s.summary)}</li>" for s in item.specs)
            bl.addWidget(label(f"<ul style='margin-top:0'>{items}</ul>", rich=True))
            for w in item.warnings:
                warn = label(f"<b>Heads-up:</b> {html.escape(w.text)}", rich=True)
                warn.setObjectName("Banner")
                bl.addWidget(warn)
                if w.offer_fix:
                    key = f"{w.offer_fix}:{sorted(w.offer_params.items())}"
                    if key in seen_offers:
                        continue
                    seen_offers.add(key)
                    box = QCheckBox(w.offer_label or "Do this first")
                    box.setChecked(False)
                    bl.addWidget(box)
                    self._offers.append((box, w))
        if plan.might_break:
            bl.addWidget(label("What might stop working", object_name="SectionTitle"))
            bl.addWidget(
                label(
                    "<ul>"
                    + "".join(f"<li>{html.escape(x)}</li>" for x in plan.might_break)
                    + "</ul>",
                    rich=True,
                )
            )
        for r in plan.refused:
            bl.addWidget(label(f"Not included: {html.escape(r)}", object_name="Dim"))
        bl.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(body)
        scroll.setMinimumHeight(260)
        layout.addWidget(scroll, 1)

        self.restore = QCheckBox("Also create a System Restore point first (takes a minute)")
        layout.addWidget(self.restore)
        note = "Every change is recorded with its previous value and can be undone on the Changes page."
        if not is_admin:
            note += " Windows will ask for administrator permission to apply them."
        layout.addWidget(label(note, object_name="Dim"))

        buttons = QDialogButtonBox()
        apply_btn = buttons.addButton("Apply changes", QDialogButtonBox.ButtonRole.AcceptRole)
        apply_btn.setObjectName("Primary")
        buttons.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def choice(self) -> PreviewChoice:
        return PreviewChoice(
            accepted=self.result() == QDialog.DialogCode.Accepted,
            restore_point=self.restore.isChecked(),
            extra=[w for box, w in self._offers if box.isChecked()],
        )


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
