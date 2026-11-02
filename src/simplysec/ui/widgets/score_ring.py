"""Score ring with the grade in the middle (QPainter, no extra dependencies)."""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from .. import theme


class ScoreRing(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.score: int | None = None
        self.grade = "?"
        self.setMinimumSize(QSize(150, 150))

    def set_score(self, score: int | None, grade: str) -> None:
        self.score, self.grade = score, grade
        self.update()

    def sizeHint(self) -> QSize:
        return QSize(170, 170)

    def paintEvent(self, _event: object) -> None:
        c = theme.colors()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height()) - 16
        rect = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        pen = QPen(QColor(c.border), 12)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 0, 360 * 16)
        if self.score is not None:
            color = QColor(theme.GRADE_COLORS.get(self.grade, c.accent))
            pen.setColor(color)
            p.setPen(pen)
            p.drawArc(rect, 90 * 16, -int(360 * 16 * self.score / 100))
        p.setPen(QColor(c.text))
        f = QFont(self.font())
        f.setPointSizeF(30)
        f.setWeight(QFont.Weight.DemiBold)
        p.setFont(f)
        top = QRectF(rect.x(), rect.y() + side * 0.18, side, side * 0.45)
        p.drawText(top, Qt.AlignmentFlag.AlignCenter, self.grade if self.score is not None else "–")
        f.setPointSizeF(11)
        f.setWeight(QFont.Weight.Normal)
        p.setFont(f)
        p.setPen(QColor(c.text_dim))
        bottom = QRectF(rect.x(), rect.y() + side * 0.58, side, side * 0.2)
        p.drawText(
            bottom,
            Qt.AlignmentFlag.AlignCenter,
            f"risk {self.score}/100" if self.score is not None else "not scanned",
        )
        p.end()
