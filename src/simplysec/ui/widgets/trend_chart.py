"""Risk-score-over-time line chart drawn with QPainter (no QtCharts dependency)."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from .. import theme


class TrendChart(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.points: list[tuple[str, int]] = []
        self.setMinimumHeight(180)

    def set_points(self, points: list[tuple[str, int]]) -> None:
        self.points = points
        self.update()

    def sizeHint(self) -> QSize:
        return QSize(600, 200)

    def paintEvent(self, _event: object) -> None:
        c = theme.colors()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        left, top, right, bottom = 40, 12, 12, 26
        area = QRectF(left, top, self.width() - left - right, self.height() - top - bottom)
        p.setPen(QPen(QColor(c.border), 1))
        for score in (0, 25, 50, 75, 100):
            y = area.bottom() - area.height() * score / 100
            p.drawLine(QPointF(area.left(), y), QPointF(area.right(), y))
            p.setPen(QColor(c.text_dim))
            p.drawText(
                QRectF(0, y - 8, left - 6, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(score),
            )
            p.setPen(QPen(QColor(c.border), 1))
        if not self.points:
            p.setPen(QColor(c.text_dim))
            p.drawText(area, Qt.AlignmentFlag.AlignCenter, "No scans yet")
            p.end()
            return
        n = len(self.points)

        def pt(i: int, score: int) -> QPointF:
            x = area.left() + (area.width() * i / (n - 1) if n > 1 else area.width() / 2)
            return QPointF(x, area.bottom() - area.height() * score / 100)

        path = QPainterPath(pt(0, self.points[0][1]))
        for i, (_, s) in enumerate(self.points[1:], start=1):
            path.lineTo(pt(i, s))
        p.setPen(QPen(QColor(c.accent), 2.5))
        p.drawPath(path)
        p.setBrush(QColor(c.accent))
        for i, (_, s) in enumerate(self.points):
            p.drawEllipse(pt(i, s), 3.5, 3.5)
        p.setPen(QColor(c.text_dim))
        for i in sorted({0, n - 1}):
            x = pt(i, 0).x()
            box = (
                QRectF(x - 100, area.bottom() + 4, 100, 18)
                if i == n - 1 and n > 1
                else QRectF(x, area.bottom() + 4, 100, 18)
            )
            align = (
                Qt.AlignmentFlag.AlignRight if i == n - 1 and n > 1 else Qt.AlignmentFlag.AlignLeft
            )
            p.drawText(box, align | Qt.AlignmentFlag.AlignVCenter, self.points[i][0])
        p.end()
