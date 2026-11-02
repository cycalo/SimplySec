"""Draw the SimplySec shield icon and write src/simplysec/resources/simplysec.ico (PNG-in-ICO)."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QImage, QPainter, QPainterPath, QPen

OUT = Path(__file__).resolve().parents[1] / "src" / "simplysec" / "resources" / "simplysec.ico"
SIZES = (16, 24, 32, 48, 64, 128, 256)


def draw(size: int) -> bytes:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = size / 64.0
    shield = QPainterPath(QPointF(32 * s, 3 * s))
    shield.cubicTo(QPointF(42 * s, 9 * s), QPointF(52 * s, 10 * s), QPointF(58 * s, 10 * s))
    shield.cubicTo(QPointF(58 * s, 36 * s), QPointF(50 * s, 52 * s), QPointF(32 * s, 61 * s))
    shield.cubicTo(QPointF(14 * s, 52 * s), QPointF(6 * s, 36 * s), QPointF(6 * s, 10 * s))
    shield.cubicTo(QPointF(12 * s, 10 * s), QPointF(22 * s, 9 * s), QPointF(32 * s, 3 * s))
    p.fillPath(shield, QColor("#0067C0"))
    pen = QPen(QColor("white"), max(1.5, 6 * s))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    tick = QPainterPath(QPointF(20 * s, 32 * s))
    tick.lineTo(QPointF(29 * s, 41 * s))
    tick.lineTo(QPointF(45 * s, 23 * s))
    p.drawPath(tick)
    p.end()
    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    return bytes(data.data())


def main() -> int:
    QGuiApplication(sys.argv[:1])
    images = [(sz, draw(sz)) for sz in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for sz, png in images:
        dim = 0 if sz >= 256 else sz
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        blobs += png
        offset += len(png)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(header + entries + blobs)
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
