"""What SimplySec is doing right now: steps done, current step, elapsed time.

Shown at the top of every page while a scan, fix or undo runs, so it's always clear the app
is working and not stuck.
"""

from __future__ import annotations

import html
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QProgressBar, QVBoxLayout, QWidget

from ...core.progress import DONE, is_done

STALL_SECONDS = 150  # a step with no news for this long gets a "still working" note


class ProgressPanel(QFrame):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 10, 16, 10)
        lay.setSpacing(4)
        top = QHBoxLayout()
        self.title = QLabel()
        self.title.setStyleSheet("font-weight:600; font-size:11pt;")
        top.addWidget(self.title, 1)
        self.clock = QLabel()
        self.clock.setObjectName("Dim")
        top.addWidget(self.clock)
        lay.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        lay.addWidget(self.bar)
        self.current = QLabel()
        self.current.setWordWrap(True)
        lay.addWidget(self.current)
        self.done_list = QLabel()
        self.done_list.setObjectName("Dim")
        self.done_list.setWordWrap(True)
        lay.addWidget(self.done_list)
        self.warning = QLabel()
        self.warning.setWordWrap(True)
        self.warning.setStyleSheet("color:#B76E00;")
        lay.addWidget(self.warning)
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)
        self.hide()
        self._started = 0.0
        self._last_update = 0.0
        self._total = 0
        self._done: list[str] = []

    def start(self, title: str, total_steps: int = 0) -> None:
        self._started = self._last_update = time.monotonic()
        self._total = total_steps
        self._done = []
        self.title.setText(title)
        self.current.setText("Starting…")
        self.done_list.setText("")
        self.warning.setText("")
        if total_steps:
            self.bar.setRange(0, total_steps)
            self.bar.setValue(0)
        else:
            self.bar.setRange(0, 0)  # busy indicator when the number of steps isn't known
        self._tick()
        self.timer.start()
        self.show()

    def update_text(self, text: str) -> None:
        if not self.isVisible():
            return
        self._last_update = time.monotonic()
        self.warning.setText("")
        if is_done(text):
            self._done.append(text[len(DONE) :])
            if self._total:
                self.bar.setValue(min(len(self._done), self._total))
            recent = self._done[-4:]
            self.done_list.setText("<br>".join(f"✓ {html.escape(t)}" for t in recent))
        else:
            self.current.setText(html.escape(text))

    def finish(self) -> None:
        self.timer.stop()
        self.hide()

    def _tick(self) -> None:
        now = time.monotonic()
        steps = (
            f"step {min(len(self._done) + 1, self._total)} of {self._total} · "
            if self._total
            else ""
        )
        self.clock.setText(f"{steps}{now - self._started:.0f} s elapsed")
        # Only say something when one step has shown no progress for a long time.
        if now - self._last_update > STALL_SECONDS:
            self.warning.setText("Still working on this step. It will finish on its own.")
