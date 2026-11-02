"""Start the GUI."""

from __future__ import annotations

import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from . import theme


def run_gui(scan_on_start: bool = True) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("SimplySec")
    app.setOrganizationName("SimplySec")
    theme.apply(app)  # type: ignore[arg-type]
    from .main_window import MainWindow

    window = MainWindow()
    window.show()
    if scan_on_start:
        QTimer.singleShot(300, window.ctl.start_scan)
    return int(app.exec())
