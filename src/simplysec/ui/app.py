"""Start the GUI. Nothing is scanned until the user clicks "Scan & Protect"."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from . import theme


def run_gui() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("SimplySec")
    app.setOrganizationName("SimplySec")
    theme.apply(app)  # type: ignore[arg-type]
    from .main_window import MainWindow

    window = MainWindow()
    window.show()
    return int(app.exec())
