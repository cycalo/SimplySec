"""Main window: navigation on the left, pages on the right, status at the bottom."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..app import elevation, paths
from .controller import Controller
from .pages.changes import ChangesPage
from .pages.overview import OverviewPage
from .pages.ports import PortsPage
from .pages.settings import SettingsPage
from .pages.this_pc import ThisPcPage
from .widgets.progress_panel import ProgressPanel


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(
            f"SimplySec {__version__}" + ("" if elevation.is_admin() else " (read-only)")
        )
        icon = paths.resource("simplysec.ico")
        if icon.exists():
            self.setWindowIcon(QIcon(str(icon)))
        self.resize(1180, 800)
        self.ctl = Controller(self)

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        left = QVBoxLayout()
        left.setContentsMargins(0, 0, 0, 0)
        title = QLabel("SimplySec")
        title.setObjectName("AppTitle")
        left.addWidget(title)
        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav.setFixedWidth(220)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        left.addWidget(self.nav, 1)
        left.addWidget(self._mode_badge())
        root.addLayout(left)

        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        self.progress = ProgressPanel()
        holder = QVBoxLayout()
        holder.setContentsMargins(28, 12, 28, 0)
        holder.addWidget(self.progress)
        right.addLayout(holder)
        self.stack = QStackedWidget()
        right.addWidget(self.stack, 1)
        self.status = QLabel("")
        self.status.setObjectName("Dim")
        self.status.setContentsMargins(28, 6, 28, 8)
        right.addWidget(self.status)
        root.addLayout(right, 1)
        self.setCentralWidget(central)

        self.pages: dict[str, QWidget] = {}
        self.add_page("Overview", OverviewPage(self.ctl))
        self.add_page("This PC", ThisPcPage(self.ctl))
        self.add_page("Open ports", PortsPage(self.ctl))
        self.extend_pages()
        self.add_page("Changes", ChangesPage(self.ctl))
        self.add_page("Settings", SettingsPage(self.ctl))
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        self.ctl.busy_changed.connect(self._busy)
        self.ctl.progress.connect(self._progress)
        self.ctl.error.connect(self._error)
        self.ctl.scan_finished.connect(
            lambda r: self.status.setText(f"Scan finished in {r.duration:.0f} s.")
        )

    def extend_pages(self) -> None:
        from .pages.network import NetworkPage

        self.add_page("My network", NetworkPage(self.ctl))
        from .pages.history import HistoryPage

        self.add_page("History", HistoryPage(self.ctl))

    def _mode_badge(self) -> QWidget:
        """Bottom-left status: a coloured mode pill, and 'Restart as administrator' if needed."""
        admin = elevation.is_admin()
        box = QWidget()
        lay = QVBoxLayout(box)
        lay.setContentsMargins(14, 8, 14, 14)
        lay.setSpacing(6)
        color = "#0F7B0F" if admin else "#B76E00"
        text = "Administrator mode" if admin else "Read-only mode"
        pill = QLabel(text)
        pill.setStyleSheet(
            f"background:{color}; color:white; font-weight:600; border-radius:10px; padding:4px 10px;"
        )
        pill.setToolTip(
            "Fixes and undo apply directly."
            if admin
            else "Scans work fully. Applying or undoing a fix asks Windows for permission each time."
        )
        lay.addWidget(pill)
        if not admin:
            hint = QLabel("Fixes ask for permission")
            hint.setObjectName("Dim")
            lay.addWidget(hint)
            btn = QPushButton("Restart as administrator")
            btn.clicked.connect(self.restart_as_admin)
            lay.addWidget(btn)
        return box

    def restart_as_admin(self) -> None:
        if self.ctl.busy:
            QMessageBox.information(self, "Busy", "Wait for the current task to finish first.")
            return
        if elevation.relaunch_elevated([], gui=True):
            QApplication.quit()
        else:
            QMessageBox.information(
                self, "Not restarted", "Administrator permission was not given."
            )

    def add_page(self, name: str, page: QWidget) -> None:
        self.pages[name] = page
        self.stack.addWidget(page)
        self.nav.addItem(QListWidgetItem(name))

    def _busy(self, busy: bool, text: str) -> None:
        if busy:
            self.progress.start(text or "Working…", self.ctl.task_steps, self.ctl.task_typical)
            self.status.setText(text)
        else:
            self.progress.finish()

    def _progress(self, text: str) -> None:
        self.progress.update_text(text)
        if not text.startswith("✓"):
            self.status.setText(text)

    def _error(self, text: str) -> None:
        self.status.setText(text)
        QMessageBox.warning(self, "SimplySec", text)

    def go(self, name: str) -> None:
        names = list(self.pages)
        if name in names:
            self.nav.setCurrentRow(names.index(name))
