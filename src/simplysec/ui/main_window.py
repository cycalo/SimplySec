"""Main window: navigation on the left, pages on the right, status at the bottom."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
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
        self.mode = QLabel()
        self.mode.setObjectName("Dim")
        self.mode.setWordWrap(True)
        self.mode.setContentsMargins(16, 8, 16, 14)
        left.addWidget(self.mode)
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

        self.mode.setText(
            "Administrator mode"
            if elevation.is_admin()
            else "Read-only mode\nFixes ask for permission"
        )
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
