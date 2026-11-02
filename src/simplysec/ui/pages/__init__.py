"""Pages shown in the main window."""

from __future__ import annotations

from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from ..widgets import label


class Page(QScrollArea):
    """A scrollable page with a title; subclasses fill ``self.body``."""

    def __init__(self, title: str, subtitle: str = "") -> None:
        super().__init__()
        self.setObjectName("Page")
        self.setWidgetResizable(True)
        inner = QWidget()
        inner.setObjectName("Page")
        self.layout_ = QVBoxLayout(inner)
        self.layout_.setContentsMargins(28, 20, 28, 24)
        self.layout_.setSpacing(12)
        self.layout_.addWidget(label(title, object_name="PageTitle"))
        if subtitle:
            self.layout_.addWidget(label(subtitle, object_name="Dim"))
        self.body = QVBoxLayout()
        self.body.setSpacing(12)
        self.layout_.addLayout(self.body)
        self.layout_.addStretch(1)
        self.setWidget(inner)

    def clear(self, layout: QVBoxLayout | None = None) -> None:
        layout = layout or self.body
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
            elif item.layout() is not None:
                self.clear(item.layout())  # type: ignore[arg-type]
