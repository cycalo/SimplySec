"""Windows 11-style look: Segoe UI Variable, soft cards, accent blue, light and dark."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication

from ..core.models import Severity


@dataclass(frozen=True)
class Colors:
    window: str
    surface: str
    surface_alt: str
    border: str
    text: str
    text_dim: str
    accent: str
    accent_text: str
    nav_hover: str
    nav_selected: str


LIGHT = Colors(
    "#F3F3F3",
    "#FFFFFF",
    "#F9F9F9",
    "#E5E5E5",
    "#1B1B1B",
    "#5D5D5D",
    "#0067C0",
    "#FFFFFF",
    "#EAEAEA",
    "#E1E1E1",
)
DARK = Colors(
    "#202020",
    "#2B2B2B",
    "#323232",
    "#3A3A3A",
    "#F3F3F3",
    "#C5C5C5",
    "#4CC2FF",
    "#000000",
    "#2D2D2D",
    "#383838",
)

SEVERITY_COLORS = {
    Severity.CRITICAL: "#C42B1C",
    Severity.HIGH: "#D83B01",
    Severity.MEDIUM: "#B76E00",
    Severity.LOW: "#0F6CBD",
    Severity.INFO: "#6B6B6B",
}
GRADE_COLORS = {
    "A": "#0F7B0F",
    "B": "#4C9A2A",
    "C": "#B76E00",
    "D": "#D83B01",
    "E": "#C42B1C",
    "F": "#A4262C",
}

_current = LIGHT


def colors() -> Colors:
    return _current


def is_dark() -> bool:
    try:
        return QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark
    except AttributeError:
        return False


def apply(app: QApplication) -> None:
    global _current
    _current = DARK if is_dark() else LIGHT
    c = _current
    app.setStyle("Fusion")
    font = QFont("Segoe UI Variable Text")
    if not font.exactMatch():
        font = QFont("Segoe UI")
    font.setPointSizeF(10)
    app.setFont(font)

    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(c.window))
    pal.setColor(QPalette.ColorRole.Base, QColor(c.surface))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(c.surface_alt))
    pal.setColor(QPalette.ColorRole.Text, QColor(c.text))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(c.text))
    pal.setColor(QPalette.ColorRole.Button, QColor(c.surface))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(c.text))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(c.accent))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(c.accent_text))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(c.surface))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(c.text))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(c.text_dim))
    app.setPalette(pal)
    app.setStyleSheet(stylesheet(c))


def stylesheet(c: Colors) -> str:
    return f"""
    QWidget {{ color: {c.text}; }}
    QMainWindow, #Page {{ background: {c.window}; }}
    #Nav {{ background: {c.window}; border: none; outline: none; }}
    #Nav::item {{ padding: 9px 14px; margin: 2px 6px; border-radius: 6px; }}
    #Nav::item:hover {{ background: {c.nav_hover}; }}
    #Nav::item:selected {{ background: {c.nav_selected}; color: {c.text}; border-left: 3px solid {c.accent}; }}
    #AppTitle {{ font-size: 15pt; font-weight: 600; padding: 14px 16px 6px 16px; }}
    #PageTitle {{ font-size: 20pt; font-weight: 600; }}
    #SectionTitle {{ font-size: 12.5pt; font-weight: 600; margin-top: 6px; }}
    #Dim {{ color: {c.text_dim}; }}
    #Card {{ background: {c.surface}; border: 1px solid {c.border}; border-radius: 8px; }}
    #Banner {{ background: {c.surface_alt}; border: 1px solid {c.border}; border-left: 4px solid {c.accent};
               border-radius: 6px; padding: 8px 12px; }}
    QPushButton, QToolButton {{ background: {c.surface}; border: 1px solid {c.border}; border-radius: 5px;
               padding: 5px 14px; min-height: 22px; }}
    QPushButton:hover, QToolButton:hover {{ background: {c.surface_alt}; }}
    QPushButton:disabled, QToolButton:disabled {{ color: {c.text_dim}; }}
    QPushButton#Primary, QToolButton#Primary {{ background: {c.accent}; color: {c.accent_text}; border: 1px solid {c.accent};
               font-weight: 600; }}
    QPushButton#Primary:disabled {{ background: {c.border}; color: {c.text_dim}; border-color: {c.border}; }}
    QPushButton#Link, QToolButton#Link {{ border: none; background: transparent; color: {c.accent}; padding: 2px 4px; }}
    QToolButton::menu-indicator {{ subcontrol-position: right center; right: 6px; }}
    QToolButton[popupMode="1"] {{ padding-right: 22px; }}
    QTableView, QTreeWidget, QListWidget#Plain {{ background: {c.surface}; border: 1px solid {c.border}; border-radius: 6px;
               gridline-color: {c.border}; selection-background-color: {c.nav_selected}; selection-color: {c.text}; }}
    QHeaderView::section {{ background: {c.surface_alt}; border: none; border-bottom: 1px solid {c.border};
               padding: 6px; font-weight: 600; }}
    QScrollArea {{ border: none; background: transparent; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QCheckBox {{ spacing: 8px; }}
    QProgressBar {{ border: none; background: {c.border}; height: 4px; border-radius: 2px; }}
    QProgressBar::chunk {{ background: {c.accent}; border-radius: 2px; }}
    QLineEdit, QTimeEdit, QComboBox {{ background: {c.surface}; border: 1px solid {c.border}; border-radius: 5px; padding: 4px 8px; }}
    """


def chip(text: str, color: str) -> str:
    """Rich-text pill used for severity and status labels."""
    return (
        f"<span style='background:{color}; color:white; border-radius:4px; padding:1px 6px; "
        f"font-weight:600;'>&nbsp;{text}&nbsp;</span>"
    )
