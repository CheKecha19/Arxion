"""Цветовые роли и оформление Qt рабочего места аналитика."""

from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

COLORS = {
    "background": "#10131C",
    "panel": "#191F2D",
    "raised": "#242C3E",
    "text": "#E8EDF7",
    "muted": "#A8B3C7",
    "blue": "#79B8FF",
    "purple": "#B7A0FF",
}


def apply_theme(app: QApplication) -> None:
    """Установить единую тёмную тему, включая системные Qt диалоги."""
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    palette = QPalette()
    for role, color in (
        (QPalette.ColorRole.Window, COLORS["background"]),
        (QPalette.ColorRole.Base, COLORS["panel"]),
        (QPalette.ColorRole.AlternateBase, COLORS["raised"]),
        (QPalette.ColorRole.WindowText, COLORS["text"]),
        (QPalette.ColorRole.Text, COLORS["text"]),
        (QPalette.ColorRole.Button, COLORS["raised"]),
        (QPalette.ColorRole.ButtonText, COLORS["text"]),
        (QPalette.ColorRole.Highlight, COLORS["blue"]),
        (QPalette.ColorRole.HighlightedText, COLORS["background"]),
        (QPalette.ColorRole.ToolTipBase, COLORS["raised"]),
        (QPalette.ColorRole.ToolTipText, COLORS["text"]),
    ):
        palette.setColor(role, QColor(color))
    app.setPalette(palette)
    app.setStyleSheet("""
        QMainWindow, QWidget { background: #10131C; color: #E8EDF7; }
        QLabel#heading { font-size: 20px; font-weight: 600; }
        QLabel#muted { color: #A8B3C7; }
        QFrame#hero { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
            stop:0 #203455, stop:1 #30284A); border-radius: 12px; }
        QFrame#hero QLabel { background: transparent; }
        QPushButton, QLineEdit, QComboBox, QAbstractSpinBox, QPlainTextEdit {
            background: #242C3E; border: 1px solid #39445B; border-radius: 4px;
            padding: 2px 4px; min-height: 16px;
        }
        QPushButton:hover { background: #303C55; border-color: #79B8FF; }
        QPushButton:focus, QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus,
        QTableView:focus { border: 2px solid #79B8FF; }
        QPushButton#primary { background: #79B8FF; color: #10131C; font-weight: 600; }
        QPushButton:disabled { color: #A8B3C7; background: #191F2D; }
        QListWidget#navigation { background: #191F2D; border: none; border-radius: 12px; }
        QListWidget#navigation::item { padding: 4px 6px; margin: 1px 3px; border-radius: 4px; }
        QListWidget#navigation::item:selected { background: #30284A; color: #B7A0FF; }
        QTreeWidget#navigation { background: #191F2D; border: none; border-radius: 12px; }
        QTreeWidget#navigation::item { padding: 3px 4px; border-radius: 4px; }
        QTreeWidget#navigation::item:selected { background: #30284A; color: #B7A0FF; }
        QTreeWidget#navigation::item:disabled { color: #6F7A90; }
        QTreeWidget#navigation:focus { border: 2px solid #79B8FF; }
        QPushButton:checked { background: #30284A; color: #B7A0FF; }
        QFrame#settingsMenu, QFrame#integrationGroup {
            background: #191F2D; border: 1px solid #30394D; border-radius: 12px;
        }
        QFrame#integrationGroup QLabel { background: transparent; font-weight: 600; }
        QFrame#settingsMenu QPushButton { text-align: left; }
        QPushButton#integrationCard {
            background: #242C3E; border: 1px solid #465674;
            font-weight: 600;
        }
        QPushButton#integrationCard:hover { background: #303C55; border-color: #79B8FF; }
        QPushButton#integrationCard:disabled {
            background: #191F2D; color: #A8B3C7; border-color: #30394D;
        }
        QTableView { background: #191F2D; alternate-background-color: #202738;
            gridline-color: #30394D; border: 1px solid #30394D; border-radius: 8px; }
        QHeaderView::section { background: #242C3E; padding: 3px; border: none;
            border-right: 1px solid #39445B; font-weight: 600; }
        QTableView::item { padding: 3px; }
        QTableView::item:selected { background: #324463; color: #E8EDF7; }
        QTextBrowser { background: #191F2D; border: 1px solid #30394D;
            border-radius: 6px; padding: 6px; }
        QTabWidget::pane { border: 1px solid #30394D; border-radius: 8px; }
        QTabBar::tab { background: #191F2D; padding: 4px 8px; }
        QTabBar::tab:selected { background: #30284A; color: #B7A0FF; }
        QProgressBar { background: #242C3E; border-radius: 6px; text-align: center; }
        QProgressBar::chunk { background: #79B8FF; border-radius: 6px; }
        QSplitter::handle { background: #30394D; width: 6px; }
        QToolTip { background: #242C3E; color: #E8EDF7; border: 1px solid #79B8FF; }
    """)
