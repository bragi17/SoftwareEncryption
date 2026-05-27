from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

from skeystudio.assets import resource_path


_FONT_FALLBACKS_LOADED = False


def apply_theme(app: QApplication) -> None:
    _load_font_fallbacks(app)
    background = str(resource_path("assets/workspace-background.png")).replace("\\", "/")
    stylesheet = """
        QWidget {
            background: #f7f9fc;
            color: #1f2937;
            font-family: "Microsoft YaHei UI", "Microsoft YaHei", "Noto Sans SC", "SimHei", "Segoe UI", Arial, sans-serif;
            font-size: 13px;
        }
        QMainWindow {
            background: #f7f9fc;
        }
        QFrame#navigation_rail {
            background: #ffffff;
            border-right: 1px solid #d8dee8;
        }
        QFrame#content_shell {
            background-image: url("__WORKSPACE_BACKGROUND__");
            background-repeat: no-repeat;
            background-position: right bottom;
            border: 0;
        }
        QLabel#brand_mark {
            background: transparent;
            padding: 2px 0 0 0;
        }
        QLabel#brand_label {
            color: #111827;
            font-size: 18px;
            font-weight: 700;
            padding: 2px 2px 12px 2px;
        }
        QLabel[role="pageTitle"] {
            color: #111827;
            font-size: 20px;
            font-weight: 700;
        }
        QLabel[role="muted"] {
            color: #64748b;
        }
        QLabel[role="status"] {
            background: rgba(255, 255, 255, 232);
            border: 1px solid #d8dee8;
            border-radius: 6px;
            padding: 5px 8px;
        }
        QPushButton {
            background: #ffffff;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            color: #1f2937;
            padding: 7px 11px;
        }
        QPushButton:hover {
            border-color: #2563eb;
        }
        QPushButton:pressed {
            background: #eaf1ff;
        }
        QPushButton[primary="true"] {
            background: #1d4ed8;
            border-color: #1d4ed8;
            color: #ffffff;
            font-weight: 600;
        }
        QPushButton[nav="true"] {
            border-color: transparent;
            text-align: left;
            padding: 9px 10px;
        }
        QPushButton[nav="true"]:checked {
            background: #eaf1ff;
            border-color: #bfdbfe;
            color: #1d4ed8;
            font-weight: 600;
        }
        QGroupBox {
            background: #ffffff;
            border: 1px solid #d8dee8;
            border-radius: 8px;
            margin-top: 16px;
            padding: 13px 10px 10px 10px;
            font-weight: 600;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 4px;
        }
        QLineEdit,
        QPlainTextEdit,
        QTextEdit,
        QTextBrowser,
        QListWidget,
        QComboBox,
        QSpinBox {
            background: rgba(255, 255, 255, 244);
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            padding: 5px;
            selection-background-color: #bfdbfe;
        }
        QComboBox {
            min-width: 112px;
            padding: 5px 26px 5px 8px;
        }
        QComboBox::drop-down {
            border: 0;
            width: 22px;
        }
        QListWidget::item {
            padding: 6px;
        }
        QListWidget::item:selected {
            background: #eaf1ff;
            color: #1d4ed8;
        }
        """
    app.setStyleSheet(stylesheet.replace("__WORKSPACE_BACKGROUND__", background))


def _load_font_fallbacks(app: QApplication) -> None:
    global _FONT_FALLBACKS_LOADED
    if _FONT_FALLBACKS_LOADED:
        return
    _FONT_FALLBACKS_LOADED = True
    if not sys.platform.startswith("win"):
        return

    fonts_root = Path("C:/Windows/Fonts")
    preferred_family: str | None = None
    for filename in ("msyh.ttc", "NotoSansSC-VF.ttf", "simhei.ttf", "simsun.ttc"):
        font_path = fonts_root / filename
        if not font_path.exists():
            continue
        font_id = QFontDatabase.addApplicationFont(str(font_path))
        if font_id < 0:
            continue
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families and preferred_family is None:
            preferred_family = families[0]

    if preferred_family is not None:
        app.setFont(QFont(preferred_family, 10))
