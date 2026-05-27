"""Path input helpers for file and folder selection."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLineEdit, QPushButton, QWidget


def path_input_row(field: QLineEdit, *buttons: QPushButton) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)
    layout.addWidget(field, 1)
    for button in buttons:
        button.setMinimumWidth(72)
        layout.addWidget(button)
    return row


def choose_existing_file(
    parent: QWidget,
    title: str,
    current_text: str = "",
    filter_text: str = "All files (*)",
) -> Path | None:
    selected, _ = QFileDialog.getOpenFileName(
        parent,
        title,
        _dialog_start(current_text),
        filter_text,
    )
    return Path(selected) if selected else None


def choose_existing_folder(parent: QWidget, title: str, current_text: str = "") -> Path | None:
    selected = QFileDialog.getExistingDirectory(parent, title, _dialog_start(current_text))
    return Path(selected) if selected else None


def _dialog_start(current_text: str) -> str:
    raw_value = current_text.strip()
    if not raw_value:
        return str(Path.home())
    path = Path(raw_value).expanduser()
    if path.is_file():
        return str(path.parent)
    if path.exists():
        return str(path)
    if path.suffix:
        return str(path.parent if str(path.parent) else Path.home())
    parent = path.parent
    return str(parent if str(parent) else Path.home())
