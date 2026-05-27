"""Diagnostics view."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from skeystudio.i18n import DEFAULT_LANGUAGE, LanguageCode, tr
from skeystudio.services.diagnostics import DiagnosticsService
from skeystudio.state import OperationResult, ProjectState
from skeystudio.widgets.path_picker import choose_existing_folder
from skeystudio.workers import run_background_task


class DiagnosticsView(QWidget):
    def __init__(self, state: ProjectState, language: LanguageCode = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self.state = state
        self.language = language

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.title = QLabel()
        self.title.setProperty("role", "pageTitle")
        self.release_path = QLineEdit()
        self.browse_release_folder_button = QPushButton()
        self.browse_release_folder_button.setObjectName("diagnostics_browse_release_folder")
        self.browse_release_folder_button.clicked.connect(self.browse_release_folder)
        self.run_button = QPushButton()
        self.run_button.setProperty("primary", True)
        self.run_button.clicked.connect(self.run_diagnostics)
        self.export_button = QPushButton()
        self.export_button.clicked.connect(self.export_report)
        self.output = QTextEdit()
        self.output.setObjectName("diagnostics_output")
        self.output.setReadOnly(True)

        action_row = QHBoxLayout()
        self.release_label = QLabel()
        action_row.addWidget(self.release_label)
        action_row.addWidget(self.release_path, 1)
        action_row.addWidget(self.browse_release_folder_button)
        action_row.addWidget(self.run_button)
        action_row.addWidget(self.export_button)

        layout.addWidget(self.title)
        layout.addLayout(action_row)
        layout.addWidget(self.output, 1)
        self.retranslate(language)

    def retranslate(self, language: LanguageCode) -> None:
        self.language = language
        self.title.setText(tr(language, "diagnostics.title"))
        self.release_label.setText(tr(language, "diagnostics.release"))
        self.release_path.setPlaceholderText(tr(language, "diagnostics.release_placeholder"))
        self.browse_release_folder_button.setText(tr(language, "path.choose_folder"))
        self.run_button.setText(tr(language, "diagnostics.run"))
        self.export_button.setText(tr(language, "diagnostics.export"))

    def browse_release_folder(self) -> None:
        selected = choose_existing_folder(
            self,
            tr(self.language, "path.dialog.release_folder"),
            self.release_path.text(),
        )
        if selected is not None:
            self.state.release_root = selected
            self.release_path.setText(str(selected))

    def run_diagnostics(self) -> None:
        release_root = self._release_root()
        if release_root is None:
            self.output.setPlainText(tr(self.language, "diagnostics.select_first"))
            return
        run_background_task(
            self,
            lambda: DiagnosticsService.run(release_root),
            self._show_result,
            self._show_worker_failure,
            (self.run_button, self.export_button),
        )

    def export_report(self) -> None:
        release_root = self._release_root()
        if release_root is None:
            self.output.setPlainText(tr(self.language, "diagnostics.select_first"))
            return
        run_background_task(
            self,
            lambda: DiagnosticsService.export_report(release_root, release_root / "diagnostics-report"),
            self._show_result,
            self._show_worker_failure,
            (self.export_button, self.run_button),
        )

    def _show_result(self, result: OperationResult) -> None:
        self.state.last_result = result
        self.output.setPlainText(result.message)

    def _show_worker_failure(self, message: str) -> None:
        self.output.setPlainText(message)

    def _release_root(self) -> Path | None:
        raw_release_path = self.release_path.text().strip()
        if raw_release_path:
            self.state.release_root = Path(raw_release_path)
        return self.state.release_root
