"""Dashboard view."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from skeystudio.i18n import DEFAULT_LANGUAGE, LanguageCode, server_status_label, tr
from skeystudio.state import ProjectState


class DashboardView(QWidget):
    def __init__(self, state: ProjectState, language: LanguageCode = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self.state = state
        self.language = language

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        self.title = QLabel()
        self.title.setProperty("role", "pageTitle")
        self.summary = QLabel()
        self.summary.setProperty("role", "muted")

        self.primary_button = QPushButton()
        self.primary_button.setObjectName("build_release_action")
        self.primary_button.setProperty("primary", True)

        action_row = QHBoxLayout()
        action_row.addWidget(self.primary_button)
        action_row.addStretch(1)

        self.status_group = QGroupBox()
        status_layout = QGridLayout(self.status_group)
        self.project_row_label = QLabel()
        self.config_row_label = QLabel()
        self.release_row_label = QLabel()
        self.server_row_label = QLabel()
        self.project_status = _status_label()
        self.config_status = _status_label()
        self.release_status = _status_label()
        self.server_status = _status_label()
        for row, (label, value) in enumerate(
            (
                (self.project_row_label, self.project_status),
                (self.config_row_label, self.config_status),
                (self.release_row_label, self.release_status),
                (self.server_row_label, self.server_status),
            ),
        ):
            status_layout.addWidget(label, row, 0)
            status_layout.addWidget(value, row, 1)

        layout.addWidget(self.title)
        layout.addWidget(self.summary)
        layout.addLayout(action_row)
        layout.addWidget(self.status_group)
        layout.addStretch(1)
        self.retranslate(language)
        self.refresh()

    def retranslate(self, language: LanguageCode) -> None:
        self.language = language
        self.title.setText(tr(language, "dashboard.title"))
        self.summary.setText(tr(language, "dashboard.summary"))
        self.primary_button.setText(tr(language, "dashboard.primary"))
        self.status_group.setTitle(tr(language, "dashboard.status_group"))
        self.project_row_label.setText(tr(language, "dashboard.status.project"))
        self.config_row_label.setText(tr(language, "dashboard.status.config"))
        self.release_row_label.setText(tr(language, "dashboard.status.release"))
        self.server_row_label.setText(tr(language, "dashboard.status.server"))
        self.refresh()

    def refresh(self) -> None:
        project = str(self.state.project_root) if self.state.project_root else tr(self.language, "not_selected")
        config = str(self.state.config_path) if self.state.config_path else tr(self.language, "not_generated")
        release = str(self.state.release_root) if self.state.release_root else tr(self.language, "not_built")
        self.project_status.setText(project)
        self.config_status.setText(config)
        self.release_status.setText(release)
        self.server_status.setText(server_status_label(self.state.server, self.language))


def _status_label() -> QLabel:
    label = QLabel()
    label.setProperty("role", "status")
    return label
