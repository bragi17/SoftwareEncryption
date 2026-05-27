"""License server operation view."""

from __future__ import annotations

import subprocess
from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from skeystudio.i18n import DEFAULT_LANGUAGE, LanguageCode, tr
from skeystudio.services.server import ServerLaunchConfig, ServerService
from skeystudio.state import OperationResult, ProjectState, UserMode
from skeystudio.workers import run_background_task


class ServerConsoleView(QWidget):
    def __init__(self, state: ProjectState, language: LanguageCode = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self.state = state
        self.language = language
        self._process: subprocess.Popen[str] | None = None
        self._mode = state.mode

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.title = QLabel()
        self.title.setProperty("role", "pageTitle")
        self.database_url = QLineEdit("sqlite:///skey-studio.db")

        self.advanced_secret_group = QGroupBox()
        self.advanced_secret_group.setObjectName("advanced_secret_group")
        secret_form = QFormLayout(self.advanced_secret_group)
        self.server_secret_label = QLabel()
        self.admin_token_label = QLabel()
        self.signing_key_label = QLabel()
        self.package_kek_label = QLabel()
        self.server_secret = _password_input()
        self.admin_token = _password_input()
        self.signing_key = _password_input()
        self.package_kek = _password_input()
        self.show_secrets_checkbox = QCheckBox()
        self.show_secrets_checkbox.toggled.connect(self._apply_secret_echo_mode)
        secret_form.addRow(self.server_secret_label, self.server_secret)
        secret_form.addRow(self.admin_token_label, self.admin_token)
        secret_form.addRow(self.signing_key_label, self.signing_key)
        secret_form.addRow(self.package_kek_label, self.package_kek)
        secret_form.addRow("", self.show_secrets_checkbox)

        form = QFormLayout()
        self.database_label = QLabel()
        form.addRow(self.database_label, self.database_url)

        self.start_button = QPushButton()
        self.start_button.setProperty("primary", True)
        self.start_button.clicked.connect(self.start_server)
        self.stop_button = QPushButton()
        self.stop_button.clicked.connect(self.stop_server)
        action_row = QHBoxLayout()
        action_row.addWidget(self.start_button)
        action_row.addWidget(self.stop_button)
        action_row.addStretch(1)

        self.admin_log = QTextEdit()
        self.admin_log.setObjectName("server_log")
        self.admin_log.setReadOnly(True)

        layout.addWidget(self.title)
        layout.addLayout(form)
        layout.addWidget(self.advanced_secret_group)
        layout.addLayout(action_row)
        layout.addWidget(self.admin_log, 1)
        self.retranslate(language)
        self.apply_mode(state.mode)

    def retranslate(self, language: LanguageCode) -> None:
        self.language = language
        self.title.setText(tr(language, "server.title"))
        self.database_label.setText(tr(language, "server.database"))
        self.advanced_secret_group.setTitle(tr(language, "server.secret_group"))
        self.server_secret_label.setText(tr(language, "server.secret"))
        self.admin_token_label.setText(tr(language, "server.admin_token"))
        self.signing_key_label.setText(tr(language, "server.signing_key"))
        self.package_kek_label.setText(tr(language, "server.package_kek"))
        self.server_secret.setPlaceholderText(tr(language, "server.secret"))
        self.admin_token.setPlaceholderText(tr(language, "server.admin_token"))
        self.signing_key.setPlaceholderText(tr(language, "server.signing_key"))
        self.package_kek.setPlaceholderText(tr(language, "server.package_kek"))
        self.show_secrets_checkbox.setText(tr(language, "server.show_secrets"))
        self.start_button.setText(tr(language, "server.start"))
        self.stop_button.setText(tr(language, "server.stop"))

    def apply_mode(self, mode: UserMode) -> None:
        self._mode = mode
        is_admin = mode is UserMode.ADVANCED_ADMIN
        self.advanced_secret_group.setHidden(not is_admin)
        self.show_secrets_checkbox.setEnabled(is_admin)
        for secret_input in self._secret_inputs():
            secret_input.setEnabled(is_admin)
        if not is_admin:
            self.show_secrets_checkbox.setChecked(False)
        self._apply_secret_echo_mode()

    def start_server(self) -> None:
        missing = [
            label
            for label, value in (
                (tr(self.language, "server.secret"), self.server_secret.text().strip()),
                (tr(self.language, "server.admin_token"), self.admin_token.text().strip()),
                (tr(self.language, "server.signing_key"), self.signing_key.text().strip()),
                (tr(self.language, "server.package_kek"), self.package_kek.text().strip()),
            )
            if not value
        ]
        if missing:
            self.admin_log.setPlainText(
                tr(self.language, "server.missing", fields=", ".join(missing)),
            )
            return

        config = ServerLaunchConfig(
            database_url=self.database_url.text().strip(),
            server_secret=self.server_secret.text().strip(),
            admin_token=self.admin_token.text().strip(),
            signing_private_key_b64=self.signing_key.text().strip(),
            package_kek_b64=self.package_kek.text().strip(),
        )
        run_background_task(
            self,
            lambda: ServerService.start(config, Path.cwd()),
            self._show_start_result,
            self._show_worker_failure,
            (self.start_button, self.stop_button),
        )

    def stop_server(self) -> None:
        process = self._process
        run_background_task(
            self,
            lambda: ServerService.stop(process),
            self._show_stop_result,
            self._show_worker_failure,
            (self.stop_button, self.start_button),
        )

    def shutdown(self) -> None:
        if self._process is None:
            return
        ServerService.stop(self._process)
        self._process = None
        self.state.server.running = False
        self.state.server.starting = False

    def _show_start_result(
        self,
        service_result: tuple[OperationResult, subprocess.Popen[str] | None],
    ) -> None:
        result, process = service_result
        self._process = process
        self.state.server.running = result.success
        self.state.server.starting = False
        self.state.server.error = None if result.success else result.message
        base_url = result.detail.get("base_url")
        self.state.server.base_url = str(base_url) if isinstance(base_url, str) else None
        self.state.last_result = result
        self.admin_log.setPlainText(result.message)

    def _show_stop_result(self, result: OperationResult) -> None:
        self._process = None
        self.state.server.running = False
        self.state.server.starting = False
        self.state.server.error = None
        self.state.last_result = result
        self.admin_log.setPlainText(result.message)

    def _show_worker_failure(self, message: str) -> None:
        self.admin_log.setPlainText(message)

    def _apply_secret_echo_mode(self) -> None:
        echo_mode = (
            QLineEdit.EchoMode.Normal
            if self._mode is UserMode.ADVANCED_ADMIN and self.show_secrets_checkbox.isChecked()
            else QLineEdit.EchoMode.Password
        )
        for secret_input in self._secret_inputs():
            secret_input.setEchoMode(echo_mode)

    def _secret_inputs(self) -> tuple[QLineEdit, QLineEdit, QLineEdit, QLineEdit]:
        return (self.server_secret, self.admin_token, self.signing_key, self.package_kek)


def _password_input() -> QLineEdit:
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    return field
