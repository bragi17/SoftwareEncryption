"""Online and offline activation view."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from skeystudio.i18n import DEFAULT_LANGUAGE, LanguageCode, tr
from skeystudio.services.protector import ProtectionService
from skeystudio.state import OperationResult, ProjectState
from skeystudio.widgets.path_picker import choose_existing_folder, path_input_row
from skeystudio.workers import run_background_task


class ActivationCenterView(QWidget):
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
        self.browse_release_folder_button.setObjectName("activation_browse_release_folder")
        self.browse_release_folder_button.clicked.connect(self.browse_release_folder)
        self.license_code = QLineEdit()
        self.server_url = QLineEdit("http://127.0.0.1:8000/v1")
        self.device_hash = QLineEdit()

        form = QFormLayout()
        self.release_label = QLabel()
        self.license_label = QLabel()
        self.server_label = QLabel()
        self.device_label = QLabel()
        form.addRow(
            self.release_label,
            path_input_row(self.release_path, self.browse_release_folder_button),
        )
        form.addRow(self.license_label, self.license_code)
        form.addRow(self.server_label, self.server_url)
        form.addRow(self.device_label, self.device_hash)

        self.online_button = QPushButton()
        self.online_button.setProperty("primary", True)
        self.online_button.clicked.connect(self.activate_online)
        self.offline_request_button = QPushButton()
        self.offline_request_button.clicked.connect(self.create_offline_request)
        self.offline_import_button = QPushButton()
        self.offline_import_button.clicked.connect(self.import_offline_response)

        action_row = QHBoxLayout()
        action_row.addWidget(self.online_button)
        action_row.addWidget(self.offline_request_button)
        action_row.addWidget(self.offline_import_button)
        action_row.addStretch(1)

        self.output = QTextEdit()
        self.output.setObjectName("activation_output")
        self.output.setReadOnly(True)

        layout.addWidget(self.title)
        layout.addLayout(form)
        layout.addLayout(action_row)
        layout.addWidget(self.output, 1)
        self.retranslate(language)

    def retranslate(self, language: LanguageCode) -> None:
        self.language = language
        self.title.setText(tr(language, "activation.title"))
        self.release_label.setText(tr(language, "activation.release"))
        self.license_label.setText(tr(language, "activation.license"))
        self.server_label.setText(tr(language, "activation.server"))
        self.device_label.setText(tr(language, "activation.device"))
        self.release_path.setPlaceholderText(tr(language, "activation.release_placeholder"))
        self.browse_release_folder_button.setText(tr(language, "path.choose_folder"))
        self.license_code.setPlaceholderText(tr(language, "activation.license_placeholder"))
        self.device_hash.setPlaceholderText(tr(language, "activation.device_placeholder"))
        self.online_button.setText(tr(language, "activation.online"))
        self.offline_request_button.setText(tr(language, "activation.offline_request"))
        self.offline_import_button.setText(tr(language, "activation.offline_import"))

    def browse_release_folder(self) -> None:
        selected = choose_existing_folder(
            self,
            tr(self.language, "path.dialog.release_folder"),
            self.release_path.text(),
        )
        if selected is not None:
            self.state.release_root = selected
            self.release_path.setText(str(selected))

    def activate_online(self) -> None:
        product_root = self._release_root()
        if product_root is None:
            self.output.setPlainText(tr(self.language, "activation.select_first"))
            return
        if not self.license_code.text().strip():
            self.output.setPlainText(tr(self.language, "activation.enter_license"))
            return
        license_code = self.license_code.text().strip()
        server_url = self.server_url.text().strip()
        if not server_url:
            self.output.setPlainText(tr(self.language, "activation.enter_server"))
            return
        device_hash = self._device_hash()
        run_background_task(
            self,
            lambda: ProtectionService.activate_online(
                product_root=product_root,
                license_code=license_code,
                server_url=server_url,
                device_hash=device_hash,
            ),
            self._handle_result,
            self._handle_worker_error,
            disabled_widgets=(self.online_button,),
        )

    def create_offline_request(self) -> None:
        product_root = self._release_root()
        if product_root is None:
            self.output.setPlainText(tr(self.language, "activation.select_first"))
            return
        out = product_root / "offline-request.json"
        device_hash = self._device_hash()
        run_background_task(
            self,
            lambda: ProtectionService.create_offline_request(
                product_root=product_root,
                out=out,
                device_hash=device_hash,
            ),
            self._handle_result,
            self._handle_worker_error,
            disabled_widgets=(self.offline_request_button,),
        )

    def import_offline_response(self) -> None:
        product_root = self._release_root()
        if product_root is None:
            self.output.setPlainText(tr(self.language, "activation.select_first"))
            return
        response = product_root / "offline-response.json"
        run_background_task(
            self,
            lambda: ProtectionService.import_offline_response(
                product_root=product_root,
                response=response,
            ),
            self._handle_result,
            self._handle_worker_error,
            disabled_widgets=(self.offline_import_button,),
        )

    def _handle_result(self, result: OperationResult) -> None:
        self.state.last_result = result
        self.output.setPlainText(result.message)

    def _handle_worker_error(self, message: str) -> None:
        self.output.setPlainText(message)

    def _release_root(self) -> Path | None:
        raw_release_path = self.release_path.text().strip()
        if raw_release_path:
            self.state.release_root = Path(raw_release_path)
        return self.state.release_root

    def _device_hash(self) -> str | None:
        value = self.device_hash.text().strip()
        return value or None
