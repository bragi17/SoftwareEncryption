"""Project selection and configuration view."""

from __future__ import annotations

from pathlib import Path
import re

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from skeystudio.config_wizard import ConfigWizardDraft
from skeystudio.i18n import DEFAULT_LANGUAGE, LanguageCode, tr
from skeystudio.services.protector import ProtectionService
from skeystudio.state import OperationResult, ProjectState
from skeystudio.widgets.path_picker import choose_existing_file, choose_existing_folder
from skeystudio.workers import run_background_task


MAX_VISIBLE_SCAN_ITEMS = 40


class ProjectWorkbenchView(QWidget):
    def __init__(self, state: ProjectState, language: LanguageCode = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self.state = state
        self.language = language

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.title = QLabel()
        self.title.setProperty("role", "pageTitle")
        self.project_path = QLineEdit()
        self.project_path.setObjectName("project_path")
        self.browse_project_file_button = QPushButton()
        self.browse_project_file_button.setObjectName("project_browse_file")
        self.browse_project_file_button.clicked.connect(self.browse_project_file)
        self.browse_project_folder_button = QPushButton()
        self.browse_project_folder_button.setObjectName("project_browse_folder")
        self.browse_project_folder_button.clicked.connect(self.browse_project_folder)
        self.scan_button = QPushButton()
        self.scan_button.clicked.connect(self.scan_current_path)
        self.generate_config_button = QPushButton()
        self.generate_config_button.clicked.connect(self.generate_config_for_current_project)

        path_row = QHBoxLayout()
        self.root_label = QLabel()
        path_row.addWidget(self.root_label)
        path_row.addWidget(self.project_path, 1)
        path_row.addWidget(self.browse_project_file_button)
        path_row.addWidget(self.browse_project_folder_button)
        path_row.addWidget(self.scan_button)
        path_row.addWidget(self.generate_config_button)

        self.scan_output = QTextEdit()
        self.scan_output.setObjectName("project_scan_output")
        self.scan_output.setReadOnly(True)

        self.config_group = QGroupBox()
        self.config_group.setObjectName("config_helper")
        config_form = QFormLayout(self.config_group)
        config_form.setContentsMargins(12, 12, 12, 12)
        config_form.setSpacing(8)

        self.product_id = QLineEdit()
        self.product_id.setObjectName("product_id")
        self.product_name = QLineEdit()
        self.product_name.setObjectName("product_name")
        self.product_version = QLineEdit("1.0.0")
        self.product_version.setObjectName("product_version")
        self.activation_url = QLineEdit("http://127.0.0.1:8000/v1")
        self.activation_url.setObjectName("activation_url")
        self.entry_file = QComboBox()
        self.entry_file.setObjectName("entry_file")
        self.entry_file.setEditable(True)
        self.python_modules_include = QLineEdit("**/*.py")
        self.python_modules_include.setObjectName("python_modules_include")
        self.python_modules_exclude = QLineEdit(".venv/**; venv/**; tests/**; __pycache__/**")
        self.python_modules_exclude.setObjectName("python_modules_exclude")
        self.lease_hours = QSpinBox()
        self.lease_hours.setObjectName("lease_hours")
        self.lease_hours.setRange(1, 87600)
        self.lease_hours.setValue(720)
        self.offline_grace_hours = QSpinBox()
        self.offline_grace_hours.setObjectName("offline_grace_hours")
        self.offline_grace_hours.setRange(0, 87600)
        self.offline_grace_hours.setValue(168)
        self.perpetual_license = QCheckBox()
        self.perpetual_license.setObjectName("perpetual_license")
        self.allow_unsafe_dev_signing_key = QCheckBox()
        self.allow_unsafe_dev_signing_key.setObjectName("allow_unsafe_dev_signing_key")
        self.allow_unsafe_dev_signing_key.setChecked(True)

        self.product_id_label = QLabel()
        self.product_name_label = QLabel()
        self.product_version_label = QLabel()
        self.activation_url_label = QLabel()
        self.entry_file_label = QLabel()
        self.python_modules_include_label = QLabel()
        self.python_modules_exclude_label = QLabel()
        self.lease_hours_label = QLabel()
        self.offline_grace_hours_label = QLabel()
        config_form.addRow(self.product_id_label, self.product_id)
        config_form.addRow(self.product_name_label, self.product_name)
        config_form.addRow(self.product_version_label, self.product_version)
        config_form.addRow(self.activation_url_label, self.activation_url)
        config_form.addRow(self.entry_file_label, self.entry_file)
        config_form.addRow(self.python_modules_include_label, self.python_modules_include)
        config_form.addRow(self.python_modules_exclude_label, self.python_modules_exclude)
        config_form.addRow(self.lease_hours_label, self.lease_hours)
        config_form.addRow(self.offline_grace_hours_label, self.offline_grace_hours)
        config_form.addRow(self.perpetual_license)
        config_form.addRow(self.allow_unsafe_dev_signing_key)

        layout.addWidget(self.title)
        layout.addLayout(path_row)
        layout.addWidget(self.config_group)
        layout.addWidget(self.scan_output, 1)
        self.retranslate(language)

    def retranslate(self, language: LanguageCode) -> None:
        self.language = language
        self.title.setText(tr(language, "project.title"))
        self.root_label.setText(tr(language, "project.root_label"))
        self.project_path.setPlaceholderText(tr(language, "project.root_placeholder"))
        self.browse_project_file_button.setText(tr(language, "path.choose_file"))
        self.browse_project_folder_button.setText(tr(language, "path.choose_folder"))
        self.scan_button.setText(tr(language, "project.scan"))
        self.generate_config_button.setText(tr(language, "project.generate_config"))
        self.config_group.setTitle(tr(language, "project.config_helper"))
        self.product_id_label.setText(tr(language, "project.product_id"))
        self.product_id.setPlaceholderText(tr(language, "project.product_id_placeholder"))
        self.product_name_label.setText(tr(language, "project.product_name"))
        self.product_name.setPlaceholderText(tr(language, "project.product_name_placeholder"))
        self.product_version_label.setText(tr(language, "project.product_version"))
        self.activation_url_label.setText(tr(language, "project.activation_url"))
        self.entry_file_label.setText(tr(language, "project.entry_file"))
        self.python_modules_include_label.setText(tr(language, "project.modules_include"))
        self.python_modules_exclude_label.setText(tr(language, "project.modules_exclude"))
        self.lease_hours_label.setText(tr(language, "project.lease_hours"))
        self.offline_grace_hours_label.setText(tr(language, "project.offline_grace_hours"))
        self.perpetual_license.setText(tr(language, "project.perpetual_license"))
        self.allow_unsafe_dev_signing_key.setText(tr(language, "project.allow_dev_signing"))

    def browse_project_file(self) -> None:
        selected = choose_existing_file(
            self,
            tr(self.language, "path.dialog.source_file"),
            self.project_path.text(),
        )
        if selected is not None:
            self.project_path.setText(str(selected))

    def browse_project_folder(self) -> None:
        selected = choose_existing_folder(
            self,
            tr(self.language, "path.dialog.source_folder"),
            self.project_path.text(),
        )
        if selected is not None:
            self.project_path.setText(str(selected))

    def scan_current_path(self) -> None:
        raw_path = self.project_path.text().strip()
        if not raw_path:
            self.scan_output.setPlainText(tr(self.language, "project.select_first"))
            return
        self.set_project_root(Path(raw_path))

    def set_project_root(self, path: Path) -> None:
        self.state.project_root = path
        if path.is_file():
            self.state.config_path = None
            self.state.release_root = path.parent / f"{path.stem}-p"
        else:
            self.state.config_path = path / "skey.yaml"
            self.state.release_root = path.parent / f"{path.name}-p"
        run_background_task(
            self,
            lambda: ProtectionService.scan_project(path),
            self._show_scan_result,
            self._show_worker_failure,
            (self.scan_button, self.generate_config_button),
        )

    def _show_scan_result(self, result: OperationResult) -> None:
        self.state.last_result = result
        if not result.success:
            self.scan_output.setPlainText(result.message)
            return
        self.scan_output.setPlainText(
            "\n".join(
                (
                    tr(self.language, "project.scanned"),
                    tr(
                        self.language,
                        "project.python",
                        value=_join_detail(result.detail.get("python_entries"), self.language),
                    ),
                    tr(
                        self.language,
                        "project.exe",
                        value=_join_detail(result.detail.get("exe_entries"), self.language),
                    ),
                    tr(
                        self.language,
                        "project.jar",
                        value=_join_detail(result.detail.get("jar_entries"), self.language),
                    ),
                    tr(
                        self.language,
                        "project.resources",
                        value=_join_detail(result.detail.get("resource_entries"), self.language),
                    ),
                ),
            ),
        )
        self._populate_config_helper(result.detail)

    def generate_config_for_current_project(self) -> None:
        if self.state.project_root is None:
            self.scan_output.setPlainText(tr(self.language, "project.select_first"))
            return
        project_root = self.state.project_root
        if project_root.is_file():
            self.state.release_root = project_root.parent / f"{project_root.stem}-p"
            self.scan_output.setPlainText("Single-file shell builds do not need a project config.")
            return
        config_path = project_root / "skey.yaml"
        release_root = project_root.parent / f"{project_root.name}-p"
        self.state.config_path = config_path
        self.state.release_root = release_root
        draft = self._config_draft()
        run_background_task(
            self,
            lambda: ProtectionService.generate_interactive_config(
                path=config_path,
                draft=draft,
                force=True,
            ),
            self._show_config_result,
            self._show_worker_failure,
            (self.generate_config_button, self.scan_button),
        )

    def _show_config_result(self, result: OperationResult) -> None:
        self.state.last_result = result
        self.scan_output.setPlainText(result.message)

    def _show_worker_failure(self, message: str) -> None:
        self.scan_output.setPlainText(message)

    def _populate_config_helper(self, detail: dict[str, object]) -> None:
        if self.state.project_root is not None:
            project_name = self.state.project_root.name
            if not self.product_id.text().strip():
                self.product_id.setText(_safe_product_id(project_name))
            if not self.product_name.text().strip():
                self.product_name.setText(project_name)

        python_entries = detail.get("python_entries")
        if not isinstance(python_entries, list):
            return
        entries = [str(item) for item in python_entries]
        self.entry_file.clear()
        self.entry_file.addItems(entries)
        recommended = _recommended_python_entry(entries)
        if recommended:
            self.entry_file.setCurrentText(recommended)

    def _config_draft(self) -> ConfigWizardDraft:
        project_name = self.state.project_root.name if self.state.project_root is not None else "product"
        return ConfigWizardDraft(
            product_id=self.product_id.text().strip() or _safe_product_id(project_name),
            product_name=self.product_name.text().strip() or project_name,
            product_version=self.product_version.text().strip() or "1.0.0",
            activation_url=self.activation_url.text().strip() or "http://127.0.0.1:8000/v1",
            python_entry=self.entry_file.currentText().strip(),
            python_module_includes=_split_patterns(self.python_modules_include.text()),
            python_module_excludes=_split_patterns(self.python_modules_exclude.text()),
            lease_hours=self.lease_hours.value(),
            offline_grace_hours=self.offline_grace_hours.value(),
            allow_unsafe_dev_signing_key=self.allow_unsafe_dev_signing_key.isChecked(),
            perpetual_license=self.perpetual_license.isChecked(),
        )


def _join_detail(value: object, language: LanguageCode) -> str:
    if isinstance(value, list):
        visible_items = [str(item) for item in value[:MAX_VISIBLE_SCAN_ITEMS]]
        if not visible_items:
            return tr(language, "project.none")
        suffix = ""
        remaining_count = len(value) - len(visible_items)
        if remaining_count > 0:
            suffix = ", " + tr(language, "project.more_items", count=remaining_count)
        return ", ".join(visible_items) + suffix
    return tr(language, "project.none")


def _recommended_python_entry(entries: list[str]) -> str:
    for preferred in ("model_server.py", "main.py", "app.py", "server.py"):
        if preferred in entries:
            return preferred
    for entry in entries:
        if entry.endswith("/model_server.py") or entry.endswith("\\model_server.py"):
            return entry
    return entries[0] if entries else ""


def _split_patterns(raw_value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[;,\n]+", raw_value) if item.strip()]


def _safe_product_id(raw_name: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", raw_name.strip()).strip("-._")
    return normalized or "product"
