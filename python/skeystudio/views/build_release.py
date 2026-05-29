"""Build and verify protected release view."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
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
from skeystudio.widgets.path_picker import (
    choose_existing_file,
    choose_existing_folder,
    path_input_row,
)
from skeystudio.workers import run_background_task


class BuildReleaseView(QWidget):
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
        self.project_path.setObjectName("build_project_path")
        self.config_path = QLineEdit()
        self.config_path.setObjectName("build_config_path")
        self.release_path = QLineEdit()
        self.release_path.setObjectName("release_path")
        self.cross_platform_runtime = QCheckBox()
        self.cross_platform_runtime.setObjectName("build_cross_platform_runtime")
        self.browse_project_file_button = QPushButton()
        self.browse_project_file_button.setObjectName("build_browse_project_file")
        self.browse_project_file_button.clicked.connect(self.browse_project_file)
        self.browse_project_folder_button = QPushButton()
        self.browse_project_folder_button.setObjectName("build_browse_project_folder")
        self.browse_project_folder_button.clicked.connect(self.browse_project_folder)
        self.browse_config_file_button = QPushButton()
        self.browse_config_file_button.setObjectName("build_browse_config_file")
        self.browse_config_file_button.clicked.connect(self.browse_config_file)
        self.browse_release_folder_button = QPushButton()
        self.browse_release_folder_button.setObjectName("build_browse_release_folder")
        self.browse_release_folder_button.clicked.connect(self.browse_release_folder)
        self.build_button = QPushButton()
        self.build_button.setProperty("primary", True)
        self.build_button.clicked.connect(self.prepare_build)
        self.verify_button = QPushButton()
        self.verify_button.clicked.connect(self.verify_runtime)
        self.log = QTextEdit()
        self.log.setObjectName("build_log")
        self.log.setReadOnly(True)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(8)
        self.project_label = QLabel()
        self.config_label = QLabel()
        self.release_label = QLabel()
        form.addRow(
            self.project_label,
            path_input_row(
                self.project_path,
                self.browse_project_file_button,
                self.browse_project_folder_button,
            ),
        )
        form.addRow(self.config_label, path_input_row(self.config_path, self.browse_config_file_button))
        form.addRow(
            self.release_label,
            path_input_row(self.release_path, self.browse_release_folder_button),
        )
        form.addRow("", self.cross_platform_runtime)

        action_row = QHBoxLayout()
        action_row.addStretch(1)
        action_row.addWidget(self.build_button)
        action_row.addWidget(self.verify_button)

        layout.addWidget(self.title)
        layout.addLayout(form)
        layout.addLayout(action_row)
        layout.addWidget(self.log, 1)
        self.retranslate(language)

    def retranslate(self, language: LanguageCode) -> None:
        self.language = language
        self.title.setText(tr(language, "build.title"))
        self.project_label.setText(tr(language, "build.project_label"))
        self.project_path.setPlaceholderText(tr(language, "build.project_placeholder"))
        self.browse_project_file_button.setText(tr(language, "path.choose_file"))
        self.browse_project_folder_button.setText(tr(language, "path.choose_folder"))
        self.config_label.setText(tr(language, "build.config_label"))
        self.config_path.setPlaceholderText(tr(language, "build.config_placeholder"))
        self.browse_config_file_button.setText(tr(language, "path.choose_file"))
        self.release_label.setText(tr(language, "build.release_label"))
        self.release_path.setPlaceholderText(tr(language, "build.release_placeholder"))
        self.browse_release_folder_button.setText(tr(language, "path.choose_folder"))
        self.cross_platform_runtime.setText(tr(language, "build.cross_platform_runtime"))
        self.cross_platform_runtime.setToolTip(tr(language, "build.cross_platform_hint"))
        self.build_button.setText(tr(language, "build.build"))
        self.verify_button.setText(tr(language, "build.verify"))

    def browse_project_file(self) -> None:
        selected = choose_existing_file(
            self,
            tr(self.language, "path.dialog.source_file"),
            self.project_path.text(),
        )
        if selected is not None:
            self._apply_source_path(selected)

    def browse_project_folder(self) -> None:
        selected = choose_existing_folder(
            self,
            tr(self.language, "path.dialog.source_folder"),
            self.project_path.text(),
        )
        if selected is not None:
            self._apply_source_path(selected)

    def browse_config_file(self) -> None:
        selected = choose_existing_file(
            self,
            tr(self.language, "path.dialog.config_file"),
            self.config_path.text(),
            "SKey config (*.yaml *.yml *.sprjx);;All files (*)",
        )
        if selected is not None:
            self.state.config_path = selected
            self.config_path.setText(str(selected))

    def browse_release_folder(self) -> None:
        selected = choose_existing_folder(
            self,
            tr(self.language, "path.dialog.release_folder"),
            self.release_path.text(),
        )
        if selected is not None:
            self.state.release_root = selected
            self.release_path.setText(str(selected))

    def _apply_source_path(self, project_root: Path) -> None:
        config_path = _default_config_path(project_root)
        release_root = _default_release_path(project_root)
        self._store_resolved_paths(project_root, config_path, release_root)
        if config_path is None:
            self.state.config_path = None
            self.config_path.clear()

    def prepare_build(self) -> None:
        project_root, config_path, release_root = self._resolve_build_paths()
        missing = []
        if project_root is None:
            missing.append(tr(self.language, "field.project_root"))
        if release_root is None:
            missing.append(tr(self.language, "field.release_path"))
        if missing:
            self.log.setPlainText(tr(self.language, "build.missing", fields=", ".join(missing)))
            return
        assert project_root is not None
        assert release_root is not None
        run_background_task(
            self,
            lambda: ProtectionService.build_release_product(
                project_root=project_root,
                config_path=config_path,
                release_path=release_root,
                require_cross_platform_runtime=self.cross_platform_runtime.isChecked(),
            ),
            self._show_build_result,
            self._show_worker_failure,
            (self.build_button, self.verify_button, self.cross_platform_runtime),
        )

    def verify_runtime(self) -> None:
        release_root = self._current_release_root()
        if release_root is None:
            self.log.setPlainText(tr(self.language, "build.select_first"))
            return
        run_background_task(
            self,
            lambda: ProtectionService.verify_runtime(release_root),
            self._show_verify_result,
            self._show_worker_failure,
            (self.verify_button, self.build_button),
        )

    def _show_build_result(self, result: OperationResult) -> None:
        self.state.last_result = result
        product_root = result.detail.get("product_root")
        if result.success and isinstance(product_root, str):
            self.state.release_root = Path(product_root)
        self.log.setPlainText(result.message)

    def _show_verify_result(self, result: OperationResult) -> None:
        self.state.last_result = result
        self.log.setPlainText(result.message)

    def _show_worker_failure(self, message: str) -> None:
        self.log.setPlainText(message)

    def _release_path(self) -> Path | None:
        raw_release_path = self.release_path.text().strip()
        return Path(raw_release_path) if raw_release_path else None

    def _project_path(self) -> Path | None:
        raw_project_path = self.project_path.text().strip()
        return Path(raw_project_path) if raw_project_path else None

    def _config_path(self) -> Path | None:
        raw_config_path = self.config_path.text().strip()
        return Path(raw_config_path) if raw_config_path else None

    def _resolve_build_paths(self) -> tuple[Path | None, Path | None, Path | None]:
        project_root = self._project_path() or self.state.project_root
        config_path = self._config_path() or self.state.config_path
        release_root = self._release_path() or self.state.release_root

        if release_root is not None:
            possible_config = release_root / "skey.yaml"
            if project_root is not None and _same_path(release_root, project_root):
                release_root = _default_release_path(project_root)
            elif possible_config.is_file():
                project_root = release_root
                config_path = possible_config
                release_root = _default_release_path(project_root)

        if project_root is not None and config_path is None:
            config_path = _default_config_path(project_root)

        if project_root is not None and release_root is None:
            release_root = _default_release_path(project_root)

        self._store_resolved_paths(project_root, config_path, release_root)
        return project_root, config_path, release_root

    def _store_resolved_paths(
        self,
        project_root: Path | None,
        config_path: Path | None,
        release_root: Path | None,
    ) -> None:
        if project_root is not None:
            self.state.project_root = project_root
            self.project_path.setText(str(project_root))
        if config_path is not None:
            self.state.config_path = config_path
            self.config_path.setText(str(config_path))
        if release_root is not None:
            self.state.release_root = release_root
            self.release_path.setText(str(release_root))

    def _current_release_root(self) -> Path | None:
        visible_release = self._release_path()
        if visible_release is not None:
            self.state.release_root = visible_release
            return visible_release
        return self.state.release_root


def _default_release_path(project_root: Path) -> Path:
    if project_root.is_file():
        return project_root.parent / f"{project_root.stem}-p"
    return project_root.parent / f"{project_root.name}-p"


def _default_config_path(project_root: Path) -> Path | None:
    if project_root.is_file():
        return None
    yaml_path = project_root / "skey.yaml"
    if yaml_path.is_file():
        return yaml_path
    sprjx_path = project_root.parent / f"{project_root.name}.sprjx"
    if sprjx_path.is_file():
        return sprjx_path
    return None


def _same_path(left: Path, right: Path) -> bool:
    return left.resolve(strict=False) == right.resolve(strict=False)
