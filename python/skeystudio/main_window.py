"""Main desktop shell for SKey Studio."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from skeystudio.assets import resource_path
from skeystudio.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    LanguageCode,
    mode_label,
    server_status_label,
    tr,
)
from skeystudio.state import ProjectState, UserMode
from skeystudio.views.activation_center import ActivationCenterView
from skeystudio.views.build_release import BuildReleaseView
from skeystudio.views.dashboard import DashboardView
from skeystudio.views.diagnostics import DiagnosticsView
from skeystudio.views.help_center import HelpCenterView
from skeystudio.views.project_workbench import ProjectWorkbenchView
from skeystudio.views.security_keys import SecurityKeysView
from skeystudio.views.server_console import ServerConsoleView


NAV_KEYS = (
    "nav.dashboard",
    "nav.project",
    "nav.keys",
    "nav.build",
    "nav.server",
    "nav.activation",
    "nav.diagnostics",
    "nav.help",
)


class SKeyStudioWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.project_state = ProjectState()
        self.language: LanguageCode = DEFAULT_LANGUAGE
        self.navigation_buttons: list[QPushButton] = []

        self.setWindowTitle("SKey Studio")
        self.setWindowIcon(QIcon(str(resource_path("assets/app_icon.png"))))
        self.resize(1280, 760)

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        navigation = self._build_navigation()
        content = self._build_content()

        root_layout.addWidget(navigation)
        root_layout.addWidget(content, 1)
        self.setCentralWidget(root)

    def set_mode(self, mode: UserMode) -> None:
        self.project_state.mode = mode
        self.keys_view.apply_mode(mode)
        self.server_view.apply_mode(mode)
        self._refresh_topbar()

    def set_language(self, language: str) -> None:
        if language not in SUPPORTED_LANGUAGES:
            return
        self.language = language
        if self.language_combo.currentData() != language:
            index = self.language_combo.findData(language)
            if index >= 0:
                self.language_combo.blockSignals(True)
                self.language_combo.setCurrentIndex(index)
                self.language_combo.blockSignals(False)
        for index, button in enumerate(self.navigation_buttons):
            button.setText(tr(self.language, NAV_KEYS[index]))
        for view in (
            self.dashboard_view,
            self.project_view,
            self.keys_view,
            self.build_view,
            self.server_view,
            self.activation_view,
            self.diagnostics_view,
            self.help_view,
        ):
            view.retranslate(self.language)
        self.language_label.setText(tr(self.language, "topbar.language"))
        self._refresh_topbar()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.server_view.shutdown()
        super().closeEvent(event)

    def _build_navigation(self) -> QFrame:
        navigation = QFrame()
        navigation.setObjectName("navigation_rail")
        navigation.setFixedWidth(218)
        nav_layout = QVBoxLayout(navigation)
        nav_layout.setContentsMargins(14, 14, 14, 14)
        nav_layout.setSpacing(7)

        brand_image = QLabel()
        brand_image.setObjectName("brand_mark")
        brand_pixmap = QPixmap(str(resource_path("assets/brand-mark.png")))
        if not brand_pixmap.isNull():
            brand_image.setPixmap(
                brand_pixmap.scaled(
                    178,
                    54,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                ),
            )
        else:
            brand_image.setText("SKey Studio")
        nav_layout.addWidget(brand_image)

        self.navigation_group = QButtonGroup(self)
        self.navigation_group.setExclusive(True)
        for index, label_key in enumerate(NAV_KEYS):
            button = QPushButton(tr(self.language, label_key))
            button.setObjectName(f"nav_{index}")
            button.setCheckable(True)
            button.setProperty("nav", True)
            button.clicked.connect(lambda checked=False, page=index: self.stack.setCurrentIndex(page))
            self.navigation_group.addButton(button, index)
            self.navigation_buttons.append(button)
            nav_layout.addWidget(button)
        nav_layout.addStretch(1)
        return navigation

    def _build_content(self) -> QWidget:
        content = QFrame()
        content.setObjectName("content_shell")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(18, 14, 18, 18)
        content_layout.setSpacing(12)

        topbar = QHBoxLayout()
        topbar.setSpacing(8)
        self.project_label = _topbar_label()
        self.release_label = _topbar_label()
        self.server_label = _topbar_label()
        self.mode_label = _topbar_label()
        self.language_label = QLabel()
        self.language_label.setProperty("role", "muted")
        self.language_combo = QComboBox()
        for code, label in SUPPORTED_LANGUAGES.items():
            self.language_combo.addItem(label, code)
        self.language_combo.currentIndexChanged.connect(self._change_language_from_combo)
        self.mode_button = QPushButton()
        self.mode_button.setObjectName("mode_toggle_button")
        self.mode_button.clicked.connect(self._toggle_mode)
        topbar.addWidget(self.project_label)
        topbar.addWidget(self.release_label)
        topbar.addWidget(self.server_label)
        topbar.addStretch(1)
        topbar.addWidget(self.language_label)
        topbar.addWidget(self.language_combo)
        topbar.addWidget(self.mode_label)
        topbar.addWidget(self.mode_button)

        self.stack = QStackedWidget()
        self.dashboard_view = DashboardView(self.project_state, self.language)
        self.project_view = ProjectWorkbenchView(self.project_state, self.language)
        self.keys_view = SecurityKeysView(self.project_state, self.language)
        self.build_view = BuildReleaseView(self.project_state, self.language)
        self.server_view = ServerConsoleView(self.project_state, self.language)
        self.activation_view = ActivationCenterView(self.project_state, self.language)
        self.diagnostics_view = DiagnosticsView(self.project_state, self.language)
        self.help_view = HelpCenterView(self.language)

        for view in (
            self.dashboard_view,
            self.project_view,
            self.keys_view,
            self.build_view,
            self.server_view,
            self.activation_view,
            self.diagnostics_view,
            self.help_view,
        ):
            self.stack.addWidget(view)

        self.navigation_buttons[0].setChecked(True)
        self.dashboard_view.primary_button.clicked.connect(lambda: self.stack.setCurrentIndex(3))
        self.stack.currentChanged.connect(self._sync_navigation)
        content_layout.addLayout(topbar)
        content_layout.addWidget(self.stack, 1)
        self._refresh_topbar()
        return content

    def _toggle_mode(self) -> None:
        next_mode = (
            UserMode.ADVANCED_ADMIN
            if self.project_state.mode is UserMode.OPERATOR
            else UserMode.OPERATOR
        )
        self.set_mode(next_mode)

    def _sync_navigation(self, index: int) -> None:
        button = self.navigation_group.button(index)
        if button is not None:
            button.setChecked(True)

    def _change_language_from_combo(self, _index: int = 0) -> None:
        value = self.language_combo.currentData()
        if isinstance(value, str):
            self.set_language(value)

    def _refresh_topbar(self) -> None:
        project = (
            str(self.project_state.project_root)
            if self.project_state.project_root
            else tr(self.language, "not_selected")
        )
        release = (
            str(self.project_state.release_root)
            if self.project_state.release_root
            else tr(self.language, "not_selected")
        )
        self.project_label.setText(tr(self.language, "topbar.project", value=project))
        self.release_label.setText(tr(self.language, "topbar.release", value=release))
        self.server_label.setText(
            tr(
                self.language,
                "topbar.server",
                value=server_status_label(self.project_state.server, self.language),
            ),
        )
        self.mode_label.setText(
            tr(
                self.language,
                "topbar.mode",
                value=mode_label(self.project_state.mode, self.language),
            ),
        )
        self.mode_button.setText(
            tr(self.language, "mode.switch_to_operator")
            if self.project_state.mode is UserMode.ADVANCED_ADMIN
            else tr(self.language, "mode.switch_to_admin"),
        )
        self.language_label.setText(tr(self.language, "topbar.language"))
        self.dashboard_view.refresh()


def _topbar_label() -> QLabel:
    label = QLabel()
    label.setProperty("role", "status")
    return label
