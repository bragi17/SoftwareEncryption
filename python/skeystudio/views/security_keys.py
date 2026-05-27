"""Keys and security view."""

from __future__ import annotations

from PySide6.QtWidgets import QGroupBox, QLabel, QPushButton, QTextEdit, QVBoxLayout, QWidget

from skeystudio.i18n import DEFAULT_LANGUAGE, LanguageCode, tr
from skeystudio.services.keys import KeyService, mask_secret
from skeystudio.state import ProjectState, UserMode


class SecurityKeysView(QWidget):
    def __init__(self, state: ProjectState, language: LanguageCode = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self.state = state
        self.language = language

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.title = QLabel()
        self.title.setProperty("role", "pageTitle")
        self.operator_note = QLabel()
        self.operator_note.setProperty("role", "muted")
        self.generate_test_keys_button = QPushButton()
        self.generate_test_keys_button.clicked.connect(self.generate_test_keys)
        self.output = QTextEdit()
        self.output.setObjectName("key_summary")
        self.output.setReadOnly(True)

        self.secret_group = QGroupBox()
        self.secret_group.setObjectName("secret_group")
        secret_layout = QVBoxLayout(self.secret_group)
        self.secret_output = QTextEdit()
        self.secret_output.setObjectName("secret_values")
        self.secret_output.setReadOnly(True)
        self.secret_note = QLabel()
        secret_layout.addWidget(self.secret_note)
        secret_layout.addWidget(self.secret_output)

        layout.addWidget(self.title)
        layout.addWidget(self.operator_note)
        layout.addWidget(self.generate_test_keys_button)
        layout.addWidget(self.output, 1)
        layout.addWidget(self.secret_group)
        self.retranslate(language)
        self.apply_mode(state.mode)

    def retranslate(self, language: LanguageCode) -> None:
        self.language = language
        self.title.setText(tr(language, "keys.title"))
        self.operator_note.setText(tr(language, "keys.note"))
        self.generate_test_keys_button.setText(tr(language, "keys.generate"))
        self.secret_group.setTitle(tr(language, "keys.secret_group"))
        self.secret_note.setText(tr(language, "keys.secret_note"))

    def apply_mode(self, mode: UserMode) -> None:
        self.secret_group.setHidden(mode is UserMode.OPERATOR)

    def generate_test_keys(self) -> None:
        bundle = KeyService.generate_test_key_set()
        self.output.setPlainText(
            "\n".join(
                (
                    f"vendor_public_key_b64={bundle.vendor_public_key_b64}",
                    f"vendor_public_key_sha256={bundle.vendor_public_key_sha256}",
                    f"build_signing_private_key_b64={mask_secret(bundle.build_signing_private_key_b64)}",
                    f"package_kek_b64={mask_secret(bundle.package_kek_b64)}",
                    f"admin_wrap_key_b64={mask_secret(bundle.admin_wrap_key_b64)}",
                ),
            ),
        )
        self.secret_output.setPlainText(
            "\n".join(
                (
                    f"build_signing_private_key_b64={bundle.build_signing_private_key_b64}",
                    f"package_kek_b64={bundle.package_kek_b64}",
                    f"admin_wrap_key_b64={bundle.admin_wrap_key_b64}",
                ),
            ),
        )
