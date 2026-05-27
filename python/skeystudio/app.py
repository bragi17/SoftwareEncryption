from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import cast


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        program = sys.argv[0] if sys.argv else "skey-studio"
        args = list(sys.argv[1:])
    else:
        program = "skey-studio"
        args = list(argv)

    if "--smoke" in args:
        return 0

    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication

    from skeystudio.assets import resource_path
    from skeystudio.main_window import SKeyStudioWindow
    from skeystudio.theme import apply_theme

    existing_app = QApplication.instance()
    if existing_app is None:
        app = QApplication([program, *args])
    else:
        app = cast(QApplication, existing_app)

    apply_theme(app)
    app.setWindowIcon(QIcon(str(resource_path("assets/app_icon.png"))))
    window = SKeyStudioWindow()
    window.show()
    return app.exec()
