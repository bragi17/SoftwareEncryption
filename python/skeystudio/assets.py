from __future__ import annotations

import sys
from pathlib import Path


def resource_path(relative_path: str) -> Path:
    """Resolve a Studio asset in source or PyInstaller-frozen mode."""

    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        root = Path(str(getattr(sys, "_MEIPASS")))
    else:
        root = Path(__file__).resolve().parent
    return root / relative_path
