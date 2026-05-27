"""Executable shell launchers for protected EXE entries."""

from __future__ import annotations

import shutil
from pathlib import Path

from skeyprotect.config import ExeEntry


def write_exe_shell(product_root: Path, entry: ExeEntry, shell_binary: Path) -> Path:
    """Write the same-name executable shell without copying plaintext EXE bytes."""
    output_path = product_root / Path(entry.path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(shell_binary, output_path)
    return output_path
