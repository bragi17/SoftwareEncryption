"""JAR loader release artifact helpers."""

from __future__ import annotations

import shutil
from pathlib import Path

from skeyprotect.config import JarEntry


def write_jar_loader(product_root: Path, entry: JarEntry, loader_jar: Path) -> Path:
    """Write the executable SKey JAR loader at the protected JAR entrypoint path."""
    if not loader_jar.is_file():
        raise FileNotFoundError(f"skey loader JAR was not found: {loader_jar}")

    output_path = product_root / Path(entry.path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(loader_jar, output_path)
    return output_path
