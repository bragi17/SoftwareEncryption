# -*- mode: python ; coding: utf-8 -*-
# ruff: noqa: F821

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


spec_dir = Path(SPECPATH).resolve()
repo_root = spec_dir.parents[1]
python_root = repo_root / "python"
entry_root = repo_root / "build" / "pyinstaller-entrypoints"
entry_root.mkdir(parents=True, exist_ok=True)
entry_script = entry_root / "skey_protect_entry.py"
entry_script.write_text(
    "from skeyprotect.cli import app\n\n"
    "if __name__ == '__main__':\n"
    "    app()\n",
    encoding="utf-8",
)
runtime_hook = entry_root / "skey_protect_runtime_hook.py"
runtime_hook.write_text(
    "import os\n"
    "import sys\n"
    "from pathlib import Path\n\n"
    "if getattr(sys, 'frozen', False):\n"
    "    os.environ.setdefault('SKEY_TOOL_ARTIFACT_ROOT', str(Path(sys.executable).parent))\n",
    encoding="utf-8",
)

datas = [
    (
        str(python_root / "skeyprotect" / "templates"),
        "skeyprotect/templates",
    ),
]

hiddenimports = collect_submodules("skeyprotect")

a = Analysis(
    [str(entry_script)],
    pathex=[str(python_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(runtime_hook)],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="skey-protect",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
