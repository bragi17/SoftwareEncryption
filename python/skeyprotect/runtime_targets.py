"""Runtime target inspection for protected release layouts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RUNTIME_ROLE = "runtime_ffi"
JNI_RUNTIME_ROLE = "jni_runtime"

TARGET_FILES = {
    "windows": {
        RUNTIME_ROLE: "skey_rt.dll",
        JNI_RUNTIME_ROLE: "skey_jni.dll",
    },
    "linux": {
        RUNTIME_ROLE: "libskey_rt.so",
        JNI_RUNTIME_ROLE: "libskey_jni.so",
    },
}


@dataclass(frozen=True)
class RuntimeTargetReport:
    required_roles: tuple[str, ...]
    present_files: tuple[str, ...]
    missing_files: tuple[str, ...]
    windows_ready: bool
    linux_ready: bool

    @property
    def windows_linux_ready(self) -> bool:
        return self.windows_ready and self.linux_ready

    def summary(self) -> str:
        targets = [
            f"Windows={'yes' if self.windows_ready else 'no'}",
            f"Linux={'yes' if self.linux_ready else 'no'}",
        ]
        if self.missing_files:
            targets.append(f"missing={', '.join(self.missing_files)}")
        return "; ".join(targets)

    def as_detail(self) -> dict[str, object]:
        return {
            "required_roles": list(self.required_roles),
            "present_files": list(self.present_files),
            "missing_files": list(self.missing_files),
            "windows_ready": self.windows_ready,
            "linux_ready": self.linux_ready,
            "windows_linux_ready": self.windows_linux_ready,
        }


def inspect_runtime_targets(product_root: Path) -> RuntimeTargetReport:
    """Inspect whether a release has the native files needed for Windows and Linux."""
    required_roles = _required_runtime_roles(product_root)
    runtime_root = product_root / ".secure" / "rt"
    required_files = _required_target_files(required_roles)
    present_files = tuple(
        sorted(filename for filename in required_files if (runtime_root / filename).is_file()),
    )
    missing_files = tuple(sorted(set(required_files) - set(present_files)))
    return RuntimeTargetReport(
        required_roles=required_roles,
        present_files=present_files,
        missing_files=missing_files,
        windows_ready=_target_ready(runtime_root, required_roles, "windows"),
        linux_ready=_target_ready(runtime_root, required_roles, "linux"),
    )


def _required_runtime_roles(product_root: Path) -> tuple[str, ...]:
    manifest = _read_runtime_manifest(product_root / ".secure" / "runtime.manifest")
    files = manifest.get("files", [])
    if not isinstance(files, list):
        raise ValueError("runtime manifest files must be a list")

    roles: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        if role in {RUNTIME_ROLE, JNI_RUNTIME_ROLE}:
            roles.add(role)
    return tuple(sorted(roles))


def _read_runtime_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("runtime manifest must be an object")
    return manifest


def _required_target_files(required_roles: tuple[str, ...]) -> tuple[str, ...]:
    files: set[str] = set()
    for role in required_roles:
        for target in TARGET_FILES.values():
            files.add(target[role])
    return tuple(sorted(files))


def _target_ready(runtime_root: Path, required_roles: tuple[str, ...], target_name: str) -> bool:
    target = TARGET_FILES[target_name]
    return all((runtime_root / target[role]).is_file() for role in required_roles)
