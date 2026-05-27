"""Sentinel-style envelope builders for mirrored Python folders and single files."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skeyprotect.config import SKeyConfig
from skeyprotect.package_writer import read_encrypted_blob_bytes, write_payload
from skeyprotect.release_builder import (
    _copy_required_jni_runtime,
    _copy_required_runtime,
    _find_jar_loader_jar,
    _payload_output_path,
    _replace_output_directory,
    _write_online_policy,
    _write_run_env_scripts,
)
from skeyprotect.runtime_manifest import RuntimeManifestFile, runtime_file_entry, write_runtime_manifest
from skeyprotect.scanner import scan_project
from skeyprotect.stubs import write_bootstrap, write_python_envelope_stub

DEFAULT_FEATURE = "RUN_PROTECTED"
DEFAULT_PUBLIC_KEY_ID = "vendor_sign_2026_01"


@dataclass(frozen=True)
class SprjxConfig:
    input_root: Path
    output_root: Path
    protected_globs: list[str]
    ignored_globs: list[str]
    feature_id: int


def write_python_folder_sprjx(
    *,
    input_root: Path,
    output_root: Path,
    sprjx_path: Path,
    protected_globs: list[str],
    ignored_globs: list[str],
    feature_id: int = 3,
) -> Path:
    """Write a Sentinel-compatible project description for a Python folder."""
    payload = {
        "info": {"version": "1.0"},
        "file_entries": {
            "__Comment": "Input_root and output_root must be different from each other.",
            "input_root": input_root.as_posix(),
            "output_root": output_root.as_posix(),
            "to_be_protected": [
                {
                    "input_glob": glob,
                    "ignore_glob": ";".join(ignored_globs),
                    "feature_id": feature_id,
                }
                for glob in protected_globs
            ],
        },
        "settings": {
            "global_feature_id": feature_id,
            "message_output_mode": {"windows": True, "stderr": True},
        },
    }
    sprjx_path.parent.mkdir(parents=True, exist_ok=True)
    sprjx_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=4),
        encoding="utf-8",
    )
    return sprjx_path


def read_sprjx(path: Path) -> SprjxConfig:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("sprjx config must be a JSON object")
    file_entries = raw.get("file_entries")
    settings = raw.get("settings", {})
    if not isinstance(file_entries, dict):
        raise ValueError("sprjx config is missing file_entries")
    protected_entries = file_entries.get("to_be_protected")
    if not isinstance(protected_entries, list):
        raise ValueError("sprjx config is missing protected entries")

    protected_globs: list[str] = []
    ignored_globs: list[str] = []
    for entry in protected_entries:
        if not isinstance(entry, dict):
            raise ValueError("sprjx protected entry must be an object")
        input_glob = entry.get("input_glob")
        if not isinstance(input_glob, str) or not input_glob.strip():
            raise ValueError("sprjx protected entry is missing input_glob")
        protected_globs.append(input_glob)
        ignore_glob = entry.get("ignore_glob", "")
        if isinstance(ignore_glob, str) and ignore_glob.strip():
            ignored_globs.extend(_split_sprjx_globs(ignore_glob))

    global_feature = 3
    if isinstance(settings, dict) and isinstance(settings.get("global_feature_id"), int):
        global_feature = int(settings["global_feature_id"])

    return SprjxConfig(
        input_root=Path(_required_string(file_entries, "input_root")),
        output_root=Path(_required_string(file_entries, "output_root")),
        protected_globs=protected_globs,
        ignored_globs=sorted(set(ignored_globs)),
        feature_id=global_feature,
    )


def build_python_folder_envelope(
    *,
    signing_key: Ed25519PrivateKey,
    package_key: bytes,
    sprjx_path: Path | None = None,
    project_root: Path | None = None,
    output_root: Path | None = None,
    config: SKeyConfig | None = None,
) -> Path:
    """Build a mirrored Python folder with runnable .py shells and *_r.py ciphertext."""
    if sprjx_path is not None:
        sprjx = read_sprjx(sprjx_path)
        project_root = project_root or sprjx.input_root
        output_root = output_root or sprjx.output_root
        effective_sprjx = SprjxConfig(
            input_root=project_root,
            output_root=output_root,
            protected_globs=sprjx.protected_globs,
            ignored_globs=sprjx.ignored_globs,
            feature_id=sprjx.feature_id,
        )
        config = config or _config_from_sprjx(effective_sprjx)
    if project_root is None or output_root is None or config is None:
        raise ValueError("project_root, output_root, and config are required")

    source_root = project_root.resolve(strict=True)
    product_root = output_root.resolve(strict=False)
    _replace_output_directory(product_root, source_root)
    _copy_source_tree(source_root, product_root)

    secure_root = product_root / ".secure"
    runtime_root = secure_root / "rt"
    runtime_root.mkdir(parents=True, exist_ok=True)
    for directory in ("license", "tmp", "logs"):
        (secure_root / directory).mkdir(parents=True, exist_ok=True)

    scan_result = scan_project(source_root, config)
    payload_result = write_payload(
        project_root=source_root,
        output_path=_payload_output_path(product_root, secure_root, config),
        package_key=package_key,
        signing_key=signing_key,
        scan_result=scan_result,
        config=config,
    )
    encrypted_blobs = read_encrypted_blob_bytes(payload_result.output_path)

    runtime_files: list[RuntimeManifestFile] = []
    runtime_files.extend(_copy_required_runtime(source_root, runtime_root))
    bootstrap_path = write_bootstrap(product_root)
    runtime_files.append(runtime_file_entry(bootstrap_path, "skey_bootstrap.py", "python_bootstrap"))
    runtime_files.append(_write_online_policy(secure_root, config))

    for blob in sorted(scan_result.blobs.values(), key=lambda item: item.id):
        if blob.kind != "python":
            continue
        stub_path = write_python_envelope_stub(product_root, blob.path, blob.feature)
        sidecar_path = _encrypted_python_sidecar(product_root, blob.path)
        sidecar_path.parent.mkdir(parents=True, exist_ok=True)
        sidecar_path.write_bytes(encrypted_blobs[blob.id])
        runtime_files.append(runtime_file_entry(stub_path, blob.path, "python_stub"))
        runtime_files.append(
            runtime_file_entry(
                sidecar_path,
                sidecar_path.relative_to(product_root).as_posix(),
                "python_stub",
            )
        )

    write_runtime_manifest(
        manifest_path=secure_root / "runtime.manifest",
        signature_path=secure_root / "runtime.manifest.sig",
        product_id=config.product.id,
        package_id=payload_result.package_id,
        files=runtime_files,
        signing_key=signing_key,
    )
    _write_run_env_scripts(product_root)
    return product_root


def build_single_file_envelope(
    *,
    project_root: Path,
    output_root: Path,
    config: SKeyConfig,
    signing_key: Ed25519PrivateKey,
    package_key: bytes,
) -> Path:
    """Build a same-name shell for one compiled artifact such as a JAR or EXE."""
    from skeyprotect.jar_loader import write_jar_loader
    from skeyprotect.wrappers import write_exe_shell

    source_root = project_root.resolve(strict=True)
    product_root = output_root.resolve(strict=False)
    _replace_output_directory(product_root, source_root)

    secure_root = product_root / ".secure"
    runtime_root = secure_root / "rt"
    runtime_root.mkdir(parents=True, exist_ok=True)
    for directory in ("license", "tmp", "logs"):
        (secure_root / directory).mkdir(parents=True, exist_ok=True)

    scan_result = scan_project(source_root, config)
    payload_result = write_payload(
        project_root=source_root,
        output_path=_payload_output_path(product_root, secure_root, config),
        package_key=package_key,
        signing_key=signing_key,
        scan_result=scan_result,
        config=config,
    )

    runtime_files: list[RuntimeManifestFile] = []
    runtime_files.extend(_copy_required_runtime(source_root, runtime_root))
    runtime_files.append(_write_online_policy(secure_root, config))

    for jar_entry in config.jar.entries:
        loader_jar = _find_jar_loader_jar(source_root)
        if loader_jar is None:
            raise FileNotFoundError("skey-loader JAR was not found; build it before release")
        output_path = write_jar_loader(product_root, jar_entry, loader_jar)
        runtime_files.append(runtime_file_entry(output_path, jar_entry.path, "jar_loader"))
        runtime_files.extend(_copy_required_jni_runtime(source_root, runtime_root))

    for exe_entry in config.exe.entries:
        shell_binary = _find_exe_shell_binary_for_envelope(source_root)
        output_path = write_exe_shell(product_root, exe_entry, shell_binary)
        runtime_files.append(runtime_file_entry(output_path, exe_entry.path, "exe_shell"))

    write_runtime_manifest(
        manifest_path=secure_root / "runtime.manifest",
        signature_path=secure_root / "runtime.manifest.sig",
        product_id=config.product.id,
        package_id=payload_result.package_id,
        files=runtime_files,
        signing_key=signing_key,
    )
    _write_run_env_scripts(product_root)
    return product_root


def config_for_single_artifact(input_file: Path, output_root: Path | None = None) -> SKeyConfig:
    """Create a minimal same-name shell config for a single JAR or EXE artifact."""
    source_file = input_file.resolve(strict=False)
    product_name = output_root.name if output_root is not None else f"{source_file.stem}-p"
    entry_path = source_file.name
    suffix = source_file.suffix.lower()
    jar_entries: list[dict[str, str]] = []
    exe_entries: list[dict[str, object]] = []
    if suffix == ".jar":
        jar_entries.append(
            {
                "path": entry_path,
                "feature": DEFAULT_FEATURE,
                "mode": "temp_jar_subprocess",
                "java_runtime": "bundled_or_system",
            },
        )
    elif suffix == ".exe":
        exe_entries.append(
            {
                "path": entry_path,
                "feature": DEFAULT_FEATURE,
                "materialize": "private_temp",
                "include_deps": [],
            },
        )
    else:
        raise ValueError("single-file shell currently supports .jar and .exe inputs")

    raw_config: dict[str, Any] = {
        "product": {
            "id": _safe_product_id(source_file.stem),
            "name": product_name,
            "version": "1.0.0",
        },
        "server": {
            "activation_url": "http://127.0.0.1:8000/v1",
            "public_key_id": DEFAULT_PUBLIC_KEY_ID,
        },
        "protection": {
            "package_file": ".secure/payload.skp",
            "crypto": {"aead": "AES-256-GCM", "kdf": "HKDF-SHA256", "signature": "Ed25519"},
        },
        "python": {
            "enabled": False,
            "entries": [],
            "modules": {"include": [], "exclude": []},
            "hidden_imports": [],
        },
        "exe": {"enabled": bool(exe_entries), "entries": exe_entries},
        "jar": {"enabled": bool(jar_entries), "entries": jar_entries},
        "resources": {"entries": []},
        "license": {
            "default_features": [DEFAULT_FEATURE],
            "machine_binding": {"pass_score": 70, "review_score": 50},
            "time": {"lease_hours": 720, "offline_grace_hours": 168},
        },
        "security": {"allow_unsafe_dev_signing_key": True},
    }
    return SKeyConfig.model_validate(raw_config)


def config_for_python_folder_sprjx(sprjx_path: Path) -> SKeyConfig:
    """Create the runtime config implied by a Sentinel-style project file."""
    return _config_from_sprjx(read_sprjx(sprjx_path))


def _config_from_sprjx(config: SprjxConfig) -> SKeyConfig:
    product_name = config.output_root.name
    raw_config: dict[str, Any] = {
        "product": {
            "id": _safe_product_id(config.input_root.name),
            "name": product_name,
            "version": "1.0.0",
        },
        "server": {
            "activation_url": "http://127.0.0.1:8000/v1",
            "public_key_id": DEFAULT_PUBLIC_KEY_ID,
        },
        "protection": {
            "package_file": ".secure/payload.skp",
            "crypto": {"aead": "AES-256-GCM", "kdf": "HKDF-SHA256", "signature": "Ed25519"},
        },
        "python": {
            "enabled": True,
            "entries": _python_entries_for_globs(config.input_root, config.protected_globs),
            "modules": {"include": config.protected_globs, "exclude": config.ignored_globs},
            "hidden_imports": [],
        },
        "exe": {"enabled": False, "entries": []},
        "jar": {"enabled": False, "entries": []},
        "resources": {"entries": []},
        "license": {
            "default_features": [DEFAULT_FEATURE],
            "machine_binding": {"pass_score": 70, "review_score": 50},
            "time": {"lease_hours": 720, "offline_grace_hours": 168},
        },
        "security": {"allow_unsafe_dev_signing_key": True},
    }
    return SKeyConfig.model_validate(raw_config)


def _python_entries_for_globs(input_root: Path, protected_globs: list[str]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for glob in protected_globs:
        for path in input_root.glob(glob):
            if path.is_file() and path.suffix == ".py":
                entries.append(
                    {
                        "path": path.relative_to(input_root).as_posix(),
                        "feature": DEFAULT_FEATURE,
                    }
                )
    return sorted(entries, key=lambda item: item["path"])


def _copy_source_tree(source_root: Path, product_root: Path) -> None:
    product_root_resolved = product_root.resolve(strict=False)
    for source_path in source_root.rglob("*"):
        if source_path.resolve(strict=False).is_relative_to(product_root_resolved):
            continue
        relative_path = source_path.relative_to(source_root)
        target_path = product_root / relative_path
        if source_path.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target_path)


def _encrypted_python_sidecar(product_root: Path, relative_path: str) -> Path:
    path = PurePosixPath(relative_path)
    return product_root / Path(path.with_name(f"{path.stem}_r{path.suffix}").as_posix())


def _split_sprjx_globs(raw_value: str) -> list[str]:
    return [item.strip() for item in raw_value.replace(",", ";").split(";") if item.strip()]


def _required_string(value: dict[str, object], key: str) -> str:
    raw = value.get(key)
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"sprjx config is missing {key}")
    return raw


def _safe_product_id(raw_name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in raw_name).strip("-._") or "product"


def _find_exe_shell_binary_for_envelope(source_root: Path) -> Path:
    from skeyprotect.release_builder import _find_exe_shell_binary

    shell_binary = _find_exe_shell_binary(source_root)
    if shell_binary is None:
        raise FileNotFoundError("skey-exe-shell binary was not found; build it before release")
    return shell_binary
