"""Adapters around protector workflows for the SKey Studio UI."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from secrets import token_bytes
from json import JSONDecodeError
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml  # type: ignore[import-untyped]
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from skeyprotect.activation_client import (
    ActivationClientError,
    activate_online,
    create_offline_request,
    import_offline_response,
)
from skeyprotect.customer_key import write_customer_key_file
from skeyprotect.cli import (
    _build_signing_key,
    _config_for_output_directory,
    _config_template_text,
    _output_root_for,
    _payload_path,
    _read_admin_wrap_key,
    _read_payload_info,
    _unsafe_dev_signing_key,
    _write_admin_key_record,
    _write_runtime_public_key,
)
from skeyprotect.config import load_config
from skeyprotect.envelope_builder import (
    DEFAULT_PUBLIC_KEY_ID,
    build_python_folder_envelope,
    build_single_file_envelope,
    config_for_python_folder_sprjx,
    config_for_single_artifact,
    write_python_folder_sprjx,
)
from skeyprotect.manifest import canonical_json_bytes
from skeyprotect.release_builder import build_release
from skeyprotect.runtime_targets import inspect_runtime_targets
from skeystudio.config_wizard import ConfigWizardDraft, config_dict_from_draft
from skeystudio.state import OperationResult


RESOURCE_PATTERNS = ("*.dat", "*.bin", "*.model", "*.onnx")
RUNTIME_PUBLIC_KEY_SIDECAR = "runtime.manifest.public-key.json"
SCAN_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".venv",
    "__pycache__",
    "env",
    "node_modules",
    "venv",
}
DEFAULT_PYTHON_EXCLUDES = [".venv/**", "venv/**", "tests/**", "__pycache__/**"]


class ProtectionService:
    @staticmethod
    def generate_starter_config(path: Path, force: bool) -> OperationResult:
        if path.exists() and not force:
            return OperationResult.fail(
                f"Config already exists: {path}",
                code="config_exists",
                detail={"path": str(path)},
            )

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_config_template_text(), encoding="utf-8")
        return OperationResult.ok("Starter config written", detail={"path": str(path)})

    @staticmethod
    def generate_interactive_config(
        path: Path,
        draft: ConfigWizardDraft,
        force: bool,
    ) -> OperationResult:
        if path.exists() and not force:
            return OperationResult.fail(
                f"Config already exists: {path}",
                code="config_exists",
                detail={"path": str(path)},
            )

        path.parent.mkdir(parents=True, exist_ok=True)
        config_dict = config_dict_from_draft(draft)
        path.write_text(
            yaml.safe_dump(config_dict, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        return OperationResult.ok("Config saved", detail={"path": str(path)})

    @staticmethod
    def generate_python_sprjx_config(
        *,
        path: Path,
        input_root: Path,
        output_root: Path,
        protected_globs: list[str],
        ignored_globs: list[str],
        force: bool,
    ) -> OperationResult:
        if path.exists() and not force:
            return OperationResult.fail(
                f"Config already exists: {path}",
                code="config_exists",
                detail={"path": str(path)},
            )
        try:
            write_python_folder_sprjx(
                input_root=input_root.resolve(strict=False),
                output_root=output_root.resolve(strict=False),
                sprjx_path=path,
                protected_globs=protected_globs or ["**/*.py"],
                ignored_globs=ignored_globs,
            )
        except OSError as exc:
            return OperationResult.fail(
                f"Config could not be saved: {exc}",
                code="config_save_failed",
                detail={"path": str(path)},
            )
        return OperationResult.ok("Config saved", detail={"path": str(path)})

    @staticmethod
    def load_config(path: Path) -> OperationResult:
        try:
            config = load_config(path)
        except (OSError, ValueError, ValidationError, yaml.YAMLError) as exc:
            return OperationResult.fail(
                f"Config is invalid: {exc}",
                code="config_invalid",
                detail={"path": str(path)},
            )

        return OperationResult.ok(
            "Config loaded",
            detail={"path": str(path), "config": config.model_dump(mode="json")},
        )

    @staticmethod
    def scan_project(project_root: Path) -> OperationResult:
        if project_root.is_file():
            suffix = project_root.suffix.lower()
            detail = {
                "python_entries": [project_root.name] if suffix == ".py" else [],
                "exe_entries": [project_root.name] if suffix == ".exe" else [],
                "jar_entries": [project_root.name] if suffix == ".jar" else [],
                "resource_entries": [] if suffix in {".py", ".exe", ".jar"} else [project_root.name],
            }
            return OperationResult.ok("Project scanned", detail=detail)

        if not project_root.is_dir():
            return OperationResult.fail(
                f"Project folder does not exist: {project_root}",
                code="project_missing",
                detail={"project_root": str(project_root)},
            )

        detail = {
            "python_entries": _relative_matches(project_root, "*.py"),
            "exe_entries": _relative_matches(project_root, "*.exe"),
            "jar_entries": _relative_matches(project_root, "*.jar"),
            "resource_entries": sorted(
                {
                    path.relative_to(project_root).as_posix()
                    for pattern in RESOURCE_PATTERNS
                    for path in _iter_scannable_files(project_root)
                    if path.match(pattern)
                },
            ),
        }
        return OperationResult.ok("Project scanned", detail=detail)

    @staticmethod
    def inspect_payload(payload_path: Path) -> OperationResult:
        if not payload_path.is_file():
            return OperationResult.fail(
                f"Payload file does not exist: {payload_path}",
                code="payload_missing",
                detail={"payload_path": str(payload_path)},
            )

        try:
            payload_info = _read_payload_info(payload_path)
        except (OSError, ValueError, JSONDecodeError) as exc:
            return OperationResult.fail(
                f"Payload is invalid: {exc}",
                code="payload_invalid",
                detail={"payload_path": str(payload_path)},
            )

        return OperationResult.ok("Payload inspected", detail=payload_info)

    @staticmethod
    def build_release_product(
        *,
        project_root: Path,
        config_path: Path | None,
        release_path: Path,
        emit_admin_key_record: bool = False,
        admin_wrap_key_file: Path | None = None,
        require_cross_platform_runtime: bool = False,
    ) -> OperationResult:
        admin_wrap_key: bytes | None = None
        if emit_admin_key_record:
            if admin_wrap_key_file is None:
                return OperationResult.fail(
                    "Admin wrap key file is required",
                    code="admin_wrap_key_missing",
                    detail={"release_path": str(release_path)},
                )
            try:
                admin_wrap_key = _read_admin_wrap_key(admin_wrap_key_file)
            except (OSError, ValueError, binascii.Error) as exc:
                return OperationResult.fail(
                    f"Admin wrap key is invalid: {exc}",
                    code="admin_wrap_key_invalid",
                    detail={"path": str(admin_wrap_key_file)},
                )

        package_key = token_bytes(32)
        effective_config_path = config_path
        payload_file = ".secure/payload.skp"
        public_key_id = DEFAULT_PUBLIC_KEY_ID
        unsafe_signing = True
        customer_key_config = None
        try:
            if config_path is None:
                signing_key = _unsafe_dev_signing_key()
                if project_root.is_file():
                    build_config = config_for_single_artifact(project_root, release_path)
                    customer_key_config = build_config
                    public_key_id = build_config.server.public_key_id
                    payload_file = build_config.protection.package_file
                    product_root = build_single_file_envelope(
                        project_root=project_root.parent,
                        output_root=release_path,
                        config=build_config,
                        signing_key=signing_key,
                        package_key=package_key,
                    )
                else:
                    effective_config_path = project_root / "skey.yaml"
                    if not effective_config_path.exists():
                        auto_config = config_dict_from_draft(
                            ConfigWizardDraft(
                                product_id=_safe_product_id(project_root.name),
                                product_name=project_root.name,
                                product_version="1.0.0",
                                activation_url="http://127.0.0.1:8000/v1",
                                python_entry=_first_python_entry(project_root),
                                python_module_includes=["**/*.py"],
                                python_module_excludes=DEFAULT_PYTHON_EXCLUDES,
                                lease_hours=720,
                                offline_grace_hours=168,
                                allow_unsafe_dev_signing_key=True,
                            ),
                        )
                        effective_config_path.write_text(
                            yaml.safe_dump(auto_config, sort_keys=False, allow_unicode=True),
                            encoding="utf-8",
                        )
                    loaded_config = load_config(effective_config_path)
                    build_config = _config_for_output_directory(loaded_config, release_path)
                    customer_key_config = build_config
                    payload_file = build_config.protection.package_file
                    public_key_id = build_config.server.public_key_id
                    product_root = build_python_folder_envelope(
                        project_root=project_root,
                        output_root=release_path,
                        config=build_config,
                        signing_key=signing_key,
                        package_key=package_key,
                    )
            elif config_path.suffix.lower() == ".sprjx":
                signing_key = _unsafe_dev_signing_key()
                customer_key_config = config_for_python_folder_sprjx(config_path)
                product_root = build_python_folder_envelope(
                    sprjx_path=config_path,
                    output_root=release_path,
                    signing_key=signing_key,
                    package_key=package_key,
                )
            else:
                loaded_config = load_config(config_path)
                build_config = _config_for_output_directory(loaded_config, release_path)
                customer_key_config = build_config
                payload_file = build_config.protection.package_file
                public_key_id = build_config.server.public_key_id
                signing_key, unsafe_signing = _build_signing_key(loaded_config, config_path.parent)
                if build_config.python.enabled:
                    product_root = build_python_folder_envelope(
                        project_root=project_root,
                        output_root=release_path,
                        config=build_config,
                        signing_key=signing_key,
                        package_key=package_key,
                    )
                elif build_config.jar.entries or build_config.exe.entries:
                    product_root = build_single_file_envelope(
                        project_root=project_root,
                        output_root=release_path,
                        config=build_config,
                        signing_key=signing_key,
                        package_key=package_key,
                    )
                else:
                    product_root = build_release(
                        project_root=project_root,
                        output_root=_output_root_for(release_path),
                        config=build_config,
                        signing_key=signing_key,
                        package_key=package_key,
                    )
            _write_runtime_public_key(product_root, public_key_id, signing_key)
            payload_info = _read_payload_info(_payload_path(product_root, payload_file))
            if customer_key_config is None:
                return OperationResult.fail(
                    "Build config is missing",
                    code="build_failed",
                    detail={"release_path": str(release_path)},
                )
            customer_key_path = write_customer_key_file(
                product_root=product_root,
                payload_info=payload_info,
                config=customer_key_config,
                signing_key=signing_key,
                package_key=package_key,
            )
            if emit_admin_key_record:
                if admin_wrap_key is None:
                    return OperationResult.fail(
                        "Admin wrap key file is required",
                        code="admin_wrap_key_missing",
                        detail={"release_path": str(release_path)},
                    )
                _write_admin_key_record(product_root, payload_info, package_key, admin_wrap_key)
        except (ValidationError, yaml.YAMLError) as exc:
            return OperationResult.fail(
                f"Config is invalid: {exc}",
                code="config_invalid",
                detail={"path": str(config_path)},
            )
        except (OSError, ValueError, JSONDecodeError, binascii.Error) as exc:
            return OperationResult.fail(
                f"Build failed: {exc}",
                code="build_failed",
                detail={
                    "project_root": str(project_root),
                    "config_path": str(config_path) if config_path is not None else "",
                    "release_path": str(release_path),
                },
            )

        try:
            runtime_report = inspect_runtime_targets(product_root)
        except (OSError, ValueError, TypeError, JSONDecodeError) as exc:
            return OperationResult.fail(
                f"Runtime target inspection failed: {exc}",
                code="runtime_target_inspection_failed",
                detail={"product_root": str(product_root)},
            )

        detail: dict[str, object] = {
            "product_root": str(product_root),
            "product_id": payload_info["product_id"],
            "package_id": payload_info["package_id"],
            "unsafe_signing": unsafe_signing,
            "customer_key": str(customer_key_path),
            "runtime_targets": runtime_report.as_detail(),
        }
        if effective_config_path is not None:
            detail["config_path"] = str(effective_config_path)
        if emit_admin_key_record:
            detail["admin_key_record"] = "written"
        if require_cross_platform_runtime and not runtime_report.windows_linux_ready:
            return OperationResult.fail(
                "Release built, but Windows + Linux runtime is incomplete: "
                f"{runtime_report.summary()}",
                code="runtime_targets_missing",
                detail=detail,
            )
        return OperationResult.ok(f"Release built; {runtime_report.summary()}", detail=detail)

    @staticmethod
    def verify_runtime(product_root: Path) -> OperationResult:
        secure_root = product_root / ".secure"
        manifest_path = secure_root / "runtime.manifest"
        signature_path = secure_root / "runtime.manifest.sig"
        public_key_path = secure_root / RUNTIME_PUBLIC_KEY_SIDECAR

        if not manifest_path.is_file():
            return OperationResult.fail(
                f"Runtime manifest is missing: {manifest_path}",
                code="runtime_manifest_missing",
                detail={"path": str(manifest_path)},
            )
        if not signature_path.is_file():
            return OperationResult.fail(
                f"Runtime manifest signature is missing: {signature_path}",
                code="runtime_signature_missing",
                detail={"path": str(signature_path)},
            )
        if not public_key_path.is_file():
            return OperationResult.fail(
                f"Runtime public key is missing: {public_key_path}",
                code="runtime_public_key_missing",
                detail={"path": str(public_key_path)},
            )

        try:
            manifest = _read_runtime_manifest(manifest_path)
            signature = _read_b64_file(signature_path)
            public_key = _read_runtime_public_key(public_key_path)
            public_key.verify(signature, canonical_json_bytes(manifest))
            _verify_runtime_file_hashes(product_root.resolve(strict=False), manifest)
        except (
            OSError,
            ValueError,
            TypeError,
            JSONDecodeError,
            binascii.Error,
            InvalidSignature,
        ) as exc:
            return OperationResult.fail(
                f"Runtime manifest is invalid: {exc}",
                code="runtime_manifest_invalid",
                detail={"product_root": str(product_root)},
            )

        return OperationResult.ok(
            "Runtime manifest verified",
            detail={"product_root": str(product_root)},
        )

    @staticmethod
    def activate_online(
        *,
        product_root: Path,
        license_code: str,
        server_url: str,
        device_hash: str | None,
    ) -> OperationResult:
        try:
            activate_online(
                product_root=product_root,
                license_code=license_code,
                server_url=server_url,
                device_hash=device_hash,
            )
        except (OSError, ValueError, ActivationClientError) as exc:
            return OperationResult.fail(
                f"Activation failed: {exc}",
                code="activation_failed",
                detail={"product_root": str(product_root)},
            )
        return OperationResult.ok("Activation written", detail={"product_root": str(product_root)})

    @staticmethod
    def create_offline_request(
        *,
        product_root: Path,
        out: Path,
        device_hash: str | None,
    ) -> OperationResult:
        try:
            create_offline_request(product_root=product_root, out=out, device_hash=device_hash)
        except (OSError, ValueError, ActivationClientError) as exc:
            return OperationResult.fail(
                f"Offline request failed: {exc}",
                code="offline_request_failed",
                detail={"product_root": str(product_root), "path": str(out)},
            )
        return OperationResult.ok("Offline request written", detail={"path": str(out)})

    @staticmethod
    def import_offline_response(*, product_root: Path, response: Path) -> OperationResult:
        try:
            import_offline_response(product_root=product_root, response=response)
        except (OSError, ValueError, ActivationClientError) as exc:
            return OperationResult.fail(
                f"Offline response failed: {exc}",
                code="offline_response_failed",
                detail={"product_root": str(product_root), "response": str(response)},
            )
        return OperationResult.ok("Offline response imported", detail={"response": str(response)})


def _relative_matches(project_root: Path, pattern: str) -> list[str]:
    return sorted(
        path.relative_to(project_root).as_posix()
        for path in _iter_scannable_files(project_root)
        if path.match(pattern)
    )


def _first_python_entry(project_root: Path) -> str:
    entries = _relative_matches(project_root, "*.py")
    for preferred in ("model_server.py", "main.py", "app.py", "server.py"):
        if preferred in entries:
            return preferred
    for entry in entries:
        if entry.endswith("/model_server.py"):
            return entry
    return entries[0] if entries else ""


def _safe_product_id(raw_name: str) -> str:
    normalized = "".join(
        character if character.isalnum() or character in "._-" else "-"
        for character in raw_name.strip()
    ).strip("-._")
    return normalized or "product"


def _iter_scannable_files(project_root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(project_root, onerror=lambda _: None):
        dirnames[:] = [name for name in dirnames if name not in SCAN_EXCLUDED_DIRS]
        root = Path(dirpath)
        files.extend(
            root / filename
            for filename in filenames
            if (root / filename).is_file()
        )
    return files


def _read_runtime_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("runtime manifest must be an object")
    return manifest


def _read_b64_file(path: Path) -> bytes:
    value = "".join(path.read_text(encoding="ascii").split())
    return base64.urlsafe_b64decode(_b64_padded(value))


def _read_runtime_public_key(path: Path) -> Ed25519PublicKey:
    sidecar = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(sidecar, dict):
        raise ValueError("runtime public key must be an object")
    if sidecar.get("alg") != "Ed25519":
        raise ValueError("runtime public key algorithm must be Ed25519")
    public_key_b64 = sidecar.get("public_key")
    if not isinstance(public_key_b64, str):
        raise ValueError("runtime public key is missing public_key")
    public_key = base64.urlsafe_b64decode(_b64_padded(public_key_b64))
    if len(public_key) != 32:
        raise ValueError("runtime public key must decode to 32 bytes")
    return Ed25519PublicKey.from_public_bytes(public_key)


def _verify_runtime_file_hashes(product_root: Path, manifest: dict[str, Any]) -> None:
    files = manifest.get("files", [])
    if not isinstance(files, list):
        raise ValueError("runtime manifest files must be a list")

    for runtime_file in files:
        if not isinstance(runtime_file, dict):
            raise ValueError("runtime manifest file entry must be an object")
        relative_path = runtime_file.get("path")
        expected_hash = runtime_file.get("sha256")
        if not isinstance(relative_path, str) or not isinstance(expected_hash, str):
            raise ValueError("runtime manifest file entry is missing path or sha256")

        file_path = _validated_runtime_file_path(product_root, relative_path)
        actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(f"runtime file hash mismatch: {relative_path}")


def _validated_runtime_file_path(product_root: Path, relative_path: str) -> Path:
    windows_path = PureWindowsPath(relative_path)
    posix_path = PurePosixPath(relative_path.replace("\\", "/"))
    candidate_path = Path(relative_path)
    if (
        not relative_path
        or candidate_path.is_absolute()
        or candidate_path.drive
        or candidate_path.root
        or windows_path.is_absolute()
        or windows_path.drive
        or windows_path.root
        or posix_path.is_absolute()
        or ".." in candidate_path.parts
        or ".." in windows_path.parts
        or ".." in posix_path.parts
    ):
        raise ValueError(f"unsafe runtime file path: {relative_path}")

    resolved_path = (product_root / candidate_path).resolve(strict=False)
    if not resolved_path.is_relative_to(product_root):
        raise ValueError(f"unsafe runtime file path: {relative_path}")
    return resolved_path


def _b64_padded(value: str) -> bytes:
    return (value + "=" * (-len(value) % 4)).encode("ascii")
