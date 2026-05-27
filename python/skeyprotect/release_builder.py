"""Release directory builder for protected products."""

from __future__ import annotations

import os
import platform
import re
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skeyprotect.config import SKeyConfig
from skeyprotect.jar_loader import write_jar_loader
from skeyprotect.manifest import canonical_json_bytes
from skeyprotect.package_writer import write_payload
from skeyprotect.runtime_manifest import (
    RuntimeManifestFile,
    runtime_file_entry,
    write_runtime_manifest,
)
from skeyprotect.scanner import EntryPoint, scan_project
from skeyprotect.stubs import write_bootstrap, write_python_entry_stub
from skeyprotect.wrappers import write_exe_shell

RUNTIME_ROLE = "runtime_ffi"
PYTHON_BOOTSTRAP_ROLE = "python_bootstrap"
PYTHON_STUB_ROLE = "python_stub"
EXE_SHELL_ROLE = "exe_shell"
JNI_RUNTIME_ROLE = "jni_runtime"
JAR_LOADER_ROLE = "jar_loader"
ONLINE_POLICY_ROLE = "online_policy"
PRODUCT_DIRECTORY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,127}")


def build_release(
    project_root: Path,
    output_root: Path,
    config: SKeyConfig,
    signing_key: Ed25519PrivateKey,
    package_key: bytes,
) -> Path:
    """Build the Task 5 protected release layout and return the product root."""
    source_root = project_root.resolve(strict=True)
    product_root = output_root.resolve(strict=False) / _delivery_directory_name(config)
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

    bootstrap_path = write_bootstrap(product_root)
    entry_runtime_files: list[RuntimeManifestFile] = [
        runtime_file_entry(bootstrap_path, "skey_bootstrap.py", PYTHON_BOOTSTRAP_ROLE),
    ]
    entry_runtime_files.append(_write_online_policy(secure_root, config))
    for entrypoint in sorted(scan_result.entrypoints.values(), key=lambda item: item.id):
        entry_runtime_files.extend(_write_entry(source_root, product_root, entrypoint, config))

    if any(entry.kind == "python" for entry in scan_result.entrypoints.values()):
        runtime_files = _copy_required_runtime(source_root, runtime_root)
    else:
        runtime_files = _copy_available_runtime(source_root, runtime_root)
    if any(entry.kind == "jar" for entry in scan_result.entrypoints.values()):
        runtime_files.extend(_copy_required_jni_runtime(source_root, runtime_root))
    runtime_files.extend(entry_runtime_files)
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


def _write_online_policy(secure_root: Path, config: SKeyConfig) -> RuntimeManifestFile:
    policy_path = secure_root / "online-policy.json"
    policy_path.write_bytes(
        canonical_json_bytes(
            {
                "server_url": config.server.activation_url.rstrip("/"),
                "timeout_ms": 1500,
            },
        ),
    )
    return runtime_file_entry(policy_path, ".secure/online-policy.json", ONLINE_POLICY_ROLE)


def _replace_output_directory(product_root: Path, source_root: Path) -> None:
    if _is_link_or_junction(product_root):
        raise ValueError("release output directory must not be a symlink or junction")

    resolved_product_root = product_root.resolve(strict=False)
    resolved_source_root = source_root.resolve(strict=True)
    if resolved_product_root == resolved_source_root or resolved_source_root.is_relative_to(
        resolved_product_root,
    ):
        raise ValueError("release output directory must not be the source project root")

    if product_root.exists():
        shutil.rmtree(product_root)
    product_root.mkdir(parents=True, exist_ok=True)


def _delivery_directory_name(config: SKeyConfig) -> str:
    name = config.product.name.strip()
    candidate_path = Path(name)
    if (
        not name
        or name in {".", ".."}
        or any(separator in name for separator in ("/", "\\"))
        or candidate_path.drive
        or candidate_path.root
        or len(candidate_path.parts) != 1
        or not PRODUCT_DIRECTORY_PATTERN.fullmatch(name)
        or name.rstrip(" .") != name
    ):
        raise ValueError("product name must be a safe directory name")
    return name


def _payload_output_path(product_root: Path, secure_root: Path, config: SKeyConfig) -> Path:
    configured_path = Path(config.protection.package_file)
    if configured_path.is_absolute() or ".." in configured_path.parts:
        raise ValueError("package_file must be relative to the release product root")

    if configured_path.name in {"", ".", "..", ".secure"}:
        raise ValueError("package_file must name a payload file")

    if configured_path.parts and configured_path.parts[0] == ".secure":
        output_path = product_root / configured_path
    else:
        output_path = secure_root / configured_path.name

    if not output_path.resolve(strict=False).is_relative_to(secure_root.resolve(strict=False)):
        raise ValueError("package_file must stay under the release .secure directory")
    return output_path


def _write_entry(
    source_root: Path,
    product_root: Path,
    entrypoint: EntryPoint,
    config: SKeyConfig,
) -> list[RuntimeManifestFile]:
    if entrypoint.kind == "python":
        stub_path = write_python_entry_stub(product_root, entrypoint)
        return [
            runtime_file_entry(
                stub_path,
                entrypoint.path,
                PYTHON_STUB_ROLE,
            ),
        ]
    if entrypoint.kind == "exe":
        exe_entry = next(
            item for item in config.exe.entries if Path(item.path).as_posix() == entrypoint.path
        )
        shell_binary = _find_exe_shell_binary(source_root)
        if shell_binary is None:
            raise FileNotFoundError("skey-exe-shell binary was not found; build it before release")
        output_path = write_exe_shell(product_root, exe_entry, shell_binary)
        return [
            runtime_file_entry(
                output_path,
                entrypoint.path,
                EXE_SHELL_ROLE,
            ),
        ]
    if entrypoint.kind == "jar":
        jar_entry = next(
            item for item in config.jar.entries if Path(item.path).as_posix() == entrypoint.path
        )
        loader_jar = _find_jar_loader_jar(source_root)
        if loader_jar is None:
            raise FileNotFoundError("skey-loader JAR was not found; build it before release")
        output_path = write_jar_loader(product_root, jar_entry, loader_jar)
        return [
            runtime_file_entry(
                output_path,
                entrypoint.path,
                JAR_LOADER_ROLE,
            ),
        ]
    return []


def _copy_available_runtime(source_root: Path, runtime_root: Path) -> list[RuntimeManifestFile]:
    source_runtime = _find_runtime_binary(source_root)
    if source_runtime is None:
        return []

    return _copy_runtime(source_runtime, runtime_root)


def _copy_required_runtime(source_root: Path, runtime_root: Path) -> list[RuntimeManifestFile]:
    source_runtime = _find_runtime_binary(source_root)
    if source_runtime is None:
        raise FileNotFoundError("SKey runtime library was not found; build it before release")

    return _copy_runtime(source_runtime, runtime_root)


def _copy_runtime(source_runtime: Path, runtime_root: Path) -> list[RuntimeManifestFile]:
    delivery_name = _delivery_runtime_name()
    delivery_path = runtime_root / delivery_name
    shutil.copy2(source_runtime, delivery_path)
    return [
        runtime_file_entry(
            delivery_path,
            f".secure/rt/{delivery_name}",
            RUNTIME_ROLE,
        ),
    ]


def _copy_required_jni_runtime(source_root: Path, runtime_root: Path) -> list[RuntimeManifestFile]:
    source_runtime = _find_jni_runtime_binary(source_root)
    if source_runtime is None:
        raise FileNotFoundError("skey-jni runtime library was not found; build it before release")

    delivery_name = _delivery_jni_runtime_name()
    delivery_path = runtime_root / delivery_name
    shutil.copy2(source_runtime, delivery_path)
    return [
        runtime_file_entry(
            delivery_path,
            f".secure/rt/{delivery_name}",
            JNI_RUNTIME_ROLE,
        ),
    ]


def _find_runtime_binary(source_root: Path) -> Path | None:
    for root in _tool_artifact_roots(source_root):
        for target_dir in _rust_artifact_dirs(root, "release"):
            for candidate in _runtime_source_candidates():
                runtime_path = target_dir / candidate
                if runtime_path.exists():
                    return runtime_path.resolve(strict=True)
    return None


def _find_exe_shell_binary(source_root: Path, *, allow_debug: bool | None = None) -> Path | None:
    for root in _tool_artifact_roots(source_root):
        for release_dir in _rust_artifact_dirs(root, "release"):
            for candidate in _exe_shell_source_candidates():
                shell_path = release_dir / candidate
                if shell_path.exists():
                    return shell_path.resolve(strict=True)

    if allow_debug is None:
        allow_debug = _debug_exe_shell_allowed()
    if allow_debug:
        for root in _tool_artifact_roots(source_root):
            for debug_dir in _rust_artifact_dirs(root, "debug"):
                for candidate in _exe_shell_source_candidates():
                    shell_path = debug_dir / candidate
                    if shell_path.exists():
                        return shell_path.resolve(strict=True)
    return None


def _find_jar_loader_jar(source_root: Path) -> Path | None:
    for root in _tool_artifact_roots(source_root):
        for candidate in _jar_loader_candidates(root):
            if candidate.exists():
                return candidate.resolve(strict=True)
    return None


def _find_jni_runtime_binary(source_root: Path, *, allow_debug: bool | None = None) -> Path | None:
    for root in _tool_artifact_roots(source_root):
        for release_dir in _rust_artifact_dirs(root, "release"):
            for candidate in _jni_runtime_source_candidates():
                runtime_path = release_dir / candidate
                if runtime_path.exists():
                    return runtime_path.resolve(strict=True)

    if allow_debug is None:
        allow_debug = _debug_jni_runtime_allowed()
    if allow_debug:
        for root in _tool_artifact_roots(source_root):
            for debug_dir in _rust_artifact_dirs(root, "debug"):
                for candidate in _jni_runtime_source_candidates():
                    runtime_path = debug_dir / candidate
                    if runtime_path.exists():
                        return runtime_path.resolve(strict=True)
    return None


def _tool_artifact_roots(source_root: Path) -> list[Path]:
    roots: list[Path] = []
    env_root = os.environ.get("SKEY_TOOL_ARTIFACT_ROOT")
    if env_root:
        roots.append(Path(env_root))

    for candidate in (
        _find_repo_root(source_root),
        _find_repo_root(Path.cwd()),
        Path(__file__).resolve().parents[2],
    ):
        if candidate is not None:
            roots.append(candidate)

    unique_roots: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        resolved = root.resolve(strict=False)
        key = os.path.normcase(str(resolved))
        if key not in seen:
            unique_roots.append(resolved)
            seen.add(key)
    return unique_roots


def _rust_artifact_dirs(root: Path, profile: str) -> tuple[Path, ...]:
    return (
        root / "rust" / "target" / profile,
        root / "target" / profile,
        root,
    )


def _jar_loader_candidates(root: Path) -> tuple[Path, ...]:
    return (
        root / "java" / "skey-loader" / "build" / "libs" / "skey-loader.jar",
        root / "skey-loader.jar",
    )


def _debug_exe_shell_allowed() -> bool:
    return os.environ.get("SKEY_ALLOW_DEBUG_EXE_SHELL", "").lower() in {"1", "true", "yes"}


def _debug_jni_runtime_allowed() -> bool:
    return os.environ.get("SKEY_ALLOW_DEBUG_JNI_RUNTIME", "").lower() in {"1", "true", "yes"}


def _find_repo_root(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "rust" / "Cargo.toml").is_file():
            return candidate
    return None


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (is_junction is not None and is_junction())


def _runtime_source_candidates() -> tuple[str, ...]:
    system = platform.system()
    if system == "Windows":
        return ("skey_rt.dll", "skey_ffi.dll")
    if system == "Darwin":
        return ("libskey_rt.dylib", "libskey_ffi.dylib")
    return ("libskey_rt.so", "libskey_ffi.so")


def _exe_shell_source_candidates() -> tuple[str, ...]:
    if platform.system() == "Windows":
        return ("skey-exe-shell.exe",)
    return ("skey-exe-shell",)


def _jni_runtime_source_candidates() -> tuple[str, ...]:
    system = platform.system()
    if system == "Windows":
        return ("skey_jni.dll",)
    if system == "Darwin":
        return ("libskey_jni.dylib",)
    return ("libskey_jni.so",)


def _delivery_runtime_name() -> str:
    system = platform.system()
    if system == "Windows":
        return "skey_rt.dll"
    if system == "Darwin":
        return "libskey_rt.dylib"
    return "libskey_rt.so"


def _delivery_jni_runtime_name() -> str:
    system = platform.system()
    if system == "Windows":
        return "skey_jni.dll"
    if system == "Darwin":
        return "libskey_jni.dylib"
    return "libskey_jni.so"


def _write_run_env_scripts(product_root: Path) -> None:
    (product_root / "run_env.bat").write_text(
        "\n".join(
            [
                "@echo off",
                "set \"SKEY_HOME=%~dp0\"",
                "set \"PATH=%SKEY_HOME%.secure\\rt;%PATH%\"",
                "set \"PYTHONPATH=%SKEY_HOME%;%PYTHONPATH%\"",
                "",
            ],
        ),
        encoding="utf-8",
    )
    run_env_sh = product_root / "run_env.sh"
    run_env_sh.write_text(
        "\n".join(
            [
                "#!/usr/bin/env sh",
                "SKEY_HOME=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)",
                "export PATH=\"$SKEY_HOME/.secure/rt:$PATH\"",
                "export PYTHONPATH=\"$SKEY_HOME${PYTHONPATH:+:$PYTHONPATH}\"",
                "export LD_LIBRARY_PATH=\"$SKEY_HOME/.secure/rt${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\"",
                "export DYLD_LIBRARY_PATH=\"$SKEY_HOME/.secure/rt${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}\"",
                "",
            ],
        ),
        encoding="utf-8",
    )
    try:
        run_env_sh.chmod(0o755)
    except OSError:
        pass
