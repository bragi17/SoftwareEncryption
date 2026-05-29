"""Command-line interface for the protector build workflow."""

from __future__ import annotations

import base64
import binascii
import json
from importlib import resources
from hashlib import sha256
from json import JSONDecodeError
from pathlib import Path, PurePosixPath, PureWindowsPath
from secrets import token_bytes
from typing import Annotated, Any, NoReturn

import typer
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from skeyprotect.activation_client import (
    ActivationClientError,
    activate_online,
    create_offline_request,
    import_offline_response,
)
from skeyprotect.config import SKeyConfig, load_config
from skeyprotect.customer_key import write_customer_key_file
from skeyprotect.envelope_builder import (
    DEFAULT_PUBLIC_KEY_ID,
    build_python_folder_envelope,
    build_single_file_envelope,
    config_for_python_folder_sprjx,
    config_for_single_artifact,
    write_python_folder_sprjx,
)
from skeyprotect.manifest import canonical_json_bytes
from skeyprotect.package_writer import HEADER_STRUCT, HEADER_VERSION, MAGIC, read_payload_header
from skeyprotect.release_builder import build_release
from skeyprotect.runtime_targets import RuntimeTargetReport, inspect_runtime_targets

app = typer.Typer(no_args_is_help=True)
activate_app = typer.Typer(no_args_is_help=True)
offline_app = typer.Typer(no_args_is_help=True)
app.add_typer(activate_app, name="activate")
activate_app.add_typer(offline_app, name="offline")

PUBLIC_KEY_SIDECAR = "runtime.manifest.public-key.json"
ADMIN_KEY_RECORD = "package-key.admin.json"
UNSAFE_DEV_SIGNING_SEED = bytes(range(32, 64))


@app.command("init-config")
def init_config(
    path: Annotated[Path, typer.Option("--path", help="Path to write the config template.")] = Path(
        "skey.yaml",
    ),
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write a starter skey.yaml configuration."""
    if path.exists() and not force:
        raise typer.BadParameter(f"config already exists: {path}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_config_template_text(), encoding="utf-8")
    typer.echo(f"wrote {path}")


@app.command("init-sprjx")
def init_sprjx(
    input_root: Annotated[Path, typer.Option("--input-root", help="Python folder to protect.")],
    out: Annotated[Path, typer.Option("--out", help="Mirrored protected output folder.")],
    path: Annotated[Path, typer.Option("--path", help="Path to write the .sprjx file.")],
    include: Annotated[
        list[str] | None,
        typer.Option("--include", help="Python glob to protect; repeat for multiple globs."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Glob to exclude; repeat for multiple globs."),
    ] = None,
    feature_id: Annotated[int, typer.Option("--feature-id", help="Sentinel feature id value.")] = 3,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing file.")] = False,
) -> None:
    """Write a Sentinel-style .sprjx file for a Python folder."""
    if path.exists() and not force:
        raise typer.BadParameter(f"sprjx config already exists: {path}")
    if not input_root.is_dir():
        _fail(f"input root is not a folder: {input_root}")

    written_path = write_python_folder_sprjx(
        input_root=input_root.resolve(strict=True),
        output_root=out.resolve(strict=False),
        sprjx_path=path,
        protected_globs=include or ["**/*.py"],
        ignored_globs=exclude or [],
        feature_id=feature_id,
    )
    typer.echo(f"wrote {written_path}")


@app.command()
def build(
    config: Annotated[Path, typer.Option("--config", help="Path to skey.yaml.")],
    project: Annotated[Path, typer.Option("--project", help="Project root to protect.")],
    out: Annotated[Path, typer.Option("--out", help="Release product directory path.")],
    emit_admin_key_record: Annotated[
        bool,
        typer.Option(
            "--emit-admin-key-record",
            help="Opt-in encrypted admin package key record; requires --admin-wrap-key-file.",
        ),
    ] = False,
    admin_wrap_key_file: Annotated[
        Path | None,
        typer.Option(
            "--admin-wrap-key-file",
            help=(
                "Base64/base64url 32-byte admin wrapping key for encrypted admin package "
                "key records; do not ship wrapping key."
            ),
        ),
    ] = None,
    require_windows_linux_runtime: Annotated[
        bool,
        typer.Option(
            "--require-windows-linux-runtime",
            help="Fail the command if the release lacks either Windows DLLs or Linux SO files.",
        ),
    ] = False,
) -> None:
    """Build a protected release directory."""
    if emit_admin_key_record and admin_wrap_key_file is None:
        _fail("--admin-wrap-key-file is required when --emit-admin-key-record is passed")

    admin_wrap_key = _admin_wrap_key_or_none(
        emit_admin_key_record=emit_admin_key_record,
        admin_wrap_key_file=admin_wrap_key_file,
    )

    if config.suffix.lower() == ".sprjx":
        package_key = token_bytes(32)
        signing_key = _unsafe_dev_signing_key()
        typer.echo(
            "WARNING: using unsafe dev/test-only build signing key; do not ship this release",
            err=True,
        )
        try:
            product_root = build_python_folder_envelope(
                sprjx_path=config,
                output_root=out,
                signing_key=signing_key,
                package_key=package_key,
            )
            _write_runtime_public_key(product_root, DEFAULT_PUBLIC_KEY_ID, signing_key)
            payload_info = _read_payload_info(product_root / ".secure" / "payload.skp")
            sprjx_build_config = config_for_python_folder_sprjx(config)
            customer_key_path = write_customer_key_file(
                product_root=product_root,
                payload_info=payload_info,
                config=sprjx_build_config,
                signing_key=signing_key,
                package_key=package_key,
            )
        except (OSError, ValueError, JSONDecodeError) as exc:
            _fail(f"build failed: {exc}")
        _maybe_write_admin_record(
            emit_admin_key_record=emit_admin_key_record,
            admin_wrap_key=admin_wrap_key,
            product_root=product_root,
            payload_info=payload_info,
            package_key=package_key,
        )
        runtime_report = _runtime_target_report_or_fail(
            product_root,
            require_windows_linux_runtime,
        )
        _echo_build_output(
            product_root=product_root,
            payload_info=payload_info,
            admin_record_written=emit_admin_key_record,
            customer_key_path=customer_key_path,
            runtime_report=runtime_report,
        )
        return

    try:
        loaded_config = load_config(config)
    except (OSError, ValueError, ValidationError) as exc:
        _fail(f"failed to load config: {exc}")

    build_config = _config_for_output_directory(loaded_config, out)
    package_key = token_bytes(32)
    try:
        signing_key, unsafe_signing = _build_signing_key(loaded_config, config.parent)
    except (OSError, ValueError, binascii.Error) as exc:
        _fail(f"failed to load build signing key: {exc}")
    if unsafe_signing:
        typer.echo(
            "WARNING: using unsafe dev/test-only build signing key; do not ship this release",
            err=True,
        )
    try:
        if build_config.python.enabled:
            product_root = build_python_folder_envelope(
                project_root=project,
                output_root=out,
                config=build_config,
                signing_key=signing_key,
                package_key=package_key,
            )
        elif build_config.jar.entries or build_config.exe.entries:
            product_root = build_single_file_envelope(
                project_root=project,
                output_root=out,
                config=build_config,
                signing_key=signing_key,
                package_key=package_key,
            )
        else:
            product_root = build_release(
                project_root=project,
                output_root=_output_root_for(out),
                config=build_config,
                signing_key=signing_key,
                package_key=package_key,
            )
    except (OSError, ValueError) as exc:
        _fail(f"build failed: {exc}")

    _write_runtime_public_key(product_root, build_config.server.public_key_id, signing_key)

    payload_path = _payload_path(product_root, build_config.protection.package_file)
    try:
        payload_info = _read_payload_info(payload_path)
    except (OSError, ValueError, JSONDecodeError) as exc:
        _fail(f"failed to inspect built payload: {exc}")

    _maybe_write_admin_record(
        emit_admin_key_record=emit_admin_key_record,
        admin_wrap_key=admin_wrap_key,
        product_root=product_root,
        payload_info=payload_info,
        package_key=package_key,
    )
    try:
        customer_key_path = write_customer_key_file(
            product_root=product_root,
            payload_info=payload_info,
            config=build_config,
            signing_key=signing_key,
            package_key=package_key,
        )
    except (OSError, ValueError) as exc:
        _fail(f"failed to write customer key: {exc}")
    runtime_report = _runtime_target_report_or_fail(product_root, require_windows_linux_runtime)
    _echo_build_output(
        product_root=product_root,
        payload_info=payload_info,
        admin_record_written=emit_admin_key_record,
        customer_key_path=customer_key_path,
        runtime_report=runtime_report,
    )


@app.command("wrap-file")
def wrap_file(
    input_file: Annotated[Path, typer.Option("--input", help="Single JAR or EXE to protect.")],
    out: Annotated[Path, typer.Option("--out", help="Output folder for the protected shell.")],
    require_windows_linux_runtime: Annotated[
        bool,
        typer.Option(
            "--require-windows-linux-runtime",
            help="Fail the command if the release lacks either Windows DLLs or Linux SO files.",
        ),
    ] = False,
) -> None:
    """Build a same-name shell for a single compiled artifact."""
    if not input_file.is_file():
        _fail(f"input file does not exist: {input_file}")
    package_key = token_bytes(32)
    signing_key = _unsafe_dev_signing_key()
    try:
        build_config = config_for_single_artifact(input_file, out)
        product_root = build_single_file_envelope(
            project_root=input_file.parent,
            output_root=out,
            config=build_config,
            signing_key=signing_key,
            package_key=package_key,
        )
        _write_runtime_public_key(product_root, build_config.server.public_key_id, signing_key)
        payload_info = _read_payload_info(
            _payload_path(product_root, build_config.protection.package_file),
        )
        customer_key_path = write_customer_key_file(
            product_root=product_root,
            payload_info=payload_info,
            config=build_config,
            signing_key=signing_key,
            package_key=package_key,
        )
    except (OSError, ValueError, JSONDecodeError) as exc:
        _fail(f"build failed: {exc}")
    runtime_report = _runtime_target_report_or_fail(product_root, require_windows_linux_runtime)
    typer.echo(
        json.dumps(
            {
                "product_root": str(product_root),
                "product_id": payload_info["product_id"],
                "package_id": payload_info["package_id"],
                "customer_key": str(customer_key_path),
                "runtime_targets": runtime_report.as_detail(),
            },
            sort_keys=True,
        ),
    )


@app.command()
def inspect(
    payload: Annotated[Path, typer.Argument(help="Path to payload.skp.")],
) -> None:
    """Inspect a protected payload header and manifest."""
    if not payload.is_file():
        _fail(f"payload does not exist: {payload}")
    try:
        typer.echo(json.dumps(_read_payload_info(payload), sort_keys=True))
    except (OSError, ValueError, JSONDecodeError) as exc:
        _fail(f"failed to inspect payload: {exc}")


@app.command("verify-runtime")
def verify_runtime(
    product: Annotated[Path, typer.Argument(help="Release product directory.")],
) -> None:
    """Verify a release runtime manifest signature and file hashes."""
    if not product.is_dir():
        _fail(f"product directory does not exist: {product}")
    product_root = product.resolve(strict=True)
    secure_root = product / ".secure"
    manifest_path = secure_root / "runtime.manifest"
    signature_path = secure_root / "runtime.manifest.sig"
    public_key_path = secure_root / PUBLIC_KEY_SIDECAR

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _fail(f"runtime manifest is missing: {manifest_path}")
    except (OSError, JSONDecodeError) as exc:
        _fail(f"runtime manifest is malformed: {exc}")
    if not isinstance(manifest, dict):
        _fail("runtime manifest is malformed: expected object")

    try:
        signature = base64.urlsafe_b64decode(signature_path.read_text(encoding="ascii"))
    except FileNotFoundError:
        _fail(f"runtime manifest signature is missing: {signature_path}")
    except (OSError, binascii.Error, ValueError) as exc:
        _fail(f"runtime manifest signature is malformed: {exc}")

    public_key = _read_runtime_public_key(public_key_path)
    try:
        public_key.verify(signature, canonical_json_bytes(manifest))
    except InvalidSignature:
        _fail("runtime manifest signature is invalid")

    files = manifest.get("files", [])
    if not isinstance(files, list):
        _fail("runtime manifest files must be a list")
    for runtime_file in files:
        if (
            not isinstance(runtime_file, dict)
            or not isinstance(runtime_file.get("path"), str)
            or not isinstance(runtime_file.get("sha256"), str)
        ):
            _fail("runtime manifest file entry is malformed")
        relative_path = runtime_file["path"]
        file_path = _validated_runtime_file_path(product_root, relative_path)
        try:
            actual_hash = sha256(file_path.read_bytes()).hexdigest()
        except OSError as exc:
            _fail(f"runtime file cannot be read: {relative_path}: {exc}")
        expected_hash = runtime_file["sha256"]
        if actual_hash != expected_hash:
            _fail(f"runtime file hash mismatch: {relative_path}")

    typer.echo("runtime manifest verified")


@activate_app.command("online")
def activate_online_command(
    product_root: Annotated[Path, typer.Option("--product-root", help="Release product root.")],
    license_code: Annotated[str, typer.Option("--license-code", help="License code to activate.")],
    server_url: Annotated[str, typer.Option("--server-url", help="Activation server /v1 URL.")],
    device_hash: Annotated[
        str | None,
        typer.Option("--device-hash", help="Override auto-detected device hash."),
    ] = None,
) -> None:
    """Activate a release against the online license server."""
    try:
        activate_online(
            product_root=product_root,
            license_code=license_code,
            server_url=server_url,
            device_hash=device_hash,
        )
    except (OSError, ValueError, ActivationClientError) as exc:
        _fail(f"activation failed: {exc}")
    typer.echo("activation written")


@offline_app.command("request")
def activate_offline_request_command(
    product_root: Annotated[Path, typer.Option("--product-root", help="Release product root.")],
    out: Annotated[Path, typer.Option("--out", help="Path to write the offline request JSON.")],
    device_hash: Annotated[
        str | None,
        typer.Option("--device-hash", help="Override auto-detected device hash."),
    ] = None,
    server_url: Annotated[
        str | None,
        typer.Option("--server-url", help="Deprecated compatibility option; offline request is local."),
    ] = None,
) -> None:
    """Create a signed offline activation request and pending client key."""
    try:
        create_offline_request(
            product_root=product_root,
            out=out,
            device_hash=device_hash,
            server_url=server_url,
        )
    except (OSError, ValueError, ActivationClientError) as exc:
        _fail(f"offline request failed: {exc}")
    typer.echo(f"offline request written: {out}")


@offline_app.command("import")
def activate_offline_import_command(
    product_root: Annotated[Path, typer.Option("--product-root", help="Release product root.")],
    response: Annotated[Path, typer.Option("--response", help="Offline response JSON from server.")],
) -> None:
    """Import an offline activation response into a release."""
    try:
        import_offline_response(product_root=product_root, response=response)
    except (OSError, ValueError, ActivationClientError) as exc:
        _fail(f"offline import failed: {exc}")
    typer.echo("activation written")


def _admin_wrap_key_or_none(
    *,
    emit_admin_key_record: bool,
    admin_wrap_key_file: Path | None,
) -> bytes | None:
    if not emit_admin_key_record:
        return None
    if admin_wrap_key_file is None:
        _fail("--admin-wrap-key-file is required when --emit-admin-key-record is passed")
    try:
        return _read_admin_wrap_key(admin_wrap_key_file)
    except (OSError, ValueError, binascii.Error) as exc:
        _fail(f"failed to load admin wrapping key: {exc}")


def _maybe_write_admin_record(
    *,
    emit_admin_key_record: bool,
    admin_wrap_key: bytes | None,
    product_root: Path,
    payload_info: dict[str, Any],
    package_key: bytes,
) -> None:
    if not emit_admin_key_record:
        return
    if admin_wrap_key is None:
        _fail("--admin-wrap-key-file is required when --emit-admin-key-record is passed")
    _write_admin_key_record(product_root, payload_info, package_key, admin_wrap_key)


def _echo_build_output(
    *,
    product_root: Path,
    payload_info: dict[str, Any],
    admin_record_written: bool,
    customer_key_path: Path | None = None,
    runtime_report: RuntimeTargetReport | None = None,
) -> None:
    build_output = {
        "product_root": str(product_root),
        "product_id": payload_info["product_id"],
        "package_id": payload_info["package_id"],
    }
    if customer_key_path is not None:
        build_output["customer_key"] = str(customer_key_path)
    if admin_record_written:
        build_output["admin_key_record"] = (
            "encrypted admin package key record written; do not ship wrapping key"
        )
    if runtime_report is not None:
        build_output["runtime_targets"] = runtime_report.as_detail()
    typer.echo(json.dumps(build_output, sort_keys=True))


def _runtime_target_report_or_fail(
    product_root: Path,
    require_windows_linux_runtime: bool,
) -> RuntimeTargetReport:
    try:
        report = inspect_runtime_targets(product_root)
    except (OSError, ValueError, TypeError, JSONDecodeError) as exc:
        _fail(f"runtime target inspection failed: {exc}")
    if require_windows_linux_runtime and not report.windows_linux_ready:
        _fail(f"Windows + Linux runtime is incomplete: {report.summary()}")
    return report


def _read_payload_info(payload_path: Path) -> dict[str, Any]:
    header = read_payload_header(payload_path)
    _validate_payload_header(header)
    with payload_path.open("rb") as payload_file:
        payload_file.seek(header.header_length)
        manifest = json.loads(payload_file.read(header.manifest_length))

    if not isinstance(manifest, dict):
        raise ValueError("payload manifest is malformed: expected object")
    product_id = manifest.get("product_id")
    package_id = manifest.get("package_id")
    if not isinstance(product_id, str):
        raise ValueError("payload manifest is malformed: product_id must be a string")
    if not isinstance(package_id, str):
        raise ValueError("payload manifest is malformed: package_id must be a string")

    return {
        "product_id": product_id,
        "package_id": package_id,
        "package_hash": sha256(payload_path.read_bytes()).hexdigest(),
        "manifest_hash": sha256(canonical_json_bytes(manifest)).hexdigest(),
    }


def _write_runtime_public_key(
    product_root: Path,
    key_id: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    public_key = signing_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    sidecar = {
        "kid": key_id,
        "alg": "Ed25519",
        "public_key": base64.urlsafe_b64encode(public_key).decode("ascii"),
    }
    (product_root / ".secure" / PUBLIC_KEY_SIDECAR).write_text(
        json.dumps(sidecar, sort_keys=True),
        encoding="utf-8",
    )


def _read_runtime_public_key(path: Path) -> Ed25519PublicKey:
    try:
        sidecar = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _fail(f"runtime public key is missing: {path}")
    except (OSError, JSONDecodeError) as exc:
        _fail(f"runtime public key is malformed: {exc}")
    if not isinstance(sidecar, dict):
        _fail("runtime public key is malformed: expected object")
    if sidecar.get("alg") != "Ed25519":
        _fail("runtime public key is malformed: unsupported algorithm")
    try:
        return Ed25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode(sidecar["public_key"]),
        )
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        _fail(f"runtime public key is malformed: {exc}")


def _build_signing_key(config: SKeyConfig, config_dir: Path) -> tuple[Ed25519PrivateKey, bool]:
    security = config.security
    private_key_b64 = security.build_signing_private_key_b64
    if security.build_signing_private_key_file is not None:
        key_path = Path(security.build_signing_private_key_file)
        if not key_path.is_absolute():
            key_path = config_dir / key_path
        private_key_b64 = "".join(key_path.read_text(encoding="ascii").split())

    if private_key_b64 is None:
        if security.vendor_public_key_b64 is not None and not security.allow_unsafe_dev_signing_key:
            raise ValueError(
                "build_signing_private_key_b64 or build_signing_private_key_file is required "
                "when vendor_public_key_b64 is configured",
            )
        if not security.allow_unsafe_dev_signing_key:
            raise ValueError(
                "build signing key is required; set security.allow_unsafe_dev_signing_key "
                "only for dev/test releases",
            )
        signing_key = _unsafe_dev_signing_key()
        if security.vendor_public_key_b64 is not None:
            expected_public = _decode_raw_key(security.vendor_public_key_b64, 32)
            actual_public = signing_key.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw,
            )
            if actual_public != expected_public:
                raise ValueError(
                    "vendor_public_key_b64 does not match the unsafe dev/test signing key; "
                    "provide the matching build signing private key instead",
                )
        return signing_key, True

    signing_key = Ed25519PrivateKey.from_private_bytes(_decode_raw_key(private_key_b64, 32))
    if security.vendor_public_key_b64 is not None:
        expected_public = _decode_raw_key(security.vendor_public_key_b64, 32)
        actual_public = signing_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        if actual_public != expected_public:
            raise ValueError("vendor_public_key_b64 does not match build signing private key")
    return signing_key, False


def _unsafe_dev_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(UNSAFE_DEV_SIGNING_SEED)


def _decode_raw_key(value: str, expected_length: int) -> bytes:
    decoded = base64.b64decode(
        _base64_padded("".join(value.split())),
        altchars=b"-_",
        validate=True,
    )
    if len(decoded) != expected_length:
        raise ValueError(f"key must decode to {expected_length} bytes")
    return decoded


def _write_admin_key_record(
    product_root: Path,
    payload_info: dict[str, Any],
    package_key: bytes,
    admin_wrap_key: bytes,
) -> None:
    aad = f"product_id={payload_info['product_id']}|package_id={payload_info['package_id']}"
    nonce = token_bytes(12)
    ciphertext = AESGCM(admin_wrap_key).encrypt(nonce, package_key, aad.encode("utf-8"))
    record = {
        "schema": "skey-package-key-admin-v1",
        "product_id": payload_info["product_id"],
        "package_id": payload_info["package_id"],
        "package_hash": payload_info["package_hash"],
        "package_key_sha256": sha256(package_key).hexdigest(),
        "wrapped_pkg_key": {
            "alg": "AES-256-GCM",
            "nonce": _base64url_no_pad(nonce),
            "aad": aad,
            "ciphertext": _base64url_no_pad(ciphertext),
        },
    }
    (product_root / ".secure" / ADMIN_KEY_RECORD).write_text(
        json.dumps(record, sort_keys=True),
        encoding="utf-8",
    )


def _validate_payload_header(header: Any) -> None:
    if header.magic != MAGIC:
        raise ValueError("payload header is invalid: magic must be SKP1")
    if header.header_version != HEADER_VERSION:
        raise ValueError("payload header is invalid: header_version must be 1")
    if header.header_length != HEADER_STRUCT.size:
        raise ValueError("payload header is invalid: header_length is unsupported")


def _read_admin_wrap_key(path: Path) -> bytes:
    encoded_key = "".join(path.read_text(encoding="ascii").split())
    decoded_key = base64.b64decode(
        _base64_padded(encoded_key),
        altchars=b"-_",
        validate=True,
    )
    if len(decoded_key) != 32:
        raise ValueError("admin wrapping key must decode to 32 bytes")
    return decoded_key


def _base64url_no_pad(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64_padded(value: str) -> bytes:
    return (value + "=" * (-len(value) % 4)).encode("ascii")


def _payload_path(product_root: Path, package_file: str) -> Path:
    configured_path = Path(package_file)
    if configured_path.parts and configured_path.parts[0] == ".secure":
        return product_root / configured_path
    return product_root / ".secure" / configured_path.name


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
        _fail(f"unsafe runtime file path: {relative_path}")

    resolved_path = (product_root / candidate_path).resolve(strict=False)
    if not resolved_path.is_relative_to(product_root):
        _fail(f"unsafe runtime file path: {relative_path}")
    return resolved_path


def _config_for_output_directory(config: SKeyConfig, out: Path) -> SKeyConfig:
    return config.model_copy(
        update={"product": config.product.model_copy(update={"name": out.name})},
    )


def _output_root_for(out: Path) -> Path:
    return out.parent if out.parent != Path("") else Path(".")


def _config_template_text() -> str:
    return (
        resources.files("skeyprotect")
        .joinpath("templates", "skey.example.yaml")
        .read_text(encoding="utf-8")
    )


def _fail(message: str) -> NoReturn:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(1)
