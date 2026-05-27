"""Client-side online and offline activation helpers."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import platform
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from json import JSONDecodeError
from pathlib import Path
from secrets import token_bytes
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from skeyprotect.manifest import canonical_json_bytes
from skeyprotect.package_writer import HEADER_STRUCT, HEADER_VERSION, MAGIC, read_payload_header


PUBLIC_KEY_SIDECAR = "runtime.manifest.public-key.json"
CLIENT_KEY_SCHEMA = "skey-client-key-v1"
CLIENT_KEY_PROTECTION = "platform-derived-hmac-sha256-xor-v2"
WINDOWS_CLIENT_KEY_PROTECTION = "windows-dpapi-v1"
STATE_SCHEMA = "skey-state-v1"


class ActivationClientError(ValueError):
    """Raised when activation input, server output, or local writes are invalid."""


def activate_online(
    *,
    product_root: Path,
    license_code: str,
    server_url: str,
    device_hash: str | None,
) -> None:
    context = _load_product_context(product_root)
    client_private = X25519PrivateKey.generate()
    client_public_b64 = _x25519_public_b64(client_private)
    response = _post_json(
        _endpoint(server_url, "activate"),
        {
            "license_code": license_code,
            "product_id": context["product_id"],
            "package_id": context["package_id"],
            "device_hash": device_hash or _device_hash(),
            "client_pub": client_public_b64,
        },
    )
    activation = _require_mapping(response.get("activation"), "activation response")
    cert = _require_mapping(activation.get("cert"), "activation certificate")
    _verify_activation_cert(cert, context)
    _write_activation_artifacts(
        product_root=product_root,
        context=context,
        cert=cert,
        client_private=client_private,
        server_time=None,
        client_key_bytes=_x25519_private_bytes(client_private),
        write_client_key=True,
    )


def create_offline_request(
    *,
    product_root: Path,
    out: Path,
    device_hash: str | None,
    server_url: str | None = None,
) -> None:
    del server_url
    context = _load_product_context(product_root)
    client_private = X25519PrivateKey.generate()
    offline_request = {
        "schema": "skey-offline-request-v1",
        "product_id": context["product_id"],
        "package_id": context["package_id"],
        "package_hash": context["package_hash"],
        "device_hash": device_hash or _device_hash(),
        "client_pub": _x25519_public_b64(client_private),
        "issued_at": _utcnow_text(),
    }
    license_dir = _license_dir(product_root)
    license_dir.mkdir(parents=True, exist_ok=True)
    _write_client_key(license_dir, client_private)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(canonical_json_bytes({"offline_request": offline_request}))


def import_offline_response(*, product_root: Path, response: Path) -> None:
    context = _load_product_context(product_root)
    try:
        response_payload = json.loads(response.read_text(encoding="utf-8"))
    except (OSError, JSONDecodeError) as exc:
        raise ActivationClientError(f"offline response is malformed: {exc}") from exc
    response_mapping = _require_mapping(response_payload, "offline response file")
    offline_response = _require_mapping(
        response_mapping.get("offline_response", response_mapping),
        "offline response",
    )
    _verify_signed_json(
        offline_response,
        context["public_key"],
        "offline response signature is invalid",
    )
    cert = _require_mapping(offline_response.get("activation_cert"), "activation certificate")
    _verify_activation_cert(cert, context)
    if not (_license_dir(product_root) / "client_key.dat").is_file():
        raise ActivationClientError("client_key.dat is missing; create an offline request first")
    server_time = offline_response.get("server_time")
    license_dir = _license_dir(product_root)
    _write_activation_artifacts(
        product_root=product_root,
        context=context,
        cert=cert,
        client_private=None,
        server_time=server_time if isinstance(server_time, str) else None,
        client_key_bytes=_read_client_key(license_dir),
        write_client_key=False,
    )


def _load_product_context(product_root: Path) -> dict[str, Any]:
    resolved_root = product_root.resolve(strict=True)
    secure_root = resolved_root / ".secure"
    payload_path = secure_root / "payload.skp"
    payload_info = _read_payload_info(payload_path)
    public_key = _read_runtime_public_key(secure_root / PUBLIC_KEY_SIDECAR)
    return {
        **payload_info,
        "product_root": resolved_root,
        "payload_path": payload_path,
        "public_key": public_key,
    }


def _read_payload_info(payload_path: Path) -> dict[str, str]:
    header = read_payload_header(payload_path)
    if header.magic != MAGIC or header.header_version != HEADER_VERSION:
        raise ActivationClientError("payload header is invalid")
    if header.header_length != HEADER_STRUCT.size:
        raise ActivationClientError("payload header is unsupported")
    try:
        with payload_path.open("rb") as payload_file:
            payload_file.seek(header.header_length)
            manifest = json.loads(payload_file.read(header.manifest_length))
    except (OSError, JSONDecodeError) as exc:
        raise ActivationClientError(f"payload manifest is malformed: {exc}") from exc
    manifest_mapping = _require_mapping(manifest, "payload manifest")
    product_id = manifest_mapping.get("product_id")
    package_id = manifest_mapping.get("package_id")
    if not isinstance(product_id, str) or not isinstance(package_id, str):
        raise ActivationClientError("payload manifest is missing product_id or package_id")
    return {
        "product_id": product_id,
        "package_id": package_id,
        "package_hash": f"sha256:{hashlib.sha256(payload_path.read_bytes()).hexdigest()}",
    }


def _read_runtime_public_key(path: Path) -> Ed25519PublicKey:
    try:
        sidecar = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, JSONDecodeError) as exc:
        raise ActivationClientError(f"runtime public key is malformed: {exc}") from exc
    sidecar_mapping = _require_mapping(sidecar, "runtime public key")
    if sidecar_mapping.get("alg") != "Ed25519":
        raise ActivationClientError("runtime public key uses an unsupported algorithm")
    public_key_b64 = sidecar_mapping.get("public_key")
    if not isinstance(public_key_b64, str):
        raise ActivationClientError("runtime public key is missing public_key")
    try:
        public_key_bytes = _b64url_decode(public_key_b64)
        if len(public_key_bytes) != 32:
            raise ValueError("wrong length")
        return Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except (ValueError, binascii.Error) as exc:
        raise ActivationClientError("runtime public key is malformed") from exc


def _verify_activation_cert(cert: dict[str, Any], context: dict[str, Any]) -> None:
    _verify_signed_json(
        cert,
        cast(Ed25519PublicKey, context["public_key"]),
        "activation certificate signature is invalid",
    )
    _require_equal(cert, "product_id", cast(str, context["product_id"]))
    _require_equal(cert, "package_id", cast(str, context["package_id"]))
    _require_equal(cert, "package_hash", cast(str, context["package_hash"]))
    for field_name in ("activation_id", "lease_until", "issued_at"):
        value = cert.get(field_name)
        if not isinstance(value, str) or not value:
            raise ActivationClientError(f"activation certificate is missing {field_name}")


def _write_activation_artifacts(
    *,
    product_root: Path,
    context: dict[str, Any],
    cert: dict[str, Any],
    client_private: X25519PrivateKey | None,
    server_time: str | None,
    client_key_bytes: bytes,
    write_client_key: bool,
) -> None:
    license_dir = _license_dir(product_root)
    license_dir.mkdir(parents=True, exist_ok=True)
    if write_client_key:
        if client_private is None:
            raise ActivationClientError("client private key is unavailable")
        _write_client_key(license_dir, client_private)
    (license_dir / "activation.cert").write_bytes(canonical_json_bytes(cert))
    _write_initial_state(
        license_dir=license_dir,
        cert=cert,
        client_key_bytes=client_key_bytes,
        server_time=server_time,
    )


def _write_client_key(license_dir: Path, client_private: X25519PrivateKey) -> None:
    private_bytes = _x25519_private_bytes(client_private)
    client_key_path = license_dir / "client_key.dat"
    client_key_path.write_bytes(_client_key_envelope(license_dir, private_bytes))
    if os.name != "nt":
        client_key_path.chmod(0o600)


def _x25519_private_bytes(client_private: X25519PrivateKey) -> bytes:
    return client_private.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )


def _read_client_key(license_dir: Path) -> bytes:
    try:
        envelope = _require_mapping(
            json.loads((license_dir / "client_key.dat").read_text(encoding="utf-8")),
            "client key envelope",
        )
    except (OSError, JSONDecodeError) as exc:
        raise ActivationClientError("client_key.dat is malformed") from exc
    if envelope.get("schema") != CLIENT_KEY_SCHEMA:
        raise ActivationClientError("client_key.dat schema is unsupported")
    if os.name == "nt":
        if envelope.get("protection") != WINDOWS_CLIENT_KEY_PROTECTION:
            raise ActivationClientError("client_key.dat protection is unsupported")
        ciphertext = _decode_required_b64url(envelope, "ciphertext")
        plaintext = _crypt_unprotect_data(ciphertext)
    else:
        if envelope.get("protection") != CLIENT_KEY_PROTECTION or envelope.get("kdf") != (
            "sha256-platform-material-v1"
        ):
            raise ActivationClientError("client_key.dat protection is unsupported")
        salt = _decode_required_b64url(envelope, "salt")
        nonce = _decode_required_b64url(envelope, "nonce")
        ciphertext = _decode_required_b64url(envelope, "ciphertext")
        supplied_tag = _decode_required_b64url(envelope, "tag")
        tag_key = _derive_client_key_material(license_dir, salt, nonce, b"tag")
        tag_mac = hmac.new(tag_key, digestmod=hashlib.sha256)
        tag_mac.update(CLIENT_KEY_SCHEMA.encode("utf-8"))
        tag_mac.update(b"\0")
        tag_mac.update(CLIENT_KEY_PROTECTION.encode("utf-8"))
        tag_mac.update(b"\0")
        tag_mac.update(salt)
        tag_mac.update(nonce)
        tag_mac.update(ciphertext)
        if not hmac.compare_digest(tag_mac.digest(), supplied_tag):
            raise ActivationClientError("client_key.dat tag is invalid")
        enc_key = _derive_client_key_material(license_dir, salt, nonce, b"enc")
        plaintext = _xor_stream(ciphertext, enc_key, nonce)
    if len(plaintext) != 32:
        raise ActivationClientError("client_key.dat decrypted to invalid key length")
    return plaintext


def _client_key_envelope(license_dir: Path, plaintext: bytes) -> bytes:
    if os.name == "nt":
        return canonical_json_bytes(
            {
                "schema": CLIENT_KEY_SCHEMA,
                "protection": WINDOWS_CLIENT_KEY_PROTECTION,
                "ciphertext": _b64url_encode(_crypt_protect_data(plaintext)),
            },
        )
    salt = token_bytes(16)
    nonce = hashlib.sha256(b"nonce:" + salt).digest()[:12]
    enc_key = _derive_client_key_material(license_dir, salt, nonce, b"enc")
    ciphertext = _xor_stream(plaintext, enc_key, nonce)
    tag_key = _derive_client_key_material(license_dir, salt, nonce, b"tag")
    tag_mac = hmac.new(tag_key, digestmod=hashlib.sha256)
    tag_mac.update(CLIENT_KEY_SCHEMA.encode("utf-8"))
    tag_mac.update(b"\0")
    tag_mac.update(CLIENT_KEY_PROTECTION.encode("utf-8"))
    tag_mac.update(b"\0")
    tag_mac.update(salt)
    tag_mac.update(nonce)
    tag_mac.update(ciphertext)
    return canonical_json_bytes(
        {
            "schema": CLIENT_KEY_SCHEMA,
            "protection": CLIENT_KEY_PROTECTION,
            "kdf": "sha256-platform-material-v1",
            "salt": _b64url_encode(salt),
            "nonce": _b64url_encode(nonce),
            "ciphertext": _b64url_encode(ciphertext),
            "tag": _b64url_encode(tag_mac.digest()),
        },
    )


def _derive_client_key_material(
    license_dir: Path,
    salt: bytes,
    nonce: bytes,
    purpose: bytes,
) -> bytes:
    digest = hashlib.sha256()
    digest.update(CLIENT_KEY_SCHEMA.encode("utf-8"))
    digest.update(b"\0")
    digest.update(CLIENT_KEY_PROTECTION.encode("utf-8"))
    digest.update(b"\0")
    digest.update(purpose)
    digest.update(b"\0")
    digest.update(_platform_client_key_material(license_dir))
    digest.update(b"\0")
    digest.update(salt)
    digest.update(nonce)
    return digest.digest()


def _platform_client_key_material(license_dir: Path) -> bytes:
    if _rust_os_name() == "macos":
        return _macos_client_key_material()
    if os.name != "nt":
        user_id = str(license_dir.stat().st_uid)
        parts = [
            CLIENT_KEY_SCHEMA,
            CLIENT_KEY_PROTECTION,
            _rust_os_name(),
            _rust_arch_name(),
            user_id,
            _machine_id(),
        ]
        return "\0".join(parts).encode("utf-8")
    user = os.environ.get("USERNAME") or os.environ.get("USER", "")
    hostname = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME", "")
    return "\0".join(
        [
            CLIENT_KEY_SCHEMA,
            CLIENT_KEY_PROTECTION,
            _rust_os_name(),
            _rust_arch_name(),
            user,
            hostname,
        ],
    ).encode("utf-8")


def _macos_client_key_material() -> bytes:
    service = "com.skey.client-key.v1"
    account = os.environ.get("USER") or "default"
    secret = _read_macos_keychain_secret(service, account)
    if secret is None:
        secret = _create_macos_keychain_secret(service, account)
    material = "\0".join(
        [CLIENT_KEY_SCHEMA, CLIENT_KEY_PROTECTION, "macos", _rust_arch_name(), account],
    ).encode("utf-8")
    return material + b"\0" + secret


def _read_macos_keychain_secret(service: str, account: str) -> bytes | None:
    try:
        output = subprocess.run(
            ["security", "find-generic-password", "-w", "-s", service, "-a", account],
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if not output.returncode == 0:
        return None
    return output.stdout.rstrip(b"\r\n") or None


def _create_macos_keychain_secret(service: str, account: str) -> bytes:
    secret = _uuid_secret()
    subprocess.run(
        ["security", "add-generic-password", "-U", "-s", service, "-a", account, "-w", secret.decode()],
        check=True,
        capture_output=True,
    )
    return secret


def _uuid_secret() -> bytes:
    try:
        output = subprocess.run(["uuidgen"], capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return _b64url_encode(token_bytes(32)).encode("ascii")
    return output.stdout.rstrip(b"\r\n")


def _machine_id() -> str:
    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return platform.node()


def _crypt_protect_data(plaintext: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    input_buffer = ctypes.create_string_buffer(plaintext)
    input_blob = DataBlob(len(plaintext), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_byte)))
    output_blob = DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    ok = crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    if not ok:
        raise ActivationClientError("failed to protect client key with Windows DPAPI")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)


def _crypt_unprotect_data(ciphertext: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    input_buffer = ctypes.create_string_buffer(ciphertext)
    input_blob = DataBlob(len(ciphertext), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_byte)))
    output_blob = DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    if not ok:
        raise ActivationClientError("failed to unprotect client key with Windows DPAPI")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)


def _xor_stream(input_bytes: bytes, key: bytes, nonce: bytes) -> bytes:
    output = bytearray()
    for counter, chunk_start in enumerate(range(0, len(input_bytes), 32)):
        chunk = input_bytes[chunk_start : chunk_start + 32]
        digest = hashlib.sha256()
        digest.update(key)
        digest.update(nonce)
        digest.update(counter.to_bytes(8, "big"))
        stream = digest.digest()
        output.extend(byte ^ mask for byte, mask in zip(chunk, stream))
    return bytes(output)


def _write_initial_state(
    *,
    license_dir: Path,
    cert: dict[str, Any],
    client_key_bytes: bytes,
    server_time: str | None,
) -> None:
    product_id = _require_str(cert, "product_id")
    package_id = _require_str(cert, "package_id")
    activation_id = _require_str(cert, "activation_id")
    package_hash = _require_str(cert, "package_hash")
    observed_time = server_time or _optional_str(cert, "issued_at") or _utcnow_text()
    state: dict[str, object] = {
        "schema": STATE_SCHEMA,
        "product_id": product_id,
        "package_id": package_id,
        "activation_id": activation_id,
        "package_hash": package_hash,
        "last_seen_utc": observed_time,
        "last_server_utc": observed_time,
        "last_lease_until": _require_str(cert, "lease_until"),
        "boot_counter": 1,
    }
    state["hmac"] = _b64url_encode(
        hmac.new(
            _state_hmac_key(client_key_bytes, product_id, package_id, activation_id, package_hash),
            canonical_json_bytes(state),
            hashlib.sha256,
        ).digest(),
    )
    (license_dir / "state.dat").write_bytes(canonical_json_bytes(state))


def _state_hmac_key(
    client_key_bytes: bytes,
    product_id: str,
    package_id: str,
    activation_id: str,
    package_hash: str,
) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"skey-state-hmac-v2")
    digest.update(b"\0")
    digest.update(client_key_bytes)
    digest.update(b"\0")
    digest.update(product_id.encode("utf-8"))
    digest.update(b"\0")
    digest.update(package_id.encode("utf-8"))
    digest.update(b"\0")
    digest.update(activation_id.encode("utf-8"))
    digest.update(b"\0")
    digest.update(package_hash.encode("utf-8"))
    return digest.digest()


def _verify_signed_json(
    signed: dict[str, Any],
    public_key: Ed25519PublicKey,
    message: str,
) -> None:
    signature_value = signed.get("signature")
    if not isinstance(signature_value, str):
        raise ActivationClientError(message)
    claims = dict(signed)
    claims.pop("signature", None)
    try:
        public_key.verify(_b64url_decode(signature_value), canonical_json_bytes(claims))
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise ActivationClientError(message) from exc


def _post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, sort_keys=True).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ActivationClientError(f"activation server rejected request: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ActivationClientError(f"activation server is unreachable: {exc.reason}") from exc
    try:
        decoded = json.loads(body)
    except JSONDecodeError as exc:
        raise ActivationClientError("activation server response is malformed") from exc
    return _require_mapping(decoded, "activation server response")


def _endpoint(server_url: str, suffix: str) -> str:
    return f"{server_url.rstrip('/')}/{suffix}"


def _license_dir(product_root: Path) -> Path:
    return product_root / ".secure" / "license"


def _x25519_public_b64(client_private: X25519PrivateKey) -> str:
    public_bytes = client_private.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return _b64url_encode(public_bytes)


def _device_hash() -> str:
    fields = {
        "os": _rust_os_name(),
        "arch": _rust_arch_name(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER", ""),
        "host": os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or platform.node(),
    }
    return "skey-fp-v1:" + _b64url_encode(canonical_json_bytes(fields))


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ActivationClientError(f"{label} must be an object")
    return cast(dict[str, Any], value)


def _require_equal(mapping: dict[str, Any], field_name: str, expected: str) -> None:
    actual = mapping.get(field_name)
    if actual != expected:
        raise ActivationClientError(f"activation certificate {field_name} does not match release")


def _require_str(mapping: dict[str, Any], field_name: str) -> str:
    value = mapping.get(field_name)
    if not isinstance(value, str) or not value:
        raise ActivationClientError(f"activation certificate is missing {field_name}")
    return value


def _decode_required_b64url(mapping: dict[str, Any], field_name: str) -> bytes:
    value = mapping.get(field_name)
    if not isinstance(value, str):
        raise ActivationClientError(f"client_key.dat is missing {field_name}")
    try:
        return _b64url_decode(value)
    except (ValueError, binascii.Error) as exc:
        raise ActivationClientError(f"client_key.dat {field_name} is malformed") from exc


def _optional_str(mapping: dict[str, Any], field_name: str) -> str | None:
    value = mapping.get(field_name)
    return value if isinstance(value, str) and value else None


def _utcnow_text() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _rust_os_name() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return sys.platform


def _rust_arch_name() -> str:
    machine = platform.machine().lower()
    return {
        "amd64": "x86_64",
        "x64": "x86_64",
        "arm64": "aarch64",
    }.get(machine, machine)
