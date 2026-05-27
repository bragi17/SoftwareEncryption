"""Diagnostics and redacted report export for protected releases."""

from __future__ import annotations

import base64
import binascii
import json
import re
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from skeyprotect.activation_client import ActivationClientError, _verify_signed_json
from skeystudio.services.protector import ProtectionService, _read_runtime_public_key
from skeystudio.state import OperationResult


SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<prefix>
        ["']?
        (?:package|admin|private|server|client)
        [A-Za-z0-9_.-]*
        (?:key|kek|secret|token)
        [A-Za-z0-9_.-]*
        ["']?
        \s*[:=]\s*
    )
    (?:
        "(?P<double>[^"]*)"
        |
        '(?P<single>[^']*)'
        |
        (?P<unquoted>[^"',\s}]+)
    )
    """,
)

ACTIVATION_CERT_FIELDS = (
    "license_id",
    "activation_id",
    "product_id",
    "package_id",
    "package_hash",
    "lease_until",
    "issued_at",
    "signature",
)
STATE_FIELDS = ("product_id", "package_id", "activation_id", "package_hash", "hmac")
STATE_TIME_FIELDS = ("last_seen_utc", "last_server_utc", "last_lease_until")
PLATFORM_CLIENT_KEY_PROTECTION = "platform-derived-hmac-sha256-xor-v2"
PLATFORM_CLIENT_KEY_KDF = "sha256-platform-material-v1"
WINDOWS_CLIENT_KEY_PROTECTION = "windows-dpapi-v1"


def redact_text(text: str) -> str:
    return SECRET_ASSIGNMENT.sub(_redact_assignment, text)


def _redact_assignment(match: re.Match[str]) -> str:
    prefix = match.group("prefix")
    if match.group("double") is not None:
        return f'{prefix}"[redacted]"'
    if match.group("single") is not None:
        return f"{prefix}'[redacted]'"
    return f"{prefix}[redacted]"


class DiagnosticsService:
    @staticmethod
    def run(product_root: Path) -> OperationResult:
        if not product_root.is_dir():
            return OperationResult.fail(
                f"Release folder does not exist: {product_root}",
                code="release_missing",
                detail={"product_root": str(product_root)},
            )

        secure_root = product_root / ".secure"
        if not secure_root.is_dir():
            return OperationResult.fail(
                f".secure folder is missing: {secure_root}",
                code="secure_missing",
                detail={"product_root": str(product_root)},
            )

        runtime_result = ProtectionService.verify_runtime(product_root)
        if not runtime_result.success:
            return runtime_result

        license_root = secure_root / "license"
        license_path = license_root / "activation.cert"
        client_key_path = license_root / "client_key.dat"
        state_path = license_root / "state.dat"
        if not license_path.is_file():
            return OperationResult.fail(
                f"License activation certificate is missing: {license_path}",
                code="license_missing",
                detail={"product_root": str(product_root)},
            )
        if not client_key_path.is_file():
            return OperationResult.fail(
                f"Client key envelope is missing: {client_key_path}",
                code="client_key_missing",
                detail={"product_root": str(product_root)},
            )
        if not state_path.is_file():
            return OperationResult.fail(
                f"Runtime state is missing: {state_path}",
                code="state_missing",
                detail={"product_root": str(product_root)},
            )

        activation_cert = _read_json_object(license_path, code="license_invalid")
        if isinstance(activation_cert, OperationResult):
            return activation_cert
        invalid_activation_fields = [
            field for field in ACTIVATION_CERT_FIELDS if not _has_string(activation_cert, field)
        ]
        if invalid_activation_fields:
            return OperationResult.fail(
                "License activation certificate is invalid",
                code="license_invalid",
                detail={"missing_fields": invalid_activation_fields},
            )
        public_key_path = secure_root / "runtime.manifest.public-key.json"
        try:
            _verify_signed_json(
                activation_cert,
                _read_runtime_public_key(public_key_path),
                "activation certificate signature is invalid",
            )
        except (ActivationClientError, OSError, ValueError, TypeError, JSONDecodeError) as exc:
            return OperationResult.fail(
                f"License activation certificate is invalid: {exc}",
                code="license_invalid",
                detail={"path": str(license_path)},
            )

        client_key = _read_json_object(client_key_path, code="client_key_invalid")
        if isinstance(client_key, OperationResult):
            return client_key
        client_key_result = _validate_client_key(client_key, path=client_key_path)
        if client_key_result is not None:
            return client_key_result

        state = _read_json_object(state_path, code="state_invalid")
        if isinstance(state, OperationResult):
            return state
        state_result = _validate_state(state, activation_cert)
        if state_result is not None:
            return state_result

        return OperationResult.ok(
            "Diagnostics passed",
            detail={
                "product_root": str(product_root),
                "secure_root": str(secure_root),
                "runtime_manifest": str(secure_root / "runtime.manifest"),
                "license": str(license_path),
                "client_key": str(client_key_path),
                "state": str(state_path),
            },
        )

    @staticmethod
    def export_report(product_root: Path, report_dir: Path) -> OperationResult:
        result = DiagnosticsService.run(product_root)
        report_dir.mkdir(parents=True, exist_ok=True)

        summary = {
            "product_root": str(product_root),
            "success": result.success,
            "code": result.code,
            "message": result.message,
            "detail": result.detail,
        }
        (report_dir / "summary.json").write_text(
            redact_text(json.dumps(summary, indent=2, sort_keys=True)),
            encoding="utf-8",
        )
        (report_dir / "report.txt").write_text(
            _report_text(product_root, result),
            encoding="utf-8",
        )

        return OperationResult.ok("Diagnostics report exported", detail={"report_dir": str(report_dir)})


def _report_text(product_root: Path, result: OperationResult) -> str:
    lines = [
        f"Product root: {product_root}",
        f"Result: {result.message}",
        f"Code: {result.code or 'ok'}",
    ]
    for path in _safe_report_files(product_root):
        lines.append("")
        lines.append(f"[{path.relative_to(product_root).as_posix()}]")
        try:
            lines.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            lines.append(f"Unreadable: {exc}")

    client_key = product_root / ".secure" / "license" / "client_key.dat"
    if client_key.exists():
        lines.append("")
        lines.append("[.secure/license/client_key.dat]")
        lines.append("[redacted: client key material is never exported]")

    return redact_text("\n".join(lines))


def _safe_report_files(product_root: Path) -> list[Path]:
    candidates = [
        product_root / ".secure" / "runtime.manifest",
        product_root / ".secure" / "runtime.manifest.sig",
        product_root / ".secure" / "runtime.manifest.public-key.json",
        product_root / ".secure" / "online-policy.json",
    ]
    return [path for path in candidates if path.is_file()]


def _read_json_object(path: Path, *, code: str) -> dict[str, Any] | OperationResult:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, JSONDecodeError) as exc:
        return OperationResult.fail(
            f"JSON artifact is invalid: {path}: {exc}",
            code=code,
            detail={"path": str(path)},
        )
    if not isinstance(value, dict):
        return OperationResult.fail(
            f"JSON artifact must be an object: {path}",
            code=code,
            detail={"path": str(path)},
        )
    return value


def _has_string(mapping: dict[str, Any], key: str) -> bool:
    value = mapping.get(key)
    return isinstance(value, str) and bool(value)


def _validate_client_key(client_key: dict[str, Any], *, path: Path) -> OperationResult | None:
    if client_key.get("schema") != "skey-client-key-v1":
        return _invalid_client_key(path)

    protection = client_key.get("protection")
    if protection == WINDOWS_CLIENT_KEY_PROTECTION:
        if _decode_b64url_field(client_key, "ciphertext", min_length=1) is None:
            return _invalid_client_key(path)
        return None

    if protection == PLATFORM_CLIENT_KEY_PROTECTION:
        if client_key.get("kdf") != PLATFORM_CLIENT_KEY_KDF:
            return _invalid_client_key(path)
        expected_lengths = {"salt": 16, "nonce": 12, "tag": 32}
        for field_name, expected_length in expected_lengths.items():
            if _decode_b64url_field(client_key, field_name, expected_length=expected_length) is None:
                return _invalid_client_key(path)
        if _decode_b64url_field(client_key, "ciphertext", min_length=1) is None:
            return _invalid_client_key(path)
        return None

    return _invalid_client_key(path)


def _validate_state(
    state: dict[str, Any],
    activation_cert: dict[str, Any],
) -> OperationResult | None:
    invalid_state_fields = ["schema"] if state.get("schema") != "skey-state-v1" else []
    invalid_state_fields.extend(field for field in STATE_FIELDS if not _has_string(state, field))
    invalid_state_fields.extend(field for field in STATE_TIME_FIELDS if not _has_string(state, field))
    if not isinstance(state.get("boot_counter"), int):
        invalid_state_fields.append("boot_counter")

    mismatched_fields = [
        field
        for field in ("product_id", "package_id", "activation_id", "package_hash")
        if state.get(field) != activation_cert.get(field)
    ]
    if state.get("last_lease_until") != activation_cert.get("lease_until"):
        mismatched_fields.append("last_lease_until")
    if invalid_state_fields or mismatched_fields:
        return OperationResult.fail(
            "Runtime state is invalid",
            code="state_invalid",
            detail={
                "missing_fields": invalid_state_fields,
                "mismatched_fields": mismatched_fields,
            },
        )
    return None


def _decode_b64url_field(
    mapping: dict[str, Any],
    field_name: str,
    *,
    expected_length: int | None = None,
    min_length: int | None = None,
) -> bytes | None:
    value = mapping.get(field_name)
    if not isinstance(value, str) or not value:
        return None
    if any(character not in _B64URL_ALPHABET for character in value):
        return None
    try:
        decoded = base64.b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError):
        return None
    if expected_length is not None and len(decoded) != expected_length:
        return None
    if min_length is not None and len(decoded) < min_length:
        return None
    return decoded


def _invalid_client_key(path: Path) -> OperationResult:
    return OperationResult.fail(
        "Client key envelope is invalid",
        code="client_key_invalid",
        detail={"path": str(path)},
    )


_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=",
)
