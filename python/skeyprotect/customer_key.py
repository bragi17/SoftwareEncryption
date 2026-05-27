"""Customer key file generation for offline first-run binding."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skeyprotect.config import SKeyConfig
from skeyprotect.manifest import canonical_json_bytes

CUSTOMER_KEY_FILENAME = "skey.key"
CUSTOMER_KEY_SCHEMA = "skey-customer-key-v1"


def write_customer_key_file(
    *,
    product_root: Path,
    payload_info: dict[str, Any],
    config: SKeyConfig,
    signing_key: Ed25519PrivateKey,
    package_key: bytes,
    issued_at: datetime | None = None,
) -> Path:
    """Write the customer-deliverable key file next to the protected launcher."""
    if len(package_key) != 32:
        raise ValueError("package_key must be 32 bytes")

    issued_at = issued_at or datetime.now(UTC)
    perpetual = config.license.time.perpetual
    expire_at = None if perpetual else issued_at + timedelta(hours=config.license.time.lease_hours)
    lease_until = None if perpetual else expire_at

    key_file: dict[str, Any] = {
        "schema": CUSTOMER_KEY_SCHEMA,
        "license_id": f"KEY-{payload_info['product_id']}-{payload_info['package_id']}",
        "activation_id": f"KEY-{payload_info['package_id']}",
        "product_id": payload_info["product_id"],
        "package_id": payload_info["package_id"],
        "package_hash": payload_info["package_hash"],
        "device_score_policy": {
            "pass_score": config.license.machine_binding.pass_score,
            "review_score": config.license.machine_binding.review_score,
        },
        "features": [
            {"code": feature, "enabled": True}
            for feature in _license_features(config)
        ],
        "not_before": _utc_json(issued_at),
        "perpetual": perpetual,
        "expire_at": None if expire_at is None else _utc_json(expire_at),
        "lease_until": None if lease_until is None else _utc_json(lease_until),
        "offline_grace_hours": config.license.time.offline_grace_hours,
        "package_key_b64": _base64url_no_pad(package_key),
        "kid": config.server.public_key_id,
        "binding": None,
    }
    signature = signing_key.sign(customer_key_signing_bytes(key_file))
    key_file["signature"] = _base64url_no_pad(signature)

    path = product_root / CUSTOMER_KEY_FILENAME
    path.write_bytes(canonical_json_bytes(key_file))
    return path


def customer_key_signing_bytes(value: dict[str, Any]) -> bytes:
    signing_value = dict(value)
    signing_value.pop("signature", None)
    signing_value.pop("binding", None)
    return canonical_json_bytes(signing_value)


def _license_features(config: SKeyConfig) -> list[str]:
    features: list[str] = []

    def append(feature: str) -> None:
        feature = feature.strip()
        if feature and feature not in features:
            features.append(feature)

    for feature in config.license.default_features:
        append(feature)
    for python_entry in config.python.entries:
        append(python_entry.feature)
    for exe_entry in config.exe.entries:
        append(exe_entry.feature)
    for jar_entry in config.jar.entries:
        append(jar_entry.feature)
    for resource_entry in config.resources.entries:
        append(resource_entry.feature)

    return features or ["RUN_MAIN"]


def _base64url_no_pad(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _utc_json(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
