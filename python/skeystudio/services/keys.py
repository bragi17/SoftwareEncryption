from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from typing import Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


@dataclass(frozen=True, slots=True)
class KeyBundle:
    vendor_public_key_b64: str
    build_signing_private_key_b64: str
    vendor_public_key_sha256: str
    package_kek_b64: str
    admin_wrap_key_b64: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, raw_json: str) -> Self:
        payload = json.loads(raw_json)
        if not isinstance(payload, dict):
            raise ValueError("Key bundle JSON must be an object.")

        vendor_public_key_b64 = _required_string(payload, "vendor_public_key_b64")
        build_signing_private_key_b64 = _required_string(
            payload,
            "build_signing_private_key_b64",
        )
        vendor_public_key_sha256 = _required_string(payload, "vendor_public_key_sha256")
        package_kek_b64 = _required_string(payload, "package_kek_b64")
        admin_wrap_key_b64 = _required_string(payload, "admin_wrap_key_b64")
        return cls(
            vendor_public_key_b64=vendor_public_key_b64,
            build_signing_private_key_b64=build_signing_private_key_b64,
            vendor_public_key_sha256=vendor_public_key_sha256,
            package_kek_b64=package_kek_b64,
            admin_wrap_key_b64=admin_wrap_key_b64,
        )


class KeyService:
    @staticmethod
    def generate_test_key_set() -> KeyBundle:
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

        return KeyBundle(
            vendor_public_key_b64=_to_b64(public_bytes),
            build_signing_private_key_b64=_to_b64(private_bytes),
            vendor_public_key_sha256=hashlib.sha256(public_bytes).hexdigest(),
            package_kek_b64=_to_b64(secrets.token_bytes(32)),
            admin_wrap_key_b64=_to_b64(secrets.token_bytes(32)),
        )


def mask_secret(secret: str) -> str:
    if len(secret) < 12:
        return "***"
    return f"{secret[:4]}...{secret[-4:]}"


def _to_b64(raw_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")


def _required_string(payload: dict[object, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Key bundle JSON is missing string field: {key}")
    return value
