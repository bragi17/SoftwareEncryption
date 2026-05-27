"""Cryptographic helpers for signed server claims and package-key wrapping."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from skeyserver.models import hash_license_code as _hash_license_code


PACKAGE_KEY_ENVELOPE_ALG = "AES-256-GCM+SKEY-PACKAGE-KEK-v1"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _canonical_json_bytes(claims: dict[str, object]) -> bytes:
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_package_kek(package_kek_b64: str | None) -> bytes:
    if package_kek_b64 is None:
        raise ValueError("package_kek_b64 must be configured")
    try:
        package_kek = _b64url_decode(package_kek_b64)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("package_kek_b64 must be valid URL-safe base64") from exc
    if len(package_kek) != 32:
        raise ValueError("package_kek_b64 must decode to 32 bytes")
    return package_kek


def _package_key_aad(*, product_id: str, package_id: str, package_hash: str) -> bytes:
    return _canonical_json_bytes(
        {
            "purpose": "skey-package-key-at-rest-v1",
            "product_id": product_id,
            "package_id": package_id,
            "package_hash": package_hash,
        },
    )


def encrypt_package_key_at_rest(
    package_key: bytes,
    *,
    package_kek: bytes,
    product_id: str,
    package_id: str,
    package_hash: str,
) -> bytes:
    """Encrypt K_pkg for database storage with AAD bound to package identity."""

    if len(package_key) != 32:
        raise ValueError("package key must be 32 bytes")
    if len(package_kek) != 32:
        raise ValueError("package KEK must be 32 bytes")
    nonce = os.urandom(12)
    aad = _package_key_aad(product_id=product_id, package_id=package_id, package_hash=package_hash)
    ciphertext = AESGCM(package_kek).encrypt(nonce, package_key, aad)
    envelope: dict[str, object] = {
        "alg": PACKAGE_KEY_ENVELOPE_ALG,
        "nonce": _b64url_encode(nonce),
        "ciphertext": _b64url_encode(ciphertext),
        "key_hash": f"sha256:{hashlib.sha256(package_key).hexdigest()}",
    }
    return _canonical_json_bytes(envelope)


def decrypt_package_key_at_rest(
    encrypted_pkg_key: bytes,
    *,
    package_kek: bytes,
    product_id: str,
    package_id: str,
    package_hash: str,
) -> bytes:
    """Decrypt a package-key database envelope and verify its identity-bound AAD."""

    if len(package_kek) != 32:
        raise ValueError("package KEK must be 32 bytes")
    try:
        envelope = json.loads(encrypted_pkg_key.decode("utf-8"))
        if not isinstance(envelope, dict):
            raise ValueError("package key envelope must be an object")
        if envelope.get("alg") != PACKAGE_KEY_ENVELOPE_ALG:
            raise ValueError("package key envelope algorithm is unsupported")
        nonce = _b64url_decode(str(envelope["nonce"]))
        ciphertext = _b64url_decode(str(envelope["ciphertext"]))
        aad = _package_key_aad(product_id=product_id, package_id=package_id, package_hash=package_hash)
        package_key = AESGCM(package_kek).decrypt(nonce, ciphertext, aad)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, binascii.Error, InvalidTag, ValueError) as exc:
        raise ValueError("package key envelope is invalid") from exc
    expected_hash = envelope.get("key_hash")
    actual_hash = f"sha256:{hashlib.sha256(package_key).hexdigest()}"
    if expected_hash != actual_hash:
        raise ValueError("package key envelope hash mismatch")
    if len(package_key) != 32:
        raise ValueError("package key envelope decrypted to invalid key length")
    return package_key


def load_ed25519_private_key(private_key_b64: str | None) -> Ed25519PrivateKey:
    if private_key_b64 is None:
        return Ed25519PrivateKey.generate()
    key_bytes = _b64url_decode(private_key_b64)
    if len(key_bytes) != 32:
        raise ValueError("signing_private_key_b64 must contain a raw 32-byte Ed25519 private key")
    return Ed25519PrivateKey.from_private_bytes(key_bytes)


def sign_json(
    claims: dict[str, object],
    private_key: Ed25519PrivateKey,
    kid: str,
) -> dict[str, object]:
    """Return canonical claims with key id and a base64url Ed25519 signature."""

    signed_claims = dict(claims)
    signed_claims["kid"] = kid
    signed_claims.pop("signature", None)
    signature = private_key.sign(_canonical_json_bytes(signed_claims))
    signed_claims["signature"] = _b64url_encode(signature)
    return signed_claims


def verify_json(signed: dict[str, object], public_key: Ed25519PublicKey) -> None:
    """Verify signed canonical JSON claims or raise ValueError."""

    signature_value = signed.get("signature")
    if not isinstance(signature_value, str):
        raise ValueError("signed JSON is missing a signature")
    claims = dict(signed)
    claims.pop("signature", None)
    try:
        signature = _b64url_decode(signature_value)
        public_key.verify(signature, _canonical_json_bytes(claims))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("signed JSON signature is invalid") from exc


def wrap_package_key(package_key: bytes, client_pub_b64: str) -> dict[str, str]:
    """Wrap K_pkg to the client public key using X25519, HKDF-SHA256, and AES-256-GCM."""

    client_public = X25519PublicKey.from_public_bytes(_b64url_decode(client_pub_b64))
    ephemeral_private = X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(client_public)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"skey-package-key-wrap-v1",
    ).derive(shared_secret)
    nonce = os.urandom(12)
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, package_key, b"skey-package-key-wrap-v1")
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "alg": "X25519+HKDF-SHA256+AES-256-GCM",
        "ephemeral_public": _b64url_encode(ephemeral_public),
        "nonce": _b64url_encode(nonce),
        "ciphertext": _b64url_encode(ciphertext),
    }


def hash_license_code(server_secret: bytes, license_code: str) -> str:
    """Return lower-hex HMAC-SHA256 of the normalized license code."""

    return _hash_license_code(server_secret, license_code)


JsonDict = dict[str, Any]
