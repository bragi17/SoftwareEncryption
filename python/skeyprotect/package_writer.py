"""SKP package writer used by build tooling."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
from secrets import token_bytes, token_hex
import struct
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from skeyprotect import __version__
from skeyprotect.config import SKeyConfig
from skeyprotect.manifest import canonical_json_bytes, manifest_signing_bytes
from skeyprotect.scanner import ScanResult

MAGIC = b"SKP1"
HEADER_VERSION = 1
HEADER_STRUCT = struct.Struct("<4sHIQQ")
RESOURCE_CHUNK_THRESHOLD = 16 * 1024 * 1024
RESOURCE_CHUNK_SIZE = 4 * 1024 * 1024


@dataclass(frozen=True)
class PayloadHeader:
    magic: bytes
    header_version: int
    header_length: int
    manifest_length: int
    blob_table_length: int


@dataclass(frozen=True)
class PayloadWriteResult:
    package_id: str
    package_hash: str
    manifest_hash: str
    blob_count: int
    output_path: Path


@dataclass(frozen=True)
class _PayloadFixtureOptions:
    """Private deterministic hook for committed Python/Rust compatibility fixtures only."""

    package_id: str
    created_at: str
    nonces_by_blob_id: dict[str, bytes]


def derive_file_key(package_key: bytes, package_id: str, blob_id: str, version: str) -> bytes:
    """Derive the AES-256-GCM key for one encrypted blob."""
    if len(package_key) != 32:
        raise ValueError("package_key must be 32 bytes")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=package_id.encode("utf-8"),
        info=f"file|{blob_id}|{version}".encode("utf-8"),
    ).derive(package_key)


def derive_resource_chunk_key(file_key: bytes, blob_id: str, chunk_index: int) -> bytes:
    """Derive the AES-256-GCM key for one encrypted resource chunk."""
    if len(file_key) != 32:
        raise ValueError("file_key must be 32 bytes")
    if chunk_index < 0:
        raise ValueError("chunk_index must be non-negative")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=blob_id.encode("utf-8"),
        info=f"chunk|{chunk_index}".encode("utf-8"),
    ).derive(file_key)


def write_payload(
    project_root: Path,
    output_path: Path,
    package_key: bytes,
    signing_key: Ed25519PrivateKey,
    scan_result: ScanResult,
    config: SKeyConfig,
    *,
    _fixture_options: _PayloadFixtureOptions | None = None,
) -> PayloadWriteResult:
    """Write a signed SKP payload and return its hashes and metadata."""
    if len(package_key) != 32:
        raise ValueError("package_key must be 32 bytes")

    resolved_root = project_root.resolve(strict=True)
    package_id = _fixture_options.package_id if _fixture_options else token_hex(16)
    version = config.product.version
    encrypted_chunks: list[bytes] = []
    manifest_blobs: list[dict[str, Any]] = []
    blob_table: list[dict[str, Any]] = []
    offset = 0

    for blob in sorted(scan_result.blobs.values(), key=lambda item: item.id):
        source_path = (resolved_root / blob.path).resolve(strict=True)
        if not source_path.is_relative_to(resolved_root):
            raise ValueError(f"blob path escapes project root: {blob.path}")

        plaintext = source_path.read_bytes()
        plain_sha256 = sha256(plaintext).hexdigest()
        aad = _blob_aad(
            product_id=config.product.id,
            package_id=package_id,
            blob_id=blob.id,
            version=version,
            plain_sha256=plain_sha256,
        )
        file_key = derive_file_key(package_key, package_id, blob.id, version)
        is_chunked_resource = (
            blob.kind == "resource" and len(plaintext) > RESOURCE_CHUNK_THRESHOLD
        )

        if is_chunked_resource:
            blob_offset = offset
            chunks: list[dict[str, Any]] = []
            ciphertext_parts: list[bytes] = []
            for chunk_index, chunk_start in enumerate(
                range(0, len(plaintext), RESOURCE_CHUNK_SIZE),
            ):
                chunk_plaintext = plaintext[chunk_start : chunk_start + RESOURCE_CHUNK_SIZE]
                chunk_nonce = token_bytes(12)
                chunk_key = derive_resource_chunk_key(file_key, blob.id, chunk_index)
                chunk_aad = _chunk_aad(aad, chunk_index)
                chunk_ciphertext = AESGCM(chunk_key).encrypt(
                    chunk_nonce,
                    chunk_plaintext,
                    chunk_aad.encode("utf-8"),
                )
                chunks.append(
                    {
                        "nonce": chunk_nonce.hex(),
                        "offset": offset,
                        "cipher_len": len(chunk_ciphertext),
                        "plain_len": len(chunk_plaintext),
                    }
                )
                ciphertext_parts.append(chunk_ciphertext)
                offset += len(chunk_ciphertext)
            ciphertext = b"".join(ciphertext_parts)
            manifest_entry = {
                "blob_id": blob.id,
                "type": blob.kind,
                "original_path": blob.path,
                "offset": blob_offset,
                "cipher_len": len(ciphertext),
                "plain_len": len(plaintext),
                "aad": aad,
                "sha256_plain": plain_sha256,
                "feature": blob.feature,
                "chunk_size": RESOURCE_CHUNK_SIZE,
                "chunk_count": len(chunks),
                "chunks": chunks,
            }
            if blob.mode is not None:
                manifest_entry["mode"] = blob.mode
            manifest_blobs.append(manifest_entry)
            blob_table.append(
                {
                    "blob_id": blob.id,
                    "offset": blob_offset,
                    "cipher_len": len(ciphertext),
                }
            )
            encrypted_chunks.append(ciphertext)
            continue

        nonce = (
            _fixture_nonce(_fixture_options, blob.id)
            if _fixture_options
            else token_bytes(12)
        )
        ciphertext = AESGCM(file_key).encrypt(nonce, plaintext, aad.encode("utf-8"))

        manifest_entry = {
            "blob_id": blob.id,
            "type": blob.kind,
            "original_path": blob.path,
            "offset": offset,
            "cipher_len": len(ciphertext),
            "plain_len": len(plaintext),
            "nonce": nonce.hex(),
            "aad": aad,
            "sha256_plain": plain_sha256,
            "feature": blob.feature,
        }
        if blob.mode is not None:
            manifest_entry["mode"] = blob.mode
        manifest_blobs.append(manifest_entry)
        blob_table.append(
            {
                "blob_id": blob.id,
                "offset": offset,
                "cipher_len": len(ciphertext),
            }
        )
        encrypted_chunks.append(ciphertext)
        offset += len(ciphertext)

    manifest: dict[str, Any] = {
        "format": "SKP1",
        "product_id": config.product.id,
        "package_id": package_id,
        "version": version,
        "created_at": (
            _fixture_options.created_at
            if _fixture_options
            else datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        ),
        "builder_version": __version__,
        "min_runtime_version": "0.1.0",
        "crypto": {
            "aead": "AES-256-GCM",
            "kdf": "HKDF-SHA256",
            "signature": "Ed25519",
            "nonce_policy": "random_96bit_per_blob",
        },
        "entrypoints": [
            {
                "id": entry.id,
                "path": entry.path,
                "kind": entry.kind,
                "feature": entry.feature,
            }
            for entry in sorted(scan_result.entrypoints.values(), key=lambda item: item.id)
        ],
        "blobs": manifest_blobs,
        "runtime": {"required_dlls": []},
        "signature": {
            "kid": config.server.public_key_id,
            "alg": "Ed25519",
            "sig": "",
        },
    }
    manifest["signature"]["sig"] = signing_key.sign(manifest_signing_bytes(manifest)).hex()
    manifest_bytes = canonical_json_bytes(manifest)
    blob_table_bytes = canonical_json_bytes(blob_table)
    header = HEADER_STRUCT.pack(
        MAGIC,
        HEADER_VERSION,
        HEADER_STRUCT.size,
        len(manifest_bytes),
        len(blob_table_bytes),
    )
    package_bytes = header + manifest_bytes + blob_table_bytes + b"".join(encrypted_chunks)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(package_bytes)

    return PayloadWriteResult(
        package_id=package_id,
        package_hash=sha256(package_bytes).hexdigest(),
        manifest_hash=sha256(manifest_bytes).hexdigest(),
        blob_count=len(manifest_blobs),
        output_path=output_path,
    )


def read_payload_header(path: Path) -> PayloadHeader:
    """Read only the fixed SKP header."""
    with path.open("rb") as package_file:
        header_bytes = package_file.read(HEADER_STRUCT.size)

    if len(header_bytes) != HEADER_STRUCT.size:
        raise ValueError("payload is too short to contain an SKP header")

    magic, header_version, header_length, manifest_length, blob_table_length = HEADER_STRUCT.unpack(
        header_bytes,
    )
    return PayloadHeader(
        magic=magic,
        header_version=header_version,
        header_length=header_length,
        manifest_length=manifest_length,
        blob_table_length=blob_table_length,
    )


def read_encrypted_blob_bytes(path: Path) -> dict[str, bytes]:
    """Return encrypted payload bytes keyed by blob id."""
    package_bytes = path.read_bytes()
    header = read_payload_header(path)
    _validate_payload_header(header)
    blob_table_start = header.header_length + header.manifest_length
    encrypted_start = blob_table_start + header.blob_table_length
    blob_table = json_loads_object_list(
        package_bytes[blob_table_start:encrypted_start],
        "blob table",
    )

    encrypted_blobs: dict[str, bytes] = {}
    for entry in blob_table:
        blob_id = entry.get("blob_id")
        offset = entry.get("offset")
        cipher_len = entry.get("cipher_len")
        if not isinstance(blob_id, str) or not isinstance(offset, int) or not isinstance(
            cipher_len,
            int,
        ):
            raise ValueError("payload blob table is malformed")
        start = encrypted_start + offset
        end = start + cipher_len
        if start < encrypted_start or end > len(package_bytes):
            raise ValueError("payload blob table offset is invalid")
        encrypted_blobs[blob_id] = package_bytes[start:end]
    return encrypted_blobs


def _blob_aad(
    *,
    product_id: str,
    package_id: str,
    blob_id: str,
    version: str,
    plain_sha256: str,
) -> str:
    return f"{product_id}|{package_id}|{blob_id}|{version}|{plain_sha256}"


def _validate_payload_header(header: PayloadHeader) -> None:
    if header.magic != MAGIC:
        raise ValueError("payload has an invalid magic header")
    if header.header_version != HEADER_VERSION:
        raise ValueError("payload header version is unsupported")
    if header.header_length != HEADER_STRUCT.size:
        raise ValueError("payload header length is invalid")


def json_loads_object_list(raw_bytes: bytes, description: str) -> list[dict[str, Any]]:
    value = json.loads(raw_bytes)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"payload {description} is malformed")
    return value


def _chunk_aad(blob_aad: str, chunk_index: int) -> str:
    return f"{blob_aad}|chunk|{chunk_index}"


def _fixture_nonce(options: _PayloadFixtureOptions, blob_id: str) -> bytes:
    nonce = options.nonces_by_blob_id[blob_id]
    if len(nonce) != 12:
        raise ValueError(f"fixture nonce must be 12 bytes for {blob_id}")
    return nonce
