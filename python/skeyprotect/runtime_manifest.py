"""Runtime manifest generation for protected release layouts."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skeyprotect import __version__
from skeyprotect.manifest import canonical_json_bytes

SCHEMA = "skey-runtime-manifest-v1"


@dataclass(frozen=True)
class RuntimeManifestFile:
    """One runtime file included in a release manifest."""

    path: str
    sha256: str
    role: str


def runtime_manifest_bytes(
    *,
    product_id: str,
    package_id: str,
    files: list[RuntimeManifestFile],
) -> bytes:
    """Return canonical runtime manifest JSON bytes."""
    return canonical_json_bytes(
        runtime_manifest(
            product_id=product_id,
            package_id=package_id,
            files=files,
        ),
    )


def runtime_manifest(
    *,
    product_id: str,
    package_id: str,
    files: list[RuntimeManifestFile],
) -> dict[str, Any]:
    """Build the runtime manifest structure."""
    return {
        "schema": SCHEMA,
        "product_id": product_id,
        "package_id": package_id,
        "runtime_version": __version__,
        "files": [
            {"path": file.path, "sha256": file.sha256, "role": file.role}
            for file in sorted(files, key=lambda item: item.path)
        ],
    }


def write_runtime_manifest(
    *,
    manifest_path: Path,
    signature_path: Path,
    product_id: str,
    package_id: str,
    files: list[RuntimeManifestFile],
    signing_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Write a canonical runtime manifest and detached Ed25519 signature."""
    manifest = runtime_manifest(product_id=product_id, package_id=package_id, files=files)
    manifest_bytes = canonical_json_bytes(manifest)
    signature = signing_key.sign(manifest_bytes)

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(manifest_bytes)
    signature_path.write_text(base64.urlsafe_b64encode(signature).decode("ascii"), encoding="ascii")
    return manifest


def runtime_file_entry(path: Path, manifest_path: str, role: str) -> RuntimeManifestFile:
    """Create a manifest entry for an on-disk runtime file."""
    return RuntimeManifestFile(
        path=manifest_path,
        sha256=sha256(path.read_bytes()).hexdigest(),
        role=role,
    )
