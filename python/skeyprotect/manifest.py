"""Canonical manifest serialization for SKP payloads."""

from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(value: object) -> bytes:
    """Return compact UTF-8 JSON bytes with deterministic key ordering."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def manifest_signing_bytes(manifest: dict[str, Any]) -> bytes:
    """Return canonical bytes for the manifest state that is signed."""
    signing_manifest = dict(manifest)
    signature = dict(signing_manifest["signature"])
    signature["sig"] = ""
    signing_manifest["signature"] = signature
    return canonical_json_bytes(signing_manifest)
