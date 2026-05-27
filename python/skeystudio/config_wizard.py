"""Operator-friendly config generation helpers for SKey Studio."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


@dataclass(frozen=True)
class ConfigWizardDraft:
    product_id: str
    product_name: str
    product_version: str
    activation_url: str
    python_entry: str
    python_module_includes: list[str]
    python_module_excludes: list[str]
    lease_hours: int
    offline_grace_hours: int
    allow_unsafe_dev_signing_key: bool
    perpetual_license: bool = False


def config_dict_from_draft(draft: ConfigWizardDraft) -> dict[str, Any]:
    python_entry = draft.python_entry.strip().replace("\\", "/")
    python_entries = []
    default_features: list[str] = []
    if python_entry:
        feature = feature_code_for_path(python_entry)
        python_entries.append({"path": python_entry, "feature": feature})
        default_features.append(feature)

    return {
        "product": {
            "id": draft.product_id.strip(),
            "name": draft.product_name.strip(),
            "version": draft.product_version.strip(),
        },
        "server": {
            "activation_url": draft.activation_url.strip(),
            "public_key_id": "vendor_sign_2026_01",
        },
        "security": {
            "vendor_public_key_b64": None,
            "build_signing_private_key_file": None,
            "build_signing_private_key_b64": None,
            "allow_unsafe_dev_signing_key": draft.allow_unsafe_dev_signing_key,
        },
        "protection": {
            "package_file": ".secure/payload.skp",
            "crypto": {
                "aead": "AES-256-GCM",
                "kdf": "HKDF-SHA256",
                "signature": "Ed25519",
            },
        },
        "python": {
            "enabled": bool(python_entries),
            "entries": python_entries,
            "modules": {
                "include": draft.python_module_includes,
                "exclude": draft.python_module_excludes,
            },
            "hidden_imports": [],
        },
        "exe": {"enabled": False, "entries": []},
        "jar": {"enabled": False, "entries": []},
        "resources": {"entries": []},
        "license": {
            "default_features": default_features,
            "machine_binding": {"pass_score": 70, "review_score": 50},
            "time": {
                "lease_hours": draft.lease_hours,
                "offline_grace_hours": draft.offline_grace_hours,
                "perpetual": draft.perpetual_license,
            },
        },
    }


def feature_code_for_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    if posix_path.name == "__init__.py" and posix_path.parent != PurePosixPath("."):
        base = posix_path.parent.name
    else:
        base = posix_path.stem or posix_path.name

    token = re.sub(r"[^A-Za-z0-9]+", "_", base).strip("_").upper()
    return f"RUN_{token or 'APP'}"
