"""Typed configuration for software-dongle protection."""

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _require_non_blank(value: str, field_name: str) -> str:
    if not value.strip():
        raise ValueError(f"{field_name} must be non-empty")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProductConfig(StrictModel):
    id: str
    name: str
    version: str

    @field_validator("id", "version")
    @classmethod
    def require_non_empty(cls, value: str) -> str:
        return _require_non_blank(value, "product value")


class ServerConfig(StrictModel):
    activation_url: str
    public_key_id: str


class CryptoConfig(StrictModel):
    aead: str
    kdf: str
    signature: str


class ProtectionConfig(StrictModel):
    package_file: str
    crypto: CryptoConfig


class PythonEntry(StrictModel):
    path: str
    feature: str

    @field_validator("feature")
    @classmethod
    def require_non_empty_feature(cls, value: str) -> str:
        return _require_non_blank(value, "feature")


class PythonModules(StrictModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class PythonConfig(StrictModel):
    enabled: bool
    entries: list[PythonEntry] = Field(default_factory=list)
    modules: PythonModules
    hidden_imports: list[str] = Field(default_factory=list)


class ExeEntry(StrictModel):
    path: str
    feature: str
    materialize: str
    include_deps: list[str] = Field(default_factory=list)

    @field_validator("feature")
    @classmethod
    def require_non_empty_feature(cls, value: str) -> str:
        return _require_non_blank(value, "feature")


class ExeConfig(StrictModel):
    enabled: bool
    entries: list[ExeEntry] = Field(default_factory=list)


class JarEntry(StrictModel):
    path: str
    feature: str
    mode: str
    java_runtime: str

    @field_validator("feature")
    @classmethod
    def require_non_empty_feature(cls, value: str) -> str:
        return _require_non_blank(value, "feature")


class JarConfig(StrictModel):
    enabled: bool
    entries: list[JarEntry] = Field(default_factory=list)


class ResourceEntry(StrictModel):
    path: str
    feature: str
    mode: str

    @field_validator("feature")
    @classmethod
    def require_non_empty_feature(cls, value: str) -> str:
        return _require_non_blank(value, "feature")

    @field_validator("mode")
    @classmethod
    def require_known_mode(cls, value: str) -> str:
        value = _require_non_blank(value, "resource mode")
        if value not in {"materialize_on_session", "stream_api"}:
            raise ValueError("resource mode must be materialize_on_session or stream_api")
        return value


class ResourceConfig(StrictModel):
    entries: list[ResourceEntry] = Field(default_factory=list)


class MachineBindingConfig(StrictModel):
    pass_score: int = Field(ge=0, le=100)
    review_score: int = Field(ge=0, le=100)


class TimeConfig(StrictModel):
    lease_hours: int = Field(gt=0)
    offline_grace_hours: int = Field(ge=0)
    perpetual: bool = False


class LicenseConfig(StrictModel):
    default_features: list[str] = Field(default_factory=list)
    machine_binding: MachineBindingConfig
    time: TimeConfig

    @field_validator("default_features")
    @classmethod
    def require_non_empty_features(cls, value: list[str]) -> list[str]:
        if any(not feature.strip() for feature in value):
            raise ValueError("feature values must be non-empty")
        return value


class SecurityConfig(StrictModel):
    vendor_public_key_b64: str | None = None
    build_signing_private_key_b64: str | None = None
    build_signing_private_key_file: str | None = None
    allow_unsafe_dev_signing_key: bool = False

    @field_validator(
        "vendor_public_key_b64",
        "build_signing_private_key_b64",
        "build_signing_private_key_file",
    )
    @classmethod
    def require_non_empty_optional(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _require_non_blank(value, "security value")

    @model_validator(mode="after")
    def require_single_private_key_source(self) -> "SecurityConfig":
        if self.build_signing_private_key_b64 and self.build_signing_private_key_file:
            raise ValueError(
                "only one of build_signing_private_key_b64 or build_signing_private_key_file may be set",
            )
        return self


class SKeyConfig(StrictModel):
    product: ProductConfig
    server: ServerConfig
    protection: ProtectionConfig
    python: PythonConfig
    exe: ExeConfig
    jar: JarConfig
    resources: ResourceConfig
    license: LicenseConfig
    security: SecurityConfig = Field(default_factory=SecurityConfig)


def load_config(path: Path) -> SKeyConfig:
    with path.open("r", encoding="utf-8") as config_file:
        raw_config: Any = yaml.safe_load(config_file)

    if not isinstance(raw_config, dict):
        raise ValueError(f"config must be a mapping: {path}")

    return SKeyConfig.model_validate(raw_config)
