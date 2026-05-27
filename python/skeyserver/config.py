"""Configuration values for the license server."""

import base64
import binascii
from typing import ClassVar

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_DEV_PACKAGE_KEK_B64 = base64.urlsafe_b64encode(b"dev-only-package-kek-32-bytes!!!").decode("ascii")


def _decode_32_byte_b64(value: str, field_name: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field_name} must be valid URL-safe base64") from exc
    if len(decoded) != 32:
        raise ValueError(f"{field_name} must decode to 32 bytes")
    return decoded


class ServerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SKEY_SERVER_", extra="ignore")

    dev_package_kek_b64: ClassVar[str] = _DEV_PACKAGE_KEK_B64

    database_url: str = "sqlite:///skeyserver.db"
    server_secret: str | None = Field(default=None, min_length=1)
    allow_dev_secret: bool = False
    admin_token: str | None = Field(default=None, min_length=1)
    issuer: str = Field(default="skey-server", min_length=1)
    signing_key_id: str = Field(default="dev-signing-key", min_length=1)
    signing_private_key_b64: str | None = None
    package_kek_b64: str | None = None
    lease_hours: int = Field(default=720, ge=1)
    offline_grace_hours: int = Field(default=168, ge=0)
    device_pass_score: int = Field(default=70, ge=0, le=100)
    device_review_score: int = Field(default=50, ge=0, le=100)

    @model_validator(mode="after")
    def require_explicit_secret(self) -> "ServerSettings":
        if self.server_secret is None:
            if not self.allow_dev_secret:
                raise ValueError("server_secret must be configured unless allow_dev_secret is true")
            self.server_secret = "dev-only-change-me"
        if self.admin_token is None:
            if not self.allow_dev_secret:
                raise ValueError("admin_token must be configured unless allow_dev_secret is true")
            self.admin_token = "dev-admin-token"
        if self.signing_private_key_b64 is None and not self.allow_dev_secret:
            raise ValueError("signing_private_key_b64 must be configured unless allow_dev_secret is true")
        if self.package_kek_b64 is None:
            if not self.allow_dev_secret:
                raise ValueError("package_kek_b64 must be configured unless allow_dev_secret is true")
            self.package_kek_b64 = self.dev_package_kek_b64
        _decode_32_byte_b64(self.package_kek_b64, "package_kek_b64")
        return self


def load_settings() -> ServerSettings:
    return ServerSettings()
