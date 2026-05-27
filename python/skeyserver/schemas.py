"""Pydantic shapes shared by license-server persistence code."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LicenseRecordInput(StrictModel):
    license_id: str
    product_id: str
    code_hash: str = Field(min_length=64, max_length=64)
    customer_id: str | None = None
    max_activations: int = Field(default=1, ge=1)
    expire_at: datetime
    status: Literal["active", "suspended", "expired", "revoked"] = "active"


class ActivationRecordInput(StrictModel):
    activation_id: str
    product_id: str
    license_id: str
    package_id: str
    slot_index: int = Field(ge=1)
    device_hash: str
    client_pub: str
    cert_json: dict[str, Any]
    lease_until: datetime | None = None
    status: Literal["active", "expired", "revoked"] = "active"
