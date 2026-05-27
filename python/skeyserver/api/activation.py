"""Activation and offline activation routes."""

from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, HTTPException, status
from pydantic import Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from skeyserver.config import ServerSettings
from skeyserver.crypto import sign_json, verify_json
from skeyserver.schemas import StrictModel
from skeyserver.services.activations import (
    ActivationRejected,
    activate_license,
    activation_payload,
)
from skeyserver.services.audit import record_audit


class ActivationRequest(StrictModel):
    license_code: str = Field(min_length=1)
    product_id: str = Field(min_length=1)
    package_id: str = Field(min_length=1)
    device_hash: str = Field(min_length=1)
    client_pub: str = Field(min_length=1)


class OfflineRequest(StrictModel):
    product_id: str = Field(min_length=1)
    package_id: str = Field(min_length=1)
    device_hash: str = Field(min_length=1)
    client_pub: str = Field(min_length=1)


class OfflineImportRequest(StrictModel):
    license_code: str = Field(min_length=1)
    offline_request: dict[str, Any]


def _activation_failure() -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="activation rejected")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _offline_request_claims(
    *,
    payload: OfflineRequest,
    settings: ServerSettings,
    issued_at: datetime,
) -> dict[str, object]:
    return {
        "product_id": payload.product_id,
        "package_id": payload.package_id,
        "device_hash": payload.device_hash,
        "client_pub": payload.client_pub,
        "issued_at": _isoformat(issued_at),
        "issuer": settings.issuer,
    }


def _verified_offline_request_fields(
    *,
    signed_request: dict[str, Any],
    settings: ServerSettings,
    signing_key: Ed25519PrivateKey,
) -> dict[str, str]:
    if "signature" in signed_request:
        verify_json(signed_request, signing_key.public_key())
        if signed_request.get("issuer") != settings.issuer or signed_request.get("kid") != settings.signing_key_id:
            raise ValueError("offline request is invalid")
    elif signed_request.get("schema") != "skey-offline-request-v1":
        raise ValueError("offline request is invalid")
    fields: dict[str, str] = {}
    for field_name in ("product_id", "package_id", "device_hash", "client_pub"):
        value = signed_request.get(field_name)
        if not isinstance(value, str) or not value:
            raise ValueError("offline request is invalid")
        fields[field_name] = value
    issued_at = signed_request.get("issued_at")
    if not isinstance(issued_at, str) or not issued_at:
        raise ValueError("offline request is invalid")
    return fields


def build_router(
    settings: ServerSettings,
    session_factory: sessionmaker[Session],
    signing_key: Ed25519PrivateKey,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["activation"])

    @router.post("/activate")
    def activate_route(payload: ActivationRequest) -> dict[str, object]:
        with session_factory() as session:
            try:
                activation = activate_license(
                    session,
                    settings=settings,
                    signing_key=signing_key,
                    license_code=payload.license_code,
                    product_id=payload.product_id,
                    package_id=payload.package_id,
                    device_hash=payload.device_hash,
                    client_pub=payload.client_pub,
                )
                record_audit(
                    session,
                    action="activation.created",
                    entity_type="activation",
                    entity_id=activation.activation_id,
                    detail_json={"product_id": activation.product_id, "package_id": activation.package_id},
                )
                session.commit()
            except (ActivationRejected, IntegrityError, ValueError) as exc:
                session.rollback()
                raise _activation_failure() from exc
            return {"activation": activation_payload(activation)}

    @router.post("/offline/request")
    def offline_request_route(payload: OfflineRequest) -> dict[str, object]:
        with session_factory() as session:
            record_audit(
                session,
                action="offline.request.created",
                entity_type="offline_request",
                entity_id=f"{payload.product_id}:{payload.package_id}:{payload.device_hash}",
                detail_json={
                    "product_id": payload.product_id,
                    "package_id": payload.package_id,
                    "device_hash": payload.device_hash,
                    "client_pub": payload.client_pub,
                },
            )
            session.commit()
        return {
            "offline_request": sign_json(
                _offline_request_claims(payload=payload, settings=settings, issued_at=_utcnow()),
                signing_key,
                settings.signing_key_id,
            ),
        }

    @router.post("/offline/import")
    def offline_import_route(payload: OfflineImportRequest) -> dict[str, object]:
        try:
            request_fields = _verified_offline_request_fields(
                signed_request=payload.offline_request,
                settings=settings,
                signing_key=signing_key,
            )
        except ValueError as exc:
            raise _activation_failure() from exc
        with session_factory() as session:
            try:
                activation = activate_license(
                    session,
                    settings=settings,
                    signing_key=signing_key,
                    license_code=payload.license_code,
                    product_id=request_fields["product_id"],
                    package_id=request_fields["package_id"],
                    device_hash=request_fields["device_hash"],
                    client_pub=request_fields["client_pub"],
                )
                issued_at = _isoformat(_utcnow())
                offline_response = sign_json(
                    {
                        "activation_cert": activation.cert_json,
                        "server_time": issued_at,
                        "issued_at": issued_at,
                        "issuer": settings.issuer,
                    },
                    signing_key,
                    settings.signing_key_id,
                )
                record_audit(
                    session,
                    action="offline.imported",
                    entity_type="activation",
                    entity_id=activation.activation_id,
                    detail_json={"product_id": activation.product_id, "package_id": activation.package_id},
                )
                session.commit()
            except (ActivationRejected, IntegrityError, ValueError) as exc:
                session.rollback()
                raise _activation_failure() from exc
            return {"offline_response": offline_response}

    return router
