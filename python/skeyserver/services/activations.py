"""Activation certificate service functions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session

from skeyserver.config import ServerSettings
from skeyserver.crypto import decrypt_package_key_at_rest, load_package_kek, sign_json, wrap_package_key
from skeyserver.models import (
    Activation,
    ActivationCapacityExceeded,
    License,
    Package,
    create_activation_record,
)
from skeyserver.services.licenses import enabled_feature_claims, find_license_by_code
from skeyserver.services.packages import get_package


class ActivationRejected(ValueError):
    """Raised for generic activation failures that should not leak lookup details."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _isoformat(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _certificate_claims(
    *,
    settings: ServerSettings,
    license_row: License,
    package_row: Package,
    activation_id: str,
    device_hash: str,
    features: list[dict[str, object]],
    lease_until: datetime,
    wrapped_pkg_key: dict[str, str],
    issued_at: datetime,
) -> dict[str, object]:
    return {
        "cert_version": 1,
        "license_id": license_row.license_id,
        "activation_id": activation_id,
        "product_id": license_row.product_id,
        "package_id": package_row.package_id,
        "package_hash": package_row.package_hash,
        "customer_id": license_row.customer_id,
        "device_hash": device_hash,
        "device_score_policy": {
            "pass_score": settings.device_pass_score,
            "review_score": settings.device_review_score,
        },
        "features": features,
        "not_before": _isoformat(issued_at),
        "expire_at": _isoformat(license_row.expire_at),
        "lease_until": _isoformat(lease_until),
        "offline_grace_hours": settings.offline_grace_hours,
        "wrapped_pkg_key": wrapped_pkg_key,
        "issued_at": _isoformat(issued_at),
        "issuer": settings.issuer,
    }


def sign_activation_certificate(
    *,
    settings: ServerSettings,
    signing_key: Ed25519PrivateKey,
    license_row: License,
    package_row: Package,
    activation_id: str,
    device_hash: str,
    lease_until: datetime,
    wrapped_pkg_key: dict[str, str],
) -> dict[str, object]:
    claims = _certificate_claims(
        settings=settings,
        license_row=license_row,
        package_row=package_row,
        activation_id=activation_id,
        device_hash=device_hash,
        features=enabled_feature_claims(license_row),
        lease_until=lease_until,
        wrapped_pkg_key=wrapped_pkg_key,
        issued_at=_utcnow(),
    )
    return sign_json(claims, signing_key, settings.signing_key_id)


def activate_license(
    session: Session,
    *,
    settings: ServerSettings,
    signing_key: Ed25519PrivateKey,
    license_code: str,
    product_id: str,
    package_id: str,
    device_hash: str,
    client_pub: str,
) -> Activation:
    license_row = find_license_by_code(
        session,
        server_secret=settings.server_secret or "",
        product_id=product_id,
        license_code=license_code,
    )
    package_row = get_package(session, product_id=product_id, package_id=package_id)
    now = _utcnow()
    if (
        license_row is None
        or package_row is None
        or license_row.status != "active"
        or _as_utc(license_row.expire_at) <= now
    ):
        raise ActivationRejected("activation rejected")

    lease_until = now + timedelta(hours=settings.lease_hours)
    activation_id = f"ACT-{uuid4().hex}"
    try:
        package_key = decrypt_package_key_at_rest(
            package_row.encrypted_pkg_key,
            package_kek=load_package_kek(settings.package_kek_b64),
            product_id=package_row.product_id,
            package_id=package_row.package_id,
            package_hash=package_row.package_hash,
        )
    except ValueError as exc:
        raise ActivationRejected("activation rejected") from exc
    wrapped_pkg_key = wrap_package_key(package_key, client_pub)
    cert_json = sign_activation_certificate(
        settings=settings,
        signing_key=signing_key,
        license_row=license_row,
        package_row=package_row,
        activation_id=activation_id,
        device_hash=device_hash,
        lease_until=lease_until,
        wrapped_pkg_key=wrapped_pkg_key,
    )
    try:
        activation = create_activation_record(
            session=session,
            license_row=license_row,
            package_row=package_row,
            activation_id=activation_id,
            device_hash=device_hash,
            client_pub=client_pub,
            cert_json=cert_json,
            lease_until=lease_until,
        )
    except ActivationCapacityExceeded as exc:
        raise ActivationRejected("activation rejected") from exc
    return activation


def activation_payload(activation: Activation) -> dict[str, object]:
    return {
        "activation_id": activation.activation_id,
        "license_id": activation.license_id,
        "product_id": activation.product_id,
        "package_id": activation.package_id,
        "device_hash": activation.device_hash,
        "lease_until": _isoformat(activation.lease_until) if activation.lease_until is not None else None,
        "cert": activation.cert_json,
    }
