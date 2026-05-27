"""Lease refresh service functions."""

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from skeyserver.config import ServerSettings
from skeyserver.models import Activation, Revocation
from skeyserver.services.activations import activation_payload, sign_activation_certificate


class LeaseRefreshRejected(ValueError):
    """Raised when a lease cannot be refreshed."""


def refresh_lease(
    session: Session,
    *,
    settings: ServerSettings,
    signing_key: Ed25519PrivateKey,
    product_id: str,
    package_id: str,
    activation_id: str,
    device_hash: str,
) -> Activation:
    activation = session.scalar(
        select(Activation).where(
            Activation.product_id == product_id,
            Activation.package_id == package_id,
            Activation.activation_id == activation_id,
            Activation.device_hash == device_hash,
            Activation.status == "active",
        ),
    )
    if activation is None:
        raise LeaseRefreshRejected("lease refresh rejected")
    matching_revocation = session.scalar(
        select(Revocation.id).where(
            Revocation.product_id == activation.product_id,
            Revocation.license_id == activation.license_id,
            (Revocation.activation_id.is_(None)) | (Revocation.activation_id == activation.activation_id),
        ),
    )
    if matching_revocation is not None:
        raise LeaseRefreshRejected("lease refresh rejected")

    wrapped_pkg_key = activation.cert_json.get("wrapped_pkg_key")
    if not isinstance(wrapped_pkg_key, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in wrapped_pkg_key.items()
    ):
        raise LeaseRefreshRejected("lease refresh rejected")

    activation.lease_until = datetime.now(UTC) + timedelta(hours=settings.lease_hours)
    activation.cert_json = sign_activation_certificate(
        settings=settings,
        signing_key=signing_key,
        license_row=activation.license,
        package_row=activation.package,
        activation_id=activation.activation_id,
        device_hash=activation.device_hash,
        lease_until=activation.lease_until,
        wrapped_pkg_key=wrapped_pkg_key,
    )
    session.flush()
    return activation


def lease_payload(activation: Activation) -> dict[str, object]:
    payload = activation_payload(activation)
    payload.pop("license_id", None)
    payload.pop("device_hash", None)
    return payload
