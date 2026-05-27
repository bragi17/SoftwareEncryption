"""Revocation service functions."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from skeyserver.models import Activation, License, Revocation


def create_revocation(
    session: Session,
    *,
    product_id: str,
    license_id: str,
    activation_id: str | None,
    reason: str | None,
) -> Revocation:
    if activation_id is None:
        license_row = session.scalar(
            select(License).where(License.product_id == product_id, License.license_id == license_id),
        )
        if license_row is not None:
            license_row.status = "revoked"
        activations = session.scalars(
            select(Activation).where(
                Activation.product_id == product_id,
                Activation.license_id == license_id,
                Activation.status != "revoked",
            ),
        ).all()
        for activation_row in activations:
            activation_row.status = "revoked"
    else:
        matched_activation = session.scalar(
            select(Activation).where(
                Activation.product_id == product_id,
                Activation.license_id == license_id,
                Activation.activation_id == activation_id,
            ),
        )
        if matched_activation is not None:
            matched_activation.status = "revoked"
    revocation = Revocation(
        product_id=product_id,
        license_id=license_id,
        activation_id=activation_id,
        reason=reason,
    )
    session.add(revocation)
    session.flush()
    return revocation


def _isoformat(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def revocations_for_package(
    session: Session,
    *,
    product_id: str,
    package_id: str,
) -> list[dict[str, object]]:
    rows = session.scalars(
        select(Revocation)
        .outerjoin(
            Activation,
            (Revocation.product_id == Activation.product_id)
            & (Revocation.license_id == Activation.license_id)
            & (Revocation.activation_id == Activation.activation_id),
        )
        .where(
            Revocation.product_id == product_id,
            (Revocation.activation_id.is_(None) | (Activation.package_id == package_id)),
        )
        .order_by(Revocation.id),
    ).all()
    return [
        {
            "license_id": row.license_id,
            "activation_id": row.activation_id,
            "reason": row.reason,
            "revoked_at": _isoformat(row.revoked_at),
        }
        for row in rows
    ]
