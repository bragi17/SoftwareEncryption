"""License service functions."""

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from skeyserver.models import Feature, License, LicenseFeature, hash_license_code


def create_license(
    session: Session,
    *,
    server_secret: str | bytes,
    license_id: str,
    product_id: str,
    license_code: str,
    customer_id: str | None,
    max_activations: int,
    expire_at: datetime,
    status: str,
) -> License:
    license_row = License(
        license_id=license_id,
        product_id=product_id,
        customer_id=customer_id,
        code_hash=hash_license_code(server_secret, license_code),
        max_activations=max_activations,
        expire_at=expire_at,
        status=status,
    )
    session.add(license_row)
    session.flush()
    return license_row


def find_license_by_code(
    session: Session,
    *,
    server_secret: str | bytes,
    product_id: str,
    license_code: str,
) -> License | None:
    code_hash = hash_license_code(server_secret, license_code)
    return session.scalar(
        select(License).where(License.product_id == product_id, License.code_hash == code_hash),
    )


def get_license(session: Session, *, product_id: str, license_id: str) -> License | None:
    return session.scalar(
        select(License).where(License.product_id == product_id, License.license_id == license_id),
    )


def set_license_feature(
    session: Session,
    *,
    product_id: str,
    license_id: str,
    feature: Feature,
    enabled: bool,
) -> LicenseFeature:
    existing = session.scalar(
        select(LicenseFeature).where(
            LicenseFeature.product_id == product_id,
            LicenseFeature.license_id == license_id,
            LicenseFeature.feature_id == feature.id,
        ),
    )
    if existing is not None:
        existing.enabled = enabled
        session.flush()
        return existing
    license_feature = LicenseFeature(
        product_id=product_id,
        license_id=license_id,
        feature=feature,
        enabled=enabled,
    )
    session.add(license_feature)
    session.flush()
    return license_feature


def enabled_feature_codes(license_row: License) -> list[str]:
    return sorted(
        license_feature.feature.code
        for license_feature in license_row.features
        if license_feature.enabled
    )


def enabled_feature_claims(license_row: License) -> list[dict[str, object]]:
    return [{"code": code, "enabled": True} for code in enabled_feature_codes(license_row)]
