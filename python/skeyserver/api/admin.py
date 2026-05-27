"""Administrative API routes."""

import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from skeyserver.config import ServerSettings
from skeyserver.schemas import StrictModel
from skeyserver.services.audit import record_audit
from skeyserver.services.licenses import create_license, get_license, set_license_feature
from skeyserver.services.packages import create_package
from skeyserver.services.products import create_feature, create_product, get_feature
from skeyserver.services.revocations import create_revocation


class ProductCreate(StrictModel):
    id: str
    name: str
    version: str


class FeatureCreate(StrictModel):
    product_id: str
    code: str
    name: str


class PackageCreate(StrictModel):
    product_id: str
    package_id: str
    package_hash: str
    version: str
    package_key_b64: str


class LicenseCreate(StrictModel):
    license_id: str
    product_id: str
    license_code: str
    customer_id: str | None = None
    max_activations: int = Field(default=1, ge=1)
    expire_at: datetime
    status: str = "active"


class LicenseFeatureCreate(StrictModel):
    product_id: str
    feature_code: str
    enabled: bool = True


class RevocationCreate(StrictModel):
    product_id: str
    license_id: str
    activation_id: str | None = None
    reason: str | None = None


def _require_admin(settings: ServerSettings, token: str | None) -> None:
    admin_token = settings.admin_token
    if (
        token is None
        or admin_token is None
        or not secrets.compare_digest(token.encode("utf-8"), admin_token.encode("utf-8"))
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid admin token")


@contextmanager
def _admin_record_transaction(session: Session) -> Iterator[None]:
    try:
        yield
        session.commit()
    except (IntegrityError, ValueError) as exc:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid admin record") from exc


def build_router(settings: ServerSettings, session_factory: sessionmaker[Session]) -> APIRouter:
    router = APIRouter(prefix="/v1/admin", tags=["admin"])

    @router.post("/products")
    def create_product_route(
        payload: ProductCreate,
        x_admin_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(settings, x_admin_token)
        with session_factory() as session:
            with _admin_record_transaction(session):
                product = create_product(
                    session,
                    product_id=payload.id,
                    name=payload.name,
                    version=payload.version,
                )
                record_audit(
                    session,
                    action="admin.product.created",
                    entity_type="product",
                    entity_id=product.id,
                    actor="admin",
                )
            return {"id": product.id, "name": product.name, "version": product.version}

    @router.post("/features")
    def create_feature_route(
        payload: FeatureCreate,
        x_admin_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(settings, x_admin_token)
        with session_factory() as session:
            with _admin_record_transaction(session):
                feature = create_feature(
                    session,
                    product_id=payload.product_id,
                    code=payload.code,
                    name=payload.name,
                )
                record_audit(
                    session,
                    action="admin.feature.created",
                    entity_type="feature",
                    entity_id=feature.code,
                    actor="admin",
                    detail_json={"product_id": feature.product_id},
                )
            return {"id": feature.id, "product_id": feature.product_id, "code": feature.code}

    @router.post("/packages")
    def create_package_route(
        payload: PackageCreate,
        x_admin_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(settings, x_admin_token)
        with session_factory() as session:
            with _admin_record_transaction(session):
                package = create_package(
                    session,
                    product_id=payload.product_id,
                    package_id=payload.package_id,
                    package_hash=payload.package_hash,
                    version=payload.version,
                    package_key_b64=payload.package_key_b64,
                    package_kek_b64=settings.package_kek_b64,
                )
                record_audit(
                    session,
                    action="admin.package.created",
                    entity_type="package",
                    entity_id=package.package_id,
                    actor="admin",
                    detail_json={"product_id": package.product_id},
                )
            return {
                "product_id": package.product_id,
                "package_id": package.package_id,
                "package_hash": package.package_hash,
            }

    @router.post("/licenses")
    def create_license_route(
        payload: LicenseCreate,
        x_admin_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(settings, x_admin_token)
        with session_factory() as session:
            with _admin_record_transaction(session):
                license_row = create_license(
                    session,
                    server_secret=settings.server_secret or "",
                    license_id=payload.license_id,
                    product_id=payload.product_id,
                    license_code=payload.license_code,
                    customer_id=payload.customer_id,
                    max_activations=payload.max_activations,
                    expire_at=payload.expire_at,
                    status=payload.status,
                )
                record_audit(
                    session,
                    action="admin.license.created",
                    entity_type="license",
                    entity_id=license_row.license_id,
                    actor="admin",
                    detail_json={"product_id": license_row.product_id},
                )
            return {
                "license_id": license_row.license_id,
                "product_id": license_row.product_id,
                "max_activations": license_row.max_activations,
            }

    @router.post("/licenses/{license_id}/features")
    def attach_license_feature_route(
        license_id: str,
        payload: LicenseFeatureCreate,
        x_admin_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(settings, x_admin_token)
        with session_factory() as session:
            with _admin_record_transaction(session):
                license_row = get_license(session, product_id=payload.product_id, license_id=license_id)
                feature = get_feature(session, product_id=payload.product_id, code=payload.feature_code)
                if license_row is None or feature is None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="admin record not found")
                license_feature = set_license_feature(
                    session,
                    product_id=payload.product_id,
                    license_id=license_id,
                    feature=feature,
                    enabled=payload.enabled,
                )
                record_audit(
                    session,
                    action="admin.license_feature.updated",
                    entity_type="license",
                    entity_id=license_id,
                    actor="admin",
                    detail_json={"feature_code": payload.feature_code, "enabled": payload.enabled},
                )
            return {
                "license_id": license_feature.license_id,
                "feature_code": payload.feature_code,
                "enabled": license_feature.enabled,
            }

    @router.post("/revocations")
    def create_revocation_route(
        payload: RevocationCreate,
        x_admin_token: str | None = Header(default=None),
    ) -> dict[str, object]:
        _require_admin(settings, x_admin_token)
        with session_factory() as session:
            with _admin_record_transaction(session):
                revocation = create_revocation(
                    session,
                    product_id=payload.product_id,
                    license_id=payload.license_id,
                    activation_id=payload.activation_id,
                    reason=payload.reason,
                )
                record_audit(
                    session,
                    action="admin.revocation.created",
                    entity_type="revocation",
                    entity_id=str(revocation.id),
                    actor="admin",
                    detail_json={"license_id": revocation.license_id},
                )
            return {
                "id": revocation.id,
                "product_id": revocation.product_id,
                "license_id": revocation.license_id,
                "activation_id": revocation.activation_id,
            }

    return router
