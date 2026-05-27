"""Lease refresh routes."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, HTTPException, status
from pydantic import Field
from sqlalchemy.orm import Session, sessionmaker

from skeyserver.config import ServerSettings
from skeyserver.schemas import StrictModel
from skeyserver.services.audit import record_audit
from skeyserver.services.leases import LeaseRefreshRejected, lease_payload, refresh_lease


class LeaseRefreshRequest(StrictModel):
    product_id: str = Field(min_length=1)
    package_id: str = Field(min_length=1)
    activation_id: str = Field(min_length=1)
    device_hash: str = Field(min_length=1)


def build_router(
    settings: ServerSettings,
    session_factory: sessionmaker[Session],
    signing_key: Ed25519PrivateKey,
) -> APIRouter:
    router = APIRouter(prefix="/v1/lease", tags=["lease"])

    @router.post("/refresh")
    def refresh_lease_route(payload: LeaseRefreshRequest) -> dict[str, object]:
        with session_factory() as session:
            try:
                activation = refresh_lease(
                    session,
                    settings=settings,
                    signing_key=signing_key,
                    product_id=payload.product_id,
                    package_id=payload.package_id,
                    activation_id=payload.activation_id,
                    device_hash=payload.device_hash,
                )
                record_audit(
                    session,
                    action="lease.refreshed",
                    entity_type="activation",
                    entity_id=activation.activation_id,
                    detail_json={"product_id": activation.product_id, "package_id": activation.package_id},
                )
                session.commit()
            except LeaseRefreshRejected as exc:
                session.rollback()
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="lease refresh rejected",
                ) from exc
            return lease_payload(activation)

    return router
