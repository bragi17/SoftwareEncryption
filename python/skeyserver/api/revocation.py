"""Revocation list routes."""

from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter
from pydantic import Field
from sqlalchemy.orm import Session, sessionmaker

from skeyserver.config import ServerSettings
from skeyserver.crypto import sign_json
from skeyserver.schemas import StrictModel
from skeyserver.services.audit import record_audit
from skeyserver.services.revocations import revocations_for_package


class RevocationQuery(StrictModel):
    product_id: str = Field(min_length=1)
    package_id: str = Field(min_length=1)


def _isoformat(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def build_router(
    settings: ServerSettings,
    session_factory: sessionmaker[Session],
    signing_key: Ed25519PrivateKey,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["revocations"])

    @router.get("/revocations")
    def get_revocations(product_id: str, package_id: str) -> dict[str, object]:
        query = RevocationQuery(product_id=product_id, package_id=package_id)
        with session_factory() as session:
            rows = revocations_for_package(
                session,
                product_id=query.product_id,
                package_id=query.package_id,
            )
            record_audit(
                session,
                action="revocations.read",
                entity_type="package",
                entity_id=query.package_id,
                detail_json={"product_id": query.product_id, "count": len(rows)},
            )
            session.commit()
        issued_at = _isoformat(datetime.now(UTC))
        signed_revocations = sign_json(
            {
                "schema": "skey-revocations-v1",
                "product_id": query.product_id,
                "package_id": query.package_id,
                "revocations": rows,
                "issued_at": issued_at,
                "issuer": settings.issuer,
            },
            signing_key,
            settings.signing_key_id,
        )
        return {"revocations": signed_revocations}

    return router
