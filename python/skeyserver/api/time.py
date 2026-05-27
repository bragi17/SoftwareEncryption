"""Trusted server time route."""

from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter
from sqlalchemy.orm import Session, sessionmaker

from skeyserver.config import ServerSettings
from skeyserver.crypto import sign_json
from skeyserver.services.audit import record_audit


def _isoformat(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def build_router(
    settings: ServerSettings,
    session_factory: sessionmaker[Session],
    signing_key: Ed25519PrivateKey,
) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["time"])

    @router.get("/time")
    def get_time() -> dict[str, object]:
        now = datetime.now(UTC)
        signed_time = sign_json(
            {
                "schema": "skey-server-time-v1",
                "server_time": _isoformat(now),
                "issued_at": _isoformat(now),
                "issuer": settings.issuer,
            },
            signing_key,
            settings.signing_key_id,
        )
        with session_factory() as session:
            record_audit(
                session,
                action="time.signed",
                entity_type="server_time",
                entity_id=_isoformat(now),
            )
            session.commit()
        return {"server_time": signed_time}

    return router
