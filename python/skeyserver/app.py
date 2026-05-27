"""FastAPI application factory for the software-dongle license server."""

import argparse

from fastapi import FastAPI

from skeyserver.api import activation, admin, lease, revocation, time
from skeyserver.config import ServerSettings, load_settings
from skeyserver.crypto import load_ed25519_private_key
from skeyserver.database import Base, create_database_engine, create_session_factory


def create_app(settings: ServerSettings | None = None) -> FastAPI:
    server_settings = settings or load_settings()
    engine = create_database_engine(server_settings.database_url)
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    signing_key = load_ed25519_private_key(server_settings.signing_private_key_b64)

    app = FastAPI(title="SKey License Server")
    app.include_router(admin.build_router(server_settings, session_factory))
    app.include_router(activation.build_router(server_settings, session_factory, signing_key))
    app.include_router(lease.build_router(server_settings, session_factory, signing_key))
    app.include_router(revocation.build_router(server_settings, session_factory, signing_key))
    app.include_router(time.build_router(server_settings, session_factory, signing_key))
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SKey license server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    import uvicorn

    uvicorn.run(create_app(load_settings()), host=args.host, port=args.port)
