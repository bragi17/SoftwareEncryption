"""Package service functions."""

import base64
import binascii

from sqlalchemy import select
from sqlalchemy.orm import Session

from skeyserver.crypto import encrypt_package_key_at_rest, load_package_kek
from skeyserver.models import Package


def _decode_package_key(package_key_b64: str) -> bytes:
    padding = "=" * (-len(package_key_b64) % 4)
    try:
        package_key = base64.urlsafe_b64decode((package_key_b64 + padding).encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("package_key_b64 must be valid URL-safe base64") from exc
    if len(package_key) != 32:
        raise ValueError("package_key_b64 must decode to 32 bytes")
    return package_key


def create_package(
    session: Session,
    *,
    product_id: str,
    package_id: str,
    package_hash: str,
    version: str,
    package_key_b64: str,
    package_kek_b64: str | None,
) -> Package:
    package_key = _decode_package_key(package_key_b64)
    package_kek = load_package_kek(package_kek_b64)
    package = Package(
        product_id=product_id,
        package_id=package_id,
        package_hash=package_hash,
        version=version,
        encrypted_pkg_key=encrypt_package_key_at_rest(
            package_key,
            package_kek=package_kek,
            product_id=product_id,
            package_id=package_id,
            package_hash=package_hash,
        ),
    )
    session.add(package)
    session.flush()
    return package


def get_package(session: Session, *, product_id: str, package_id: str) -> Package | None:
    return session.scalar(
        select(Package).where(Package.product_id == product_id, Package.package_id == package_id),
    )
