"""SQLAlchemy models for license-server persistence."""

from __future__ import annotations

from datetime import datetime
import hashlib
import hmac
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    JSON,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from skeyserver.database import Base

JsonObject = dict[str, Any]
LICENSE_STATUSES = ("active", "suspended", "expired", "revoked")
ACTIVATION_STATUSES = ("active", "expired", "revoked")


class ActivationCapacityExceeded(ValueError):
    """Raised when a license has no remaining activation capacity."""


class Product(Base):
    __tablename__ = "products"
    __table_args__ = (
        CheckConstraint("length(trim(id)) > 0", name="ck_products_id_non_empty"),
        CheckConstraint("length(trim(name)) > 0", name="ck_products_name_non_empty"),
        CheckConstraint("length(trim(version)) > 0", name="ck_products_version_non_empty"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    features: Mapped[list[Feature]] = relationship(back_populates="product")
    packages: Mapped[list[Package]] = relationship(back_populates="product")
    licenses: Mapped[list[License]] = relationship(back_populates="product")
    revocations: Mapped[list[Revocation]] = relationship(
        back_populates="product",
        overlaps="activation,license,revocations",
    )


class Feature(Base):
    __tablename__ = "features"
    __table_args__ = (
        UniqueConstraint("product_id", "code", name="uq_features_product_code"),
        UniqueConstraint("product_id", "id", name="uq_features_product_id"),
        CheckConstraint("length(trim(code)) > 0", name="ck_features_code_non_empty"),
        CheckConstraint("length(trim(name)) > 0", name="ck_features_name_non_empty"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    product: Mapped[Product] = relationship(back_populates="features")
    license_features: Mapped[list[LicenseFeature]] = relationship(
        back_populates="feature",
        cascade="all, delete-orphan",
        overlaps="features,license",
    )


class Package(Base):
    __tablename__ = "packages"
    __table_args__ = (
        UniqueConstraint("product_id", "package_id", name="uq_packages_product_package_id"),
        CheckConstraint("length(trim(package_id)) > 0", name="ck_packages_package_id_non_empty"),
        CheckConstraint("length(trim(package_hash)) > 0", name="ck_packages_package_hash_non_empty"),
        CheckConstraint("length(trim(version)) > 0", name="ck_packages_version_non_empty"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), nullable=False, index=True)
    package_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    package_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_pkg_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    product: Mapped[Product] = relationship(back_populates="packages")
    activations: Mapped[list[Activation]] = relationship(
        back_populates="package",
        overlaps="activations,license",
    )


class License(Base):
    __tablename__ = "licenses"
    __table_args__ = (
        UniqueConstraint("product_id", "license_id", name="uq_licenses_product_license_id"),
        UniqueConstraint(
            "license_id",
            "max_activations",
            name="uq_licenses_license_id_max_activations",
        ),
        CheckConstraint("length(trim(license_id)) > 0", name="ck_licenses_license_id_non_empty"),
        CheckConstraint("length(code_hash) = 64", name="ck_licenses_code_hash_length"),
        CheckConstraint("max_activations >= 1", name="ck_licenses_max_activations_positive"),
        CheckConstraint(
            "status IN ('active', 'suspended', 'expired', 'revoked')",
            name="ck_licenses_status_domain",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    license_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), nullable=False, index=True)
    customer_id: Mapped[str | None] = mapped_column(String(128))
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    max_activations: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    expire_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    product: Mapped[Product] = relationship(back_populates="licenses")
    features: Mapped[list[LicenseFeature]] = relationship(
        back_populates="license",
        cascade="all, delete-orphan",
        overlaps="feature,license_features",
    )
    activations: Mapped[list[Activation]] = relationship(
        back_populates="license",
        overlaps="activation,package,slot,activations",
    )
    revocations: Mapped[list[Revocation]] = relationship(
        back_populates="license",
        overlaps="activation,product,revocations",
    )
    activation_slots: Mapped[list[LicenseActivationSlot]] = relationship(back_populates="license")


class LicenseActivationSlot(Base):
    """Internal DB-backed activation capacity slot for a license."""

    __tablename__ = "license_activation_slots"
    __table_args__ = (
        UniqueConstraint("license_id", "slot_index", name="uq_license_activation_slots_license_slot"),
        ForeignKeyConstraint(
            ["license_id", "license_max_activations"],
            ["licenses.license_id", "licenses.max_activations"],
            name="fk_license_activation_slots_license_max",
        ),
        CheckConstraint("slot_index >= 1", name="ck_license_activation_slots_slot_positive"),
        CheckConstraint(
            "slot_index <= license_max_activations",
            name="ck_license_activation_slots_slot_within_license_max",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    license_id: Mapped[str] = mapped_column(nullable=False, index=True)
    license_max_activations: Mapped[int] = mapped_column(Integer, nullable=False)
    slot_index: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    license: Mapped[License] = relationship(back_populates="activation_slots")
    activation: Mapped[Activation | None] = relationship(
        back_populates="slot",
        foreign_keys=lambda: [Activation.license_id, Activation.slot_index],
        primaryjoin=lambda: (LicenseActivationSlot.license_id == Activation.license_id)
        & (LicenseActivationSlot.slot_index == Activation.slot_index),
        overlaps="activations,license",
        uselist=False,
    )


class LicenseFeature(Base):
    __tablename__ = "license_features"
    __table_args__ = (
        UniqueConstraint("license_id", "feature_id", name="uq_license_features_pair"),
        ForeignKeyConstraint(
            ["product_id", "license_id"],
            ["licenses.product_id", "licenses.license_id"],
            name="fk_license_features_product_license",
        ),
        ForeignKeyConstraint(
            ["product_id", "feature_id"],
            ["features.product_id", "features.id"],
            name="fk_license_features_product_feature",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    product_id: Mapped[str] = mapped_column(nullable=False, index=True)
    license_id: Mapped[str] = mapped_column(nullable=False, index=True)
    feature_id: Mapped[int] = mapped_column(nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Cascades above intentionally remain limited to this child join table.
    license: Mapped[License] = relationship(
        back_populates="features",
        foreign_keys=[product_id, license_id],
        primaryjoin=lambda: (LicenseFeature.product_id == License.product_id)
        & (LicenseFeature.license_id == License.license_id),
        overlaps="feature,license_features",
    )
    feature: Mapped[Feature] = relationship(
        back_populates="license_features",
        foreign_keys=[product_id, feature_id],
        primaryjoin=lambda: (LicenseFeature.product_id == Feature.product_id)
        & (LicenseFeature.feature_id == Feature.id),
        overlaps="features,license",
    )


class Activation(Base):
    __tablename__ = "activations"
    __table_args__ = (
        UniqueConstraint("license_id", "device_hash", name="uq_activations_license_device"),
        UniqueConstraint("product_id", "activation_id", name="uq_activations_product_activation_id"),
        UniqueConstraint(
            "product_id",
            "license_id",
            "activation_id",
            name="uq_activations_product_license_activation_id",
        ),
        UniqueConstraint("license_id", "slot_index", name="uq_activations_license_slot"),
        ForeignKeyConstraint(
            ["product_id", "license_id"],
            ["licenses.product_id", "licenses.license_id"],
            name="fk_activations_product_license",
        ),
        ForeignKeyConstraint(
            ["product_id", "package_id"],
            ["packages.product_id", "packages.package_id"],
            name="fk_activations_product_package",
        ),
        ForeignKeyConstraint(
            ["license_id", "slot_index"],
            ["license_activation_slots.license_id", "license_activation_slots.slot_index"],
            name="fk_activations_license_slot",
        ),
        CheckConstraint("length(trim(activation_id)) > 0", name="ck_activations_activation_id_non_empty"),
        CheckConstraint("slot_index >= 1", name="ck_activations_slot_positive"),
        CheckConstraint("length(trim(device_hash)) > 0", name="ck_activations_device_hash_non_empty"),
        CheckConstraint("length(trim(client_pub)) > 0", name="ck_activations_client_pub_non_empty"),
        CheckConstraint("status IN ('active', 'expired', 'revoked')", name="ck_activations_status_domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    activation_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    product_id: Mapped[str] = mapped_column(nullable=False, index=True)
    license_id: Mapped[str] = mapped_column(nullable=False, index=True)
    package_id: Mapped[str] = mapped_column(nullable=False, index=True)
    slot_index: Mapped[int] = mapped_column(Integer, nullable=False)
    device_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    client_pub: Mapped[str] = mapped_column(String(512), nullable=False)
    cert_json: Mapped[JsonObject] = mapped_column(JSON, nullable=False)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    license: Mapped[License] = relationship(
        back_populates="activations",
        foreign_keys=[product_id, license_id],
        primaryjoin=lambda: (Activation.product_id == License.product_id)
        & (Activation.license_id == License.license_id),
        overlaps="activation,activations,package,slot",
    )
    package: Mapped[Package] = relationship(
        back_populates="activations",
        foreign_keys=[product_id, package_id],
        primaryjoin=lambda: (Activation.product_id == Package.product_id)
        & (Activation.package_id == Package.package_id),
        overlaps="activations,license",
    )
    slot: Mapped[LicenseActivationSlot] = relationship(
        back_populates="activation",
        foreign_keys=[license_id, slot_index],
        primaryjoin=lambda: (Activation.license_id == LicenseActivationSlot.license_id)
        & (Activation.slot_index == LicenseActivationSlot.slot_index),
        overlaps="activation,activations,license",
    )
    revocations: Mapped[list[Revocation]] = relationship(
        back_populates="activation",
        overlaps="license,product,revocations",
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("length(trim(actor)) > 0", name="ck_audit_logs_actor_non_empty"),
        CheckConstraint("length(trim(action)) > 0", name="ck_audit_logs_action_non_empty"),
        CheckConstraint("length(trim(entity_type)) > 0", name="ck_audit_logs_entity_type_non_empty"),
        CheckConstraint("length(trim(entity_id)) > 0", name="ck_audit_logs_entity_id_non_empty"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    ip_hash: Mapped[str | None] = mapped_column(String(255))
    detail_json: Mapped[JsonObject] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Revocation(Base):
    __tablename__ = "revocations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["product_id", "license_id"],
            ["licenses.product_id", "licenses.license_id"],
            name="fk_revocations_product_license",
        ),
        ForeignKeyConstraint(
            ["product_id", "license_id", "activation_id"],
            ["activations.product_id", "activations.license_id", "activations.activation_id"],
            name="fk_revocations_product_license_activation",
        ),
        CheckConstraint("length(trim(product_id)) > 0", name="ck_revocations_product_id_non_empty"),
        CheckConstraint("length(trim(license_id)) > 0", name="ck_revocations_license_id_non_empty"),
        CheckConstraint(
            "activation_id IS NULL OR length(trim(activation_id)) > 0",
            name="ck_revocations_activation_id_null_or_non_empty",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    product_id: Mapped[str] = mapped_column(ForeignKey("products.id"), nullable=False, index=True)
    license_id: Mapped[str] = mapped_column(nullable=False, index=True)
    activation_id: Mapped[str | None] = mapped_column(index=True)
    reason: Mapped[str | None] = mapped_column(String(255))
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    product: Mapped[Product | None] = relationship(
        back_populates="revocations",
        overlaps="activation,license,revocations",
    )
    license: Mapped[License | None] = relationship(
        back_populates="revocations",
        foreign_keys=[product_id, license_id],
        primaryjoin=lambda: (Revocation.product_id == License.product_id)
        & (Revocation.license_id == License.license_id),
        overlaps="activation,product,revocations",
    )
    activation: Mapped[Activation | None] = relationship(
        back_populates="revocations",
        foreign_keys=[product_id, license_id, activation_id],
        primaryjoin=lambda: (Revocation.product_id == Activation.product_id)
        & (Revocation.license_id == Activation.license_id)
        & (Revocation.activation_id == Activation.activation_id),
        overlaps="license,product,revocations",
    )


def hash_license_code(server_secret: str | bytes, license_code: str) -> str:
    """Hash a normalized license code with HMAC-SHA256 for persistent lookup."""

    secret_bytes = server_secret if isinstance(server_secret, bytes) else server_secret.encode("utf-8")
    normalized_code = normalize_license_code(license_code)
    return hmac.new(secret_bytes, normalized_code.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_license_code(license_code: str) -> str:
    """Return the canonical license-code form used before hashing and comparison."""

    return license_code.strip().upper()


def verify_license_code_hash(server_secret: str | bytes, license_code: str, code_hash: str) -> bool:
    expected_hash = hash_license_code(server_secret, license_code)
    return hmac.compare_digest(expected_hash, code_hash)


def create_activation_record(
    *,
    session: Session,
    license_row: License,
    package_row: Package,
    activation_id: str,
    device_hash: str,
    client_pub: str,
    cert_json: JsonObject,
    lease_until: datetime | None,
    status: str = "active",
) -> Activation:
    session.flush()
    existing_slots = set(
        session.scalars(
            select(LicenseActivationSlot.slot_index).where(
                LicenseActivationSlot.license_id == license_row.license_id,
            ),
        ),
    )
    for slot_index in range(1, license_row.max_activations + 1):
        if slot_index not in existing_slots:
            session.add(
                LicenseActivationSlot(
                    license_id=license_row.license_id,
                    license_max_activations=license_row.max_activations,
                    slot_index=slot_index,
                ),
            )
    session.flush()

    used_slots = set(
        session.scalars(
            select(Activation.slot_index).where(
                Activation.license_id == license_row.license_id,
            ),
        ),
    )
    allocated_slot_index: int | None = next(
        (candidate for candidate in range(1, license_row.max_activations + 1) if candidate not in used_slots),
        None,
    )
    if allocated_slot_index is None:
        raise ActivationCapacityExceeded(
            f"license {license_row.license_id} allows {license_row.max_activations} activation(s)",
        )

    activation = Activation(
        activation_id=activation_id,
        product_id=license_row.product_id,
        license=license_row,
        package=package_row,
        slot_index=allocated_slot_index,
        device_hash=device_hash,
        client_pub=client_pub,
        cert_json=cert_json,
        lease_until=lease_until,
        status=status,
    )
    session.add(activation)
    return activation
