"""Product and feature service functions."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from skeyserver.models import Feature, Product


def create_product(session: Session, *, product_id: str, name: str, version: str) -> Product:
    product = Product(id=product_id, name=name, version=version)
    session.add(product)
    session.flush()
    return product


def get_product(session: Session, product_id: str) -> Product | None:
    return session.scalar(select(Product).where(Product.id == product_id))


def create_feature(session: Session, *, product_id: str, code: str, name: str) -> Feature:
    feature = Feature(product_id=product_id, code=code, name=name)
    session.add(feature)
    session.flush()
    return feature


def get_feature(session: Session, *, product_id: str, code: str) -> Feature | None:
    return session.scalar(select(Feature).where(Feature.product_id == product_id, Feature.code == code))
