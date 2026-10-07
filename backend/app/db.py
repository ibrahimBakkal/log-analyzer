"""Database engine, sessions and the declarative base."""

from collections.abc import Iterator
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from sqlalchemy import DateTime, Engine, MetaData, create_engine, event
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator

from app.config import get_settings

# Explicit names for indexes and constraints, so migrations can refer to them.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UTCDateTime(TypeDecorator[datetime]):
    """A timestamp that is always UTC.

    SQLite cannot store a time zone, so values are written as naive UTC and
    read back as timezone-aware UTC. Naive datetimes are rejected on the way in:
    a timestamp whose zone is unknown must not be stored as if it were UTC.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime given where a timezone-aware one is required")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return None if value is None else value.replace(tzinfo=UTC)


def make_engine(url: str, **options: Any) -> Engine:
    if not url.startswith("sqlite"):
        return create_engine(url, **options)

    # FastAPI runs request handlers in worker threads; SQLite connections refuse
    # to be used outside the thread that created them unless told otherwise.
    engine = create_engine(url, connect_args={"check_same_thread": False}, **options)

    @event.listens_for(engine, "connect")
    def enforce_foreign_keys(dbapi_connection: Any, _: Any) -> None:
        # SQLite ignores foreign keys (and ON DELETE CASCADE) unless asked on every connection.
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


@lru_cache
def _session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=make_engine(get_settings().database_url), expire_on_commit=False)


def get_session() -> Iterator[Session]:
    """FastAPI dependency: one database session per request."""
    with _session_factory()() as session:
        yield session
