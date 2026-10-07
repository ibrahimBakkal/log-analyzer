"""Fixtures shared by the backend tests."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app


@pytest.fixture
def engine() -> Iterator[Engine]:
    """An empty in-memory database with the current schema."""
    # StaticPool keeps the single in-memory database alive across threads.
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    with Session(engine, expire_on_commit=False) as session:
        yield session


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    """The API, talking to the empty test database instead of the configured one."""

    def test_session() -> Iterator[Session]:
        with Session(engine, expire_on_commit=False) as session:
            yield session

    app.dependency_overrides[get_session] = test_session
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
