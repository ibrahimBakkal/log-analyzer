"""The events table: schema, migrations and the UTC timestamp type."""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.exc import IntegrityError, StatementError

from app import models  # noqa: F401  (registers the tables)
from app.db import Base
from app.models import Event

BACKEND_DIR = Path(__file__).resolve().parents[1]


def make_event(**overrides) -> Event:
    fields = {
        "ts": datetime(2026, 9, 9, 3, 12, 39, tzinfo=UTC),
        "level": "info",
        "message": "Server listening on 0.0.0.0 port 22.",
        "raw": "Sep  9 00:00:07 web-01 sshd[1208]: Server listening on 0.0.0.0 port 22.",
        "source_file": "auth.log",
        "line_no": 1,
        "parsed": False,
    }
    return Event(**(fields | overrides))


def alembic_config(url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def test_migrations_build_exactly_the_schema_the_models_describe(tmp_path):
    url = f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    command.upgrade(alembic_config(url), "head")

    engine = create_engine(url)
    with engine.connect() as connection:
        differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    assert differences == []

    indexes = {
        index["name"]: index["column_names"] for index in inspect(engine).get_indexes("events")
    }
    assert indexes == {
        "ix_events_ts": ["ts"],
        "ix_events_src_ip_ts": ["src_ip", "ts"],
        "ix_events_action_ts": ["action", "ts"],
        "ix_events_dst_port_ts": ["dst_port", "ts"],
    }
    engine.dispose()


def test_migrations_can_be_rolled_back(tmp_path):
    url = f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    command.upgrade(alembic_config(url), "head")
    command.downgrade(alembic_config(url), "base")

    engine = create_engine(url)
    assert inspect(engine).get_table_names() == ["alembic_version"]
    engine.dispose()


def test_same_line_of_same_file_cannot_be_stored_twice(session):
    session.add(make_event())
    session.commit()

    session.add(make_event(message="something else"))
    with pytest.raises(IntegrityError):
        session.commit()


def test_same_line_number_in_another_file_is_fine(session):
    session.add_all([make_event(), make_event(source_file="auth.log.1")])
    session.commit()

    assert len(session.scalars(select(Event)).all()) == 2


def test_timestamps_are_stored_in_utc_and_come_back_timezone_aware(session):
    istanbul = timezone(timedelta(hours=3))
    session.add(make_event(ts=datetime(2026, 9, 9, 6, 12, 39, tzinfo=istanbul)))
    session.commit()
    session.expire_all()

    stored = session.scalars(select(Event)).one().ts
    assert stored == datetime(2026, 9, 9, 3, 12, 39, tzinfo=UTC)
    assert stored.utcoffset() == timedelta(0)


def test_naive_timestamps_are_rejected(session):
    session.add(make_event(ts=datetime(2026, 9, 9, 3, 12, 39)))
    with pytest.raises(StatementError, match="naive datetime"):
        session.commit()
