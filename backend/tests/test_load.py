"""Loading files from the command line: ``python -m app.load``."""

import gzip
from pathlib import Path

import pytest
from sqlalchemy import func, select

import generate  # samples/generate.py
import generate_ufw  # samples/generate_ufw.py
from app import load
from app.config import get_settings
from app.db import Base, make_engine, session_factory
from app.models import Alert, Event, Source
from app.rules import load_rules

RULES = load_rules(Path(__file__).resolve().parents[2] / "rules")
AUTH, UFW = generate.DEFAULT_OUTPUT, generate_ufw.DEFAULT_OUTPUT
YEAR = generate.DEFAULT_START.year
LINES = len(generate.build_lines()) + len(generate_ufw.build_lines())


def count(session, table) -> int:
    return session.scalar(select(func.count()).select_from(table))


def test_loads_the_files_and_runs_the_rules(session, capsys):
    assert load.load_files(session, [AUTH, UFW], rules=RULES, year=YEAR)

    assert count(session, Event) == LINES
    assert count(session, Alert) == 8
    assert capsys.readouterr().out.splitlines() == [
        f"{AUTH}: 1057 lines, 605 parsed, 452 unparsed, 0 duplicates, 0 conflicts",
        f"{UFW}: 781 lines, 781 parsed, 0 unparsed, 0 duplicates, 0 conflicts",
        "8 alerts, 8 of them new",
    ]


def test_loading_again_adds_nothing(session, capsys):
    load.load_files(session, [AUTH, UFW], rules=RULES, year=YEAR)
    capsys.readouterr()

    assert load.load_files(session, [AUTH], rules=RULES, year=YEAR)
    assert count(session, Event) == LINES
    assert capsys.readouterr().out.splitlines() == [
        f"{AUTH}: 1057 lines, 0 parsed, 0 unparsed, 1057 duplicates, 0 conflicts",
        "8 alerts, 0 of them new",
    ]


def test_each_file_gets_a_parser_of_its_own(session, tmp_path):
    """A parser follows its file through the year, so the next file needs a new one.

    Read on with the parser of a log that ended in September, a line from March
    would be taken for next year's March, which is nearer.
    """
    spring = tmp_path / "spring.log"
    spring.write_text("Mar  1 10:00:00 web-01 sshd[100]: Connection closed by 192.0.2.10\n")

    load.load_files(session, [AUTH, spring], rules=RULES, year=YEAR)

    stamp = session.scalar(select(Event.ts).where(Event.source_file == "spring.log"))
    assert (stamp.year, stamp.month) == (YEAR, 3)


def test_compressed_file_is_unpacked_and_keeps_its_name(session, tmp_path, capsys):
    packed = tmp_path / "auth.log.2.gz"
    packed.write_bytes(gzip.compress(AUTH.read_bytes()))

    assert load.load_files(session, [packed], rules=RULES, year=YEAR)
    assert session.scalars(select(Source.name)).all() == ["auth.log.2.gz"]
    assert "1057 lines, 605 parsed" in capsys.readouterr().out


def test_a_file_that_cannot_be_loaded_does_not_stop_the_others(session, tmp_path, capsys):
    notes = tmp_path / "notes.txt"
    notes.write_text("nothing here\nlooks like a log\n")
    missing = tmp_path / "missing.log"

    assert not load.load_files(session, [missing, notes, AUTH], rules=RULES, year=YEAR)

    printed = capsys.readouterr()
    assert f"{missing}: No such file or directory" in printed.err
    assert f"{notes}: " in printed.err
    assert count(session, Event) == 1057
    assert printed.out.splitlines()[-1] == "6 alerts, 6 of them new"


@pytest.fixture
def database(tmp_path, monkeypatch) -> Path:
    """Makes a file in a temporary folder the configured database. Not created yet."""
    path = tmp_path / "logs.db"
    monkeypatch.setenv("LOG_ANALYZER_DATABASE_URL", f"sqlite:///{path}")
    get_settings.cache_clear()
    session_factory.cache_clear()
    yield path
    get_settings.cache_clear()
    session_factory.cache_clear()


def test_command_line(database, capsys):
    engine = make_engine(f"sqlite:///{database}")
    Base.metadata.create_all(engine)

    assert load.main(["--year", str(YEAR), str(AUTH), str(UFW)]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "8 alerts, 8 of them new"

    assert load.main([str(database.parent / "missing.log")]) == 1
    engine.dispose()


def test_command_line_says_what_to_do_about_a_database_without_tables(database, capsys):
    assert load.main([str(AUTH)]) == 1
    assert "alembic upgrade head" in capsys.readouterr().err


def test_command_line_rejects_what_it_does_not_know(database, capsys):
    for arguments in (["--tz", "Mars/Olympus", str(AUTH)], ["--parser", "apache", str(AUTH)], []):
        with pytest.raises(SystemExit) as stopped:
            load.main(arguments)
        assert stopped.value.code == 2
    assert "unknown time zone 'Mars/Olympus'" in capsys.readouterr().err
