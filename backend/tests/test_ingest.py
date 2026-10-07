"""Reading a file line by line and storing it in batches."""

import math
from datetime import UTC, datetime

import pytest
from sqlalchemy import event, func, select

import generate  # samples/generate.py
from app import ingest
from app.ingest import NoTimestampsError, ingest_lines, read_lines
from app.models import Event
from app.parsers import create_parser

SAMPLE = generate.DEFAULT_OUTPUT
YEAR = generate.DEFAULT_START.year
TOTAL = len(generate.build_lines())


def load(session, lines, *, source_file="auth.log", **options):
    """Ingest an iterable of text lines (numbered from 1) with a fresh auth parser."""
    numbered = enumerate(lines, start=1)
    parser = create_parser("auth", year=YEAR)
    return ingest_lines(session, numbered, source_file=source_file, parser=parser, **options)


def stored(session) -> int:
    return session.scalar(select(func.count()).select_from(Event))


# --- read_lines ------------------------------------------------------------------------------


def test_read_lines_numbers_from_one_and_drops_line_endings():
    stream = [b"first\n", b"second\r\n", b"last without newline"]
    assert list(read_lines(stream)) == [(1, "first"), (2, "second"), (3, "last without newline")]


def test_read_lines_survives_bytes_that_are_not_text():
    assert list(read_lines([b"caf\xff\x00e\n"])) == [(1, "caf�e")]


def test_read_lines_cuts_very_long_lines():
    [(_, text)] = read_lines([b"x" * (ingest.MAX_LINE_LENGTH + 500) + b"\n"])
    assert len(text) == ingest.MAX_LINE_LENGTH


def test_read_lines_reads_one_line_at_a_time():
    def stream():
        yield b"only this line is needed\n"
        raise AssertionError("read further than was asked for")

    assert next(read_lines(stream())) == (1, "only this line is needed")


def test_read_lines_reads_the_sample_file():
    with SAMPLE.open("rb") as stream:
        assert [text for _, text in read_lines(stream)] == generate.build_lines()


# --- ingest_lines: the sample ----------------------------------------------------------------


def test_every_line_of_the_sample_is_stored_as_parsed_or_unparsed(session):
    result = load(session, generate.build_lines())

    assert result.lines == TOTAL
    assert result.parsed + result.unparsed == TOTAL
    assert (result.duplicates, result.conflicts) == (0, 0)
    assert stored(session) == TOTAL
    assert result.parsed == session.scalar(
        select(func.count()).select_from(Event).where(Event.parsed)
    )


def test_loading_the_same_file_again_stores_nothing_new(session):
    first = load(session, generate.build_lines())
    again = load(session, generate.build_lines())

    assert (again.parsed, again.unparsed, again.conflicts) == (0, 0, 0)
    assert again.duplicates == again.lines == TOTAL
    assert stored(session) == first.parsed + first.unparsed == TOTAL


def test_loading_a_file_that_has_grown_stores_only_the_new_lines(session):
    lines = generate.build_lines()
    load(session, lines[:500])
    result = load(session, lines)

    assert result.duplicates == 500
    assert result.parsed + result.unparsed == TOTAL - 500
    assert stored(session) == TOTAL


def test_same_content_under_another_name_is_a_different_file(session):
    load(session, generate.build_lines()[:50])
    result = load(session, generate.build_lines()[:50], source_file="auth.log.1")

    assert result.duplicates == 0
    assert stored(session) == 100


def test_different_text_at_a_stored_line_number_is_reported_not_overwritten(session):
    lines = generate.build_lines()[:10]
    load(session, lines)
    rotated = [
        lines[0],
        "Sep 11 08:00:00 web-01 sshd[1]: Server listening on :: port 22.",
        *lines[2:],
    ]
    result = load(session, rotated)

    assert (result.duplicates, result.conflicts) == (9, 1)
    assert stored(session) == 10
    assert session.scalar(select(Event.raw).where(Event.line_no == 2)) == lines[1]


def test_recognized_fields_are_stored(session):
    load(session, generate.build_lines())
    failed = session.scalars(
        select(Event).where(Event.action == "auth_fail").order_by(Event.id).limit(1)
    ).one()

    assert failed.raw == generate.build_lines()[failed.line_no - 1]
    assert failed.raw.endswith(f"from {failed.src_ip} port {failed.src_port} ssh2")
    assert (failed.host, failed.service, failed.level) == ("web-01", "sshd", "warning")
    assert (failed.source_file, failed.parsed) == ("auth.log", True)
    assert failed.ts.tzinfo is not None


# --- ingest_lines: batching ------------------------------------------------------------------


@pytest.mark.parametrize("batch_size", [100, 1000, 5000])
def test_rows_are_written_in_batches(session, batch_size):
    inserts = []

    @event.listens_for(session.get_bind(), "before_cursor_execute")
    def count_inserts(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO events"):
            inserts.append(len(parameters) if executemany else 1)

    result = load(session, generate.build_lines(), batch_size=batch_size)

    assert result.parsed + result.unparsed == TOTAL
    assert len(inserts) == math.ceil(TOTAL / batch_size)
    assert sum(inserts) == TOTAL and max(inserts) <= batch_size


def test_batch_size_does_not_change_what_is_stored(engine, session):
    load(session, generate.build_lines(), batch_size=7)
    small = session.execute(select(Event.line_no, Event.action, Event.ts)).all()
    session.execute(Event.__table__.delete())
    session.commit()

    load(session, generate.build_lines(), batch_size=5000)
    assert session.execute(select(Event.line_no, Event.action, Event.ts)).all() == small


# --- ingest_lines: lines without a timestamp -----------------------------------------------


def test_undated_line_takes_time_and_host_of_the_line_before_it(session):
    result = load(
        session,
        [
            "Sep  9 03:12:39 web-01 sshd[1]: Failed password for root "
            "from 203.0.113.45 port 1 ssh2",
            "    a continuation line without a timestamp",
        ],
    )
    first, second = session.scalars(select(Event).order_by(Event.line_no)).all()

    assert (result.parsed, result.unparsed) == (1, 1)
    assert (second.ts, second.host) == (first.ts, "web-01")
    assert (second.parsed, second.service, second.action) == (False, None, None)
    assert second.message == second.raw == "    a continuation line without a timestamp"


def test_undated_lines_at_the_top_take_the_time_of_the_first_dated_line(session):
    result = load(
        session,
        [
            "# exported from web-01",
            "",
            "Sep  9 03:12:39 web-01 sshd[1]: Server listening on :: port 22.",
        ],
    )
    events = session.scalars(select(Event).order_by(Event.line_no)).all()

    assert result.lines == 2  # the blank line is not counted ...
    assert [e.line_no for e in events] == [1, 3]  # ... but numbering still matches the file
    assert {e.ts for e in events} == {datetime(2026, 9, 9, 3, 12, 39, tzinfo=UTC)}


def test_file_without_any_timestamp_is_refused_and_nothing_is_stored(session):
    with pytest.raises(NoTimestampsError):
        load(session, ["hello", "this is not", "a log file"])
    assert stored(session) == 0


def test_file_without_timestamps_is_given_up_on_early(session):
    def endless():
        for number in range(ingest.MAX_UNDATED_LINES + 2):
            yield f"line {number} of some other kind of file"
        raise AssertionError("kept reading a file that is clearly not a log")

    with pytest.raises(NoTimestampsError):
        load(session, endless())
    assert stored(session) == 0


def test_empty_file_stores_nothing(session):
    result = load(session, [])
    assert (result.lines, result.parsed, result.unparsed) == (0, 0, 0)
