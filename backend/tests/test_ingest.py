"""Reading a file line by line and storing it in batches."""

import io
import math
import tracemalloc
from datetime import UTC, datetime

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import OperationalError

import generate  # samples/generate.py
from app import ingest
from app.ingest import Ingestor, LineReader, NoTimestampsError, ingest_lines, open_log, read_lines
from app.models import Event, Source
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
    stream = io.BytesIO(b"first\nsecond\r\n\nlast without newline")
    assert list(read_lines(stream)) == [
        (1, "first"),
        (2, "second"),
        (3, ""),
        (4, "last without newline"),
    ]


def test_read_lines_survives_bytes_that_are_not_text():
    assert list(read_lines(io.BytesIO(b"caf\xff\x00e\n"))) == [(1, "caf\ufffde")]


def test_read_lines_cuts_very_long_lines():
    [(_, text)] = read_lines(io.BytesIO(b"x" * (ingest.MAX_LINE_LENGTH + 500) + b"\n"))
    assert len(text) == ingest.MAX_LINE_LENGTH


def test_overlong_line_is_one_line_and_never_held_in_memory_whole():
    class Counting(io.BytesIO):
        largest = 0

        def readline(self, size=-1):
            data = super().readline(size)
            Counting.largest = max(Counting.largest, len(data))
            return data

    stream = Counting(b"before\n" + b"x" * 5_000_000 + b"\nafter\n" + b"y" * 5_000_000)
    lines = list(read_lines(stream))

    assert [(number, text[:6], len(text)) for number, text in lines] == [
        (1, "before", 6),
        (2, "xxxxxx", ingest.MAX_LINE_LENGTH),
        (3, "after", 5),
        (4, "yyyyyy", ingest.MAX_LINE_LENGTH),
    ]
    assert Counting.largest <= 4 * ingest.MAX_LINE_LENGTH


def test_memory_does_not_grow_with_the_length_of_a_line():
    stream = io.BytesIO(b"x" * 20_000_000 + b"\nafter\n" + b"y" * 20_000_000)
    tracemalloc.start()
    try:
        lines = [(number, len(text)) for number, text in read_lines(stream)]
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert lines == [(1, ingest.MAX_LINE_LENGTH), (2, 5), (3, ingest.MAX_LINE_LENGTH)]
    assert peak < 1_000_000  # the two lines are 20 MB each


def test_read_lines_reads_one_line_at_a_time():
    class OneLineOnly(io.BytesIO):
        calls = 0

        def readline(self, size=-1):
            OneLineOnly.calls += 1
            assert OneLineOnly.calls == 1, "read further than was asked for"
            return super().readline(size)

    assert next(read_lines(OneLineOnly(b"only this line is needed\nnot this\n"))) == (
        1,
        "only this line is needed",
    )


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


def test_same_content_under_another_name_is_the_same_file(session):
    load(session, generate.build_lines()[:50])
    result = load(session, generate.build_lines()[:50], source_file="auth.log.1")

    assert (result.source_file, result.duplicates) == ("auth.log", 50)
    assert stored(session) == 50


def test_rotated_file_that_grew_adds_only_its_new_lines(session):
    load(session, generate.build_lines()[:50])
    result = load(session, generate.build_lines()[:80], source_file="auth.log.1")

    assert (result.source_file, result.duplicates, result.parsed + result.unparsed) == (
        "auth.log",
        50,
        30,
    )
    assert session.scalars(select(Event.source_file).distinct()).all() == ["auth.log"]


def test_another_file_under_a_name_in_use_gets_the_date_of_its_first_line(session):
    lines = generate.build_lines()
    load(session, lines[:50])
    second = load(session, lines[50:80])
    third = load(session, lines[80:90])
    fourth = load(session, lines[90:95])
    next_day = load(session, [line for line in lines if line.startswith("Sep 10")][:5])

    assert (second.source_file, second.conflicts, second.parsed + second.unparsed) == (
        "auth.log (2026-09-09)",
        0,
        30,
    )
    assert third.source_file == "auth.log (2026-09-09, 2)"
    assert fourth.source_file == "auth.log (2026-09-09, 3)"
    assert next_day.source_file == "auth.log (2026-09-10)"
    assert stored(session) == 100
    assert session.scalar(select(func.count()).select_from(Source)) == 5


def test_file_is_known_by_its_first_line_even_if_that_line_has_no_timestamp(session):
    lines = ["# exported from web-01", *generate.build_lines()[:5]]
    load(session, lines, source_file="export.txt")
    again = load(session, [*lines, generate.build_lines()[5]], source_file="other.txt")

    assert (again.source_file, again.duplicates, again.parsed + again.unparsed) == (
        "export.txt",
        6,
        1,
    )


def test_name_used_by_lines_loaded_before_files_were_registered_is_not_reused(session):
    load(session, generate.build_lines()[:10])
    session.execute(Source.__table__.delete())  # as in a database from before the sources table
    session.commit()

    result = load(session, generate.build_lines()[10:20])
    assert result.source_file == "auth.log (2026-09-09)"
    assert stored(session) == 20


def test_refused_file_is_not_registered(session):
    with pytest.raises(NoTimestampsError):
        load(session, ["hello", "this is not", "a log file"])
    assert session.scalar(select(func.count()).select_from(Source)) == 0


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
    assert load(session, ["", "   ", "\t"]).lines == 0


# --- a file that is still being written ------------------------------------------------------


class Growing(io.BytesIO):
    """A file that someone else appends to while it is being read."""

    def append(self, data: bytes) -> None:
        position = self.tell()
        self.seek(0, io.SEEK_END)
        self.write(data)
        self.seek(position)


def test_line_reader_hands_out_only_complete_lines():
    stream = Growing()
    reader = LineReader(stream)
    assert list(reader.read()) == []

    stream.append(b"first\nsec")
    assert list(reader.read()) == [(1, "first")]
    assert list(reader.read()) == []

    stream.append(b"ond\nthird\n")
    assert list(reader.read()) == [(2, "second"), (3, "third")]
    assert (reader.line_no, list(reader.finish())) == (3, [])


def test_line_reader_gives_up_the_unfinished_last_line_only_when_told_to():
    stream = Growing(b"first\nlast, never finished")
    reader = LineReader(stream)
    assert list(reader.read()) == [(1, "first")]
    assert list(reader.finish()) == [(2, "last, never finished")]
    assert list(reader.finish()) == []


def test_line_reader_keeps_numbering_through_an_overlong_line_that_arrives_in_pieces():
    stream = Growing()
    reader = LineReader(stream)
    seen = []
    for piece in (b"a\n", b"x" * 40_000, b"x" * 40_000, b"x" * 10 + b"\nb\n"):
        stream.append(piece)
        seen += list(reader.read())

    assert [(number, text[:1], len(text)) for number, text in seen] == [
        (1, "a", 1),
        (2, "x", ingest.MAX_LINE_LENGTH),
        (3, "b", 1),
    ]


def feed(ingestor: Ingestor, lines: list[str], first: int) -> None:
    ingestor.feed(enumerate(lines, start=first))
    ingestor.flush()


def test_ingestor_stores_lines_as_they_are_handed_in(session):
    lines = generate.build_lines()
    ingestor = Ingestor(session, name="auth.log", parser=create_parser("auth", year=YEAR))

    feed(ingestor, lines[:10], 1)
    assert stored(session) == 10
    feed(ingestor, lines[10:25], 11)
    feed(ingestor, [], 26)

    assert stored(session) == ingestor.result.added == 25
    assert session.scalars(select(Event.line_no).order_by(Event.line_no)).all() == list(
        range(1, 26)
    )


def test_failed_write_can_be_repeated_without_losing_or_doubling_anything(session, monkeypatch):
    ingestor = Ingestor(session, name="auth.log", parser=create_parser("auth", year=YEAR))
    ingestor.feed(enumerate(generate.build_lines()[:30], start=1))

    def busy():
        raise OperationalError("COMMIT", {}, Exception("database is locked"))

    with monkeypatch.context() as patched:
        patched.setattr(session, "commit", busy)
        with pytest.raises(OperationalError):
            ingestor.flush()
    session.rollback()
    assert (stored(session), ingestor.result.added) == (0, 0)
    assert session.scalar(select(func.count()).select_from(Source)) == 0

    ingestor.flush()
    ingestor.flush()
    assert (stored(session), ingestor.result.added, ingestor.result.duplicates) == (30, 30, 0)
    assert session.scalars(select(Source.name)).all() == ["auth.log"]


def test_resuming_skips_what_is_stored_without_parsing_it(session):
    lines = generate.build_lines()
    load(session, lines[:300])

    class Counting:
        def __init__(self, parser):
            self.parser, self.parsed = parser, 0

        def parse(self, line):
            self.parsed += 1
            return self.parser.parse(line)

    parser = Counting(create_parser("auth", year=YEAR))
    ingestor = Ingestor(session, name="whatever.log", parser=parser, resume=True)
    feed(ingestor, lines[:320], 1)

    result = ingestor.result
    assert (result.source_file, result.lines, result.duplicates, result.added) == (
        "auth.log",
        320,
        300,
        20,
    )
    assert parser.parsed == 20
    assert stored(session) == 320


def test_resuming_gives_an_undated_line_after_the_gap_the_time_of_the_last_stored_line(session):
    lines = generate.build_lines()
    load(session, lines[:300])
    last = session.scalars(select(Event).where(Event.line_no == 300)).one()

    ingestor = Ingestor(
        session, name="auth.log", parser=create_parser("auth", year=YEAR), resume=True
    )
    feed(ingestor, [*lines[:300], "    a continuation line"], 1)

    added = session.scalars(select(Event).where(Event.line_no == 301)).one()
    assert (added.ts, added.host, added.parsed) == (last.ts, last.host, False)


def test_resuming_a_file_never_seen_before_starts_at_its_first_line(session):
    ingestor = Ingestor(
        session, name="auth.log", parser=create_parser("auth", year=YEAR), resume=True
    )
    feed(ingestor, generate.build_lines()[:10], 1)
    assert (ingestor.result.added, ingestor.result.duplicates) == (10, 0)


# --- compressed files ------------------------------------------------------------------------


def test_open_log_leaves_plain_text_alone_and_does_not_consume_it():
    stream = io.BytesIO(b"plain\n")
    assert open_log(stream) is stream
    assert stream.read() == b"plain\n"


def test_open_log_copes_with_an_empty_file():
    assert list(read_lines(open_log(io.BytesIO()))) == []
