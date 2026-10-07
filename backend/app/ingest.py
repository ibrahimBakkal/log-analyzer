"""Loading the lines of a log file into the database.

Three pieces, used by both the upload endpoint and the file follower:

* :func:`open_log` unpacks a compressed file as it is read,
* :class:`LineReader` turns bytes into numbered, cleaned-up lines,
* :class:`Ingestor` parses the lines and stores them as events.
"""

import bz2
import gzip
import hashlib
import lzma
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import IO, Any

from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Event, Source
from app.parsers import BaseParser, ParsedLine

DEFAULT_BATCH_SIZE = 5000  # rows per transaction: fewer, larger commits load a big file faster
MAX_LINE_LENGTH = 8192  # rsyslog's default message size limit; longer lines are cut
MAX_UNDATED_LINES = 1000  # how long to wait for a first timestamp before giving up

_READ_BYTES = 4 * MAX_LINE_LENGTH  # the most a line of MAX_LINE_LENGTH characters can take

# How a compressed file starts, and what unpacks it. logrotate uses gzip unless told otherwise.
_COMPRESSION = (
    (b"\x1f\x8b", lambda stream: gzip.GzipFile(fileobj=stream, mode="rb")),
    (b"BZh", bz2.BZ2File),
    (b"\xfd7zXZ\x00", lzma.LZMAFile),
)
_UNPACKERS = (gzip.GzipFile, bz2.BZ2File, lzma.LZMAFile)
_DAMAGED = (EOFError, zlib.error, lzma.LZMAError, OSError)  # OSError: also gzip.BadGzipFile


class NoTimestampsError(ValueError):
    """The input does not look like a log: no line carries a readable timestamp."""


class DamagedFileError(ValueError):
    """A compressed file ends early or does not unpack."""


@dataclass
class IngestResult:
    """How the lines of one file were accounted for.

    ``lines == parsed + unparsed + duplicates + conflicts``. Blank lines are not counted.
    """

    source_file: str  # the name the lines are stored under
    lines: int = 0
    parsed: int = 0  # stored, and a pattern recognized the message
    unparsed: int = 0  # stored as-is because no pattern matched
    duplicates: int = 0  # already stored by an earlier load of the same file
    conflicts: int = 0  # line number already stored with different text; left untouched

    @property
    def added(self) -> int:
        return self.parsed + self.unparsed


def open_log(stream: IO[bytes]) -> IO[bytes]:
    """Return *stream*, wrapped so that it reads as plain text if it is compressed.

    The format is told from how the file starts, not from its name, which
    someone may have changed. gzip, bzip2 and xz are understood.
    """
    start = stream.tell()
    head = stream.read(8)
    stream.seek(start)
    for magic, unpack in _COMPRESSION:
        if head.startswith(magic):
            return unpack(stream)  # type: ignore[return-value]
    return stream


class LineReader:
    """Numbered, cleaned-up lines of a binary stream, which may still be growing.

    Line numbers start at 1. Line endings are removed, bytes that are not valid
    UTF-8 are replaced and very long lines are cut, so that a single broken line
    can neither stop a load nor bloat the database (or the memory: the rest of
    an overlong line is thrown away as it is read).

    :meth:`read` yields the complete lines available now. A last line without a
    line ending is kept back, since whoever writes the file may not be done with
    it; :meth:`finish` hands it out once it is known that nothing follows.
    """

    def __init__(self, stream: IO[bytes]) -> None:
        self._stream = stream
        self.line_no = 0  # number of the last line handed out
        self._partial = b""  # start of a line whose end has not been read yet
        self._discarding = False  # inside an overlong line, waiting for its end

    def read(self) -> Iterator[tuple[int, str]]:
        while True:
            try:
                chunk = self._stream.readline(_READ_BYTES)
            except _DAMAGED as error:
                if not isinstance(self._stream, _UNPACKERS):
                    raise
                raise DamagedFileError(
                    f"compressed file is damaged after line {self.line_no}: {error}"
                ) from None
            if not chunk:
                return
            complete = chunk.endswith(b"\n")
            if self._discarding:
                self._discarding = not complete
                continue
            data = self._partial + chunk
            if complete:
                self._partial = b""
            elif len(data) >= _READ_BYTES:
                self._partial = b""
                self._discarding = True
            else:
                self._partial = data  # the end of the stream, in the middle of a line
                continue
            self.line_no += 1
            yield self.line_no, _clean(data)

    def finish(self) -> Iterator[tuple[int, str]]:
        """The last line, if the stream ended without a line ending."""
        self._discarding = False
        if self._partial:
            data, self._partial = self._partial, b""
            self.line_no += 1
            yield self.line_no, _clean(data)


def _clean(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace").rstrip("\r\n").replace("\x00", "")
    return text[:MAX_LINE_LENGTH]


def read_lines(stream: IO[bytes]) -> Iterator[tuple[int, str]]:
    """Yield ``(line number, text)`` for each line of a finished file, one at a time."""
    reader = LineReader(stream)
    yield from reader.read()
    yield from reader.finish()


class Ingestor:
    """Stores the lines of one log file as events, as they are handed in.

    Every non-blank line is stored: recognized lines with their fields, the rest
    as unparsed. A line without a timestamp of its own takes the time and host of
    the line before it (or, at the very top of a file, of the first dated line).

    A file is known by its first line (see :class:`~app.models.Source`), and each
    of its lines by its number. Loading a file again therefore stores nothing
    new, loading a file that has grown stores only the added lines, and a
    rotated copy (``auth.log.1``, ``auth.log.2.gz``) is recognized as the file it
    used to be. A new file that arrives under a name already in use gets the date
    of its first line added to the name: ``auth.log (2026-09-14)``.

    With *resume*, lines up to the last one stored are skipped without being
    parsed or compared: for picking up a followed file where it was left.

    If :meth:`flush` fails (the database is busy, say), nothing is lost: roll
    the session back and call it again.
    """

    def __init__(
        self,
        session: Session,
        *,
        name: str,
        parser: BaseParser,
        batch_size: int = DEFAULT_BATCH_SIZE,
        resume: bool = False,
    ) -> None:
        self.result = IngestResult(name)
        self._session = session
        self._name = name
        self._parser = parser
        self._batch_size = batch_size
        self._resume = resume
        self._fingerprint: str | None = None
        self._first_ts: datetime | None = None
        self._registered = False  # the file has its row in the sources table
        self._skip_through = 0  # with resume: the last line number already stored
        self._batch: list[dict[str, Any]] = []
        self._undated: list[tuple[int, str]] = []  # lines read before the first timestamp
        self._previous: ParsedLine | None = None

    def feed(self, lines: Iterable[tuple[int, str]]) -> None:
        """Take in numbered lines; full batches are stored right away."""
        for line_no, raw in lines:
            if not raw.strip():
                continue
            self.result.lines += 1
            if self._fingerprint is None:
                self._identify(raw)
            if line_no <= self._skip_through:
                self.result.duplicates += 1
                continue

            entry = self._parser.parse(raw)
            if entry is None and self._previous is None:
                self._undated.append((line_no, raw))
                if len(self._undated) > MAX_UNDATED_LINES:
                    raise NoTimestampsError(
                        f"no timestamp in the first {MAX_UNDATED_LINES} lines: not a log file?"
                    )
                continue
            if entry is None:
                entry = _continuation(self._previous, raw)
            else:
                if self._first_ts is None:
                    self._first_ts = entry.ts
                for number, text in self._undated:
                    self._batch.append(_row(number, text, _continuation(entry, text)))
                self._undated.clear()
                self._previous = entry
            self._batch.append(_row(line_no, raw, entry))
            if len(self._batch) >= self._batch_size:
                self.flush()

    def flush(self) -> None:
        """Store what has been taken in so far and commit."""
        if not self._batch:
            return
        if not self._registered:
            self._register()
        counts = self._store(self._batch)
        self._session.commit()
        # Only now is it true: a failed commit leaves batch and counts for the next try.
        self._registered = True
        self._batch = []
        self.result.parsed += counts["parsed"]
        self.result.unparsed += counts["unparsed"]
        self.result.duplicates += counts["duplicates"]
        self.result.conflicts += counts["conflicts"]

    def finish(self) -> IngestResult:
        """Store the rest. Raises :class:`NoTimestampsError` if no line had a timestamp."""
        if self._undated:
            raise NoTimestampsError("no line has a readable timestamp: not a log file?")
        self.flush()
        return self.result

    # --- which file this is --------------------------------------------------------------

    def _identify(self, first_line: str) -> None:
        """Look the file up by its first line."""
        self._fingerprint = hashlib.sha256(first_line.encode("utf-8")).hexdigest()
        known = self._known_name()
        if known is None:
            return
        self._registered = True
        self.result.source_file = known
        if self._resume:
            last = self._session.execute(
                select(Event.line_no, Event.ts, Event.host)
                .where(Event.source_file == known)
                .order_by(Event.line_no.desc())
                .limit(1)
            ).first()
            if last is not None:
                self._skip_through = last.line_no
                # So that an undated line right after the gap still has a neighbour.
                self._previous = ParsedLine(ts=last.ts, host=last.host, message="")

    def _known_name(self) -> str | None:
        return self._session.scalar(
            select(Source.name).where(Source.fingerprint == self._fingerprint)
        )

    def _register(self) -> None:
        """Give a file seen for the first time a name of its own.

        Part of the transaction that stores the file's first lines, so that a
        file is registered if and only if lines of it are stored.
        """
        for _ in range(5):
            name = self._free_name()
            try:
                self._session.execute(
                    insert(Source).values(name=name, fingerprint=self._fingerprint)
                )
            except IntegrityError:
                # Someone registered this file, or took the name, a moment ago.
                self._session.rollback()
                if (known := self._known_name()) is not None:
                    self.result.source_file = known
                    return
            else:
                self.result.source_file = name
                return
        raise RuntimeError(f"could not register {self._name!r}: its names keep being taken")

    def _free_name(self) -> str:
        if not self._taken(self._name):
            return self._name
        assert self._first_ts is not None  # there is a batch, so there was a dated line
        dated = f"{self._name} ({self._first_ts:%Y-%m-%d})"
        name, attempt = dated, 2
        while self._taken(name):
            name = f"{dated[:-1]}, {attempt})"
            attempt += 1
        return name

    def _taken(self, name: str) -> bool:
        registered = select(Source.id).where(Source.name == name).exists()
        in_use = select(Event.id).where(Event.source_file == name).exists()
        return bool(self._session.scalar(select(registered | in_use)))

    # --- storing -------------------------------------------------------------------------

    def _store(self, rows: list[dict[str, Any]]) -> dict[str, int]:
        """Insert the rows that are not in the database yet; say what became of each."""
        source = self.result.source_file
        first, last = rows[0]["line_no"], rows[-1]["line_no"]
        stored = dict(
            self._session.execute(
                select(Event.line_no, Event.raw).where(
                    Event.source_file == source, Event.line_no.between(first, last)
                )
            ).all()
        )
        counts = {"parsed": 0, "unparsed": 0, "duplicates": 0, "conflicts": 0}
        fresh = []
        for row in rows:
            known = stored.get(row["line_no"])
            if known is None:
                fresh.append(row | {"source_file": source})
                counts["parsed" if row["parsed"] else "unparsed"] += 1
            elif known == row["raw"]:
                counts["duplicates"] += 1
            else:
                counts["conflicts"] += 1
        if fresh:
            # Insert through the table, not the ORM entity: the ORM leaves None-valued
            # columns out of the statement, which splits a batch into one INSERT per
            # run of rows that happen to have the same empty columns.
            self._session.execute(insert(Event.__table__), fresh)
        return counts


def ingest_lines(
    session: Session,
    lines: Iterable[tuple[int, str]],
    *,
    source_file: str,
    parser: BaseParser,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> IngestResult:
    """Parse the numbered *lines* of a finished file and store them as events.

    *source_file* is the name to store a new file under; see :class:`Ingestor`
    for what happens when the file or the name is already known. Rows are
    committed *batch_size* at a time.

    Raises :class:`NoTimestampsError`, having stored nothing, if no line has a timestamp.
    If a compressed file turns out to be damaged, the lines that could be read are
    stored before :class:`DamagedFileError` is passed on.
    """
    ingestor = Ingestor(session, name=source_file, parser=parser, batch_size=batch_size)
    try:
        ingestor.feed(lines)
    except DamagedFileError:
        ingestor.flush()
        raise
    return ingestor.finish()


def _continuation(neighbour: ParsedLine, raw: str) -> ParsedLine:
    """An undated line, filed under the time and host of the dated line next to it."""
    return ParsedLine(ts=neighbour.ts, host=neighbour.host, message=raw)


def _row(line_no: int, raw: str, entry: ParsedLine) -> dict[str, Any]:
    """An event's columns, all but the name of the file, which is settled when it is stored."""
    return {
        "ts": entry.ts,
        "host": entry.host,
        "service": entry.service,
        "level": entry.level,
        "src_ip": entry.src_ip,
        "dst_ip": entry.dst_ip,
        "src_port": entry.src_port,
        "dst_port": entry.dst_port,
        "user": entry.user,
        "action": entry.action,
        "message": entry.message,
        "raw": raw,
        "line_no": line_no,
        "parsed": entry.parsed,
    }
