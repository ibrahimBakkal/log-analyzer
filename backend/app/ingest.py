"""Loading the lines of a log file into the database."""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.models import Event
from app.parsers import BaseParser, ParsedLine

DEFAULT_BATCH_SIZE = 1000
MAX_LINE_LENGTH = 8192  # rsyslog's default message size limit; longer lines are cut
MAX_UNDATED_LINES = 1000  # how long to wait for a first timestamp before giving up


class NoTimestampsError(ValueError):
    """The input does not look like a log: no line carries a readable timestamp."""


@dataclass
class IngestResult:
    """How the lines of one upload were accounted for.

    ``lines == parsed + unparsed + duplicates + conflicts``. Blank lines are not counted.
    """

    source_file: str
    lines: int = 0
    parsed: int = 0  # stored, and a pattern recognized the message
    unparsed: int = 0  # stored as-is because no pattern matched
    duplicates: int = 0  # already stored by an earlier upload of the same file
    conflicts: int = 0  # line number already stored with different text; left untouched


def read_lines(stream: Iterable[bytes]) -> Iterator[tuple[int, str]]:
    """Yield ``(line number, text)`` for each line of a binary stream, one at a time.

    Line numbers start at 1. Line endings are removed, bytes that are not valid
    UTF-8 are replaced and very long lines are cut, so that a single broken line
    can neither stop an upload nor bloat the database.
    """
    for line_no, raw in enumerate(stream, start=1):
        text = raw.decode("utf-8", errors="replace").rstrip("\r\n").replace("\x00", "")
        yield line_no, text[:MAX_LINE_LENGTH]


def ingest_lines(
    session: Session,
    lines: Iterable[tuple[int, str]],
    *,
    source_file: str,
    parser: BaseParser,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> IngestResult:
    """Parse numbered *lines* and store them as events, *batch_size* rows per transaction.

    Every non-blank line is stored: recognized lines with their fields, the rest
    as unparsed. A line without a timestamp of its own takes the time and host of
    the line before it (or, at the very top of a file, of the first dated line).

    Uploading the same file again stores nothing new, and uploading a file that
    has grown stores only the added lines.

    Raises :class:`NoTimestampsError`, having stored nothing, if no line has a timestamp.
    """
    result = IngestResult(source_file)
    batch: list[dict[str, Any]] = []
    undated: list[tuple[int, str]] = []  # lines read before the first timestamp
    previous: ParsedLine | None = None

    for line_no, raw in lines:
        if not raw.strip():
            continue
        result.lines += 1
        entry = parser.parse(raw)
        if entry is None and previous is None:
            undated.append((line_no, raw))
            if len(undated) > MAX_UNDATED_LINES:
                raise NoTimestampsError(
                    f"no timestamp in the first {MAX_UNDATED_LINES} lines: not a log file?"
                )
            continue
        if entry is None:
            entry = _continuation(previous, raw)
        else:
            if previous is None:
                batch.extend(
                    _row(source_file, number, text, _continuation(entry, text))
                    for number, text in undated
                )
                undated.clear()
            previous = entry
        batch.append(_row(source_file, line_no, raw, entry))
        if len(batch) >= batch_size:
            _store(session, source_file, batch, result)
            batch.clear()

    if undated:
        raise NoTimestampsError("no line has a readable timestamp: not a log file?")
    if batch:
        _store(session, source_file, batch, result)
    return result


def _continuation(neighbour: ParsedLine, raw: str) -> ParsedLine:
    """An undated line, filed under the time and host of the dated line next to it."""
    return ParsedLine(ts=neighbour.ts, host=neighbour.host, message=raw)


def _row(source_file: str, line_no: int, raw: str, entry: ParsedLine) -> dict[str, Any]:
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
        "source_file": source_file,
        "line_no": line_no,
        "parsed": entry.parsed,
    }


def _store(
    session: Session, source_file: str, rows: list[dict[str, Any]], result: IngestResult
) -> None:
    """Insert the rows that are not in the database yet and commit."""
    first, last = rows[0]["line_no"], rows[-1]["line_no"]
    stored = dict(
        session.execute(
            select(Event.line_no, Event.raw).where(
                Event.source_file == source_file, Event.line_no.between(first, last)
            )
        ).all()
    )
    fresh = []
    for row in rows:
        known = stored.get(row["line_no"])
        if known is None:
            fresh.append(row)
            if row["parsed"]:
                result.parsed += 1
            else:
                result.unparsed += 1
        elif known == row["raw"]:
            result.duplicates += 1
        else:
            result.conflicts += 1
    if fresh:
        # Insert through the table, not the ORM entity: the ORM leaves None-valued
        # columns out of the statement, which splits a batch into one INSERT per
        # run of rows that happen to have the same empty columns.
        session.execute(insert(Event.__table__), fresh)
    session.commit()
