"""GET /timeline: how many events happened when."""

from dataclasses import fields
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import Integer, case, cast, func, select, text
from sqlalchemy.orm import Session

from app.enums import Level
from app.models import Event
from app.routers import SessionDep
from app.routers._filters import EventFilters, as_utc
from app.schemas import Timeline, TimelineBucket

router = APIRouter(tags=["timeline"])

MAX_BUCKETS = 5000
# The quick way of counting asks about every bucket of the range, empty or not.
# Beyond this many it is no longer the quick way.
MAX_PROBES = 50_000


class BucketWidth(StrEnum):
    MINUTE = "1m"
    FIVE_MINUTES = "5m"
    HOUR = "1h"
    DAY = "1d"

    @property
    def seconds(self) -> int:
        return {"1m": 60, "5m": 300, "1h": 3600, "1d": 86400}[self.value]


@router.get("/timeline")
def timeline(
    session: SessionDep,
    filters: Annotated[EventFilters, Depends()],
    bucket: BucketWidth = BucketWidth.FIVE_MINUTES,
) -> Timeline:
    """Count the selected events per time bucket, for a density chart.

    Only buckets that contain events are returned. `warnings` is the part of
    `count` that is suspicious on its own: failed logins, invalid users, denied
    sudo, packets the firewall blocked.
    """
    rows = None
    if session.get_bind().dialect.name == "sqlite" and _only_by_time(filters):
        rows = _count_by_range(session, filters, bucket.seconds)
    if rows is None:
        rows = _count_by_grouping(session, filters, bucket.seconds)
    if len(rows) > MAX_BUCKETS:
        raise HTTPException(
            status_code=422,
            detail=f"more than {MAX_BUCKETS} buckets: use a wider bucket or a shorter time range",
        )
    return Timeline(
        bucket_seconds=bucket.seconds,
        buckets=[
            TimelineBucket(ts=datetime.fromtimestamp(first, UTC), count=count, warnings=warned)
            for first, count, warned in rows
        ],
    )


def _only_by_time(filters: EventFilters) -> bool:
    return all(
        getattr(filters, field.name) is None
        for field in fields(filters)
        if field.name not in ("start", "end")
    )


def _count_by_grouping(
    session: Session, filters: EventFilters, seconds: int
) -> list[tuple[int, int, int]]:
    """Group the selected events by bucket. Works with every filter and database."""
    if session.get_bind().dialect.name == "sqlite":
        epoch = cast(func.strftime("%s", Event.ts), Integer)
    else:
        epoch = cast(func.extract("epoch", Event.ts), Integer)
    start = ((epoch // seconds) * seconds).label("start")
    warnings = func.sum(case((Event.level == Level.WARNING, 1), else_=0))
    query = filters.apply(select(start, func.count(), warnings)).group_by(start).order_by(start)
    return [tuple(row) for row in session.execute(query.limit(MAX_BUCKETS + 1)).all()]


# One count per bucket, each answered from an index without touching a row: the
# time index for all events, the (level, ts) index for the warnings. On a
# million events this takes a tenth of the time grouping does, because grouping
# has to compute the bucket of every single row.
#
# Times are stored as text ("2026-09-09 03:12:39.000000"), and datetime() writes
# the bucket's edges the same way up to the second, so plain comparison works.
#
# The first and last bucket are cut at the requested range by moving their
# edges, not by adding conditions: given "ts >= bucket AND ts >= :lowest", the
# database may pick the second as the place to start reading the index, and
# then every bucket reads from the start of the range.
_RANGE_COUNTS = text(
    """
    WITH RECURSIVE bucket(start) AS (
        SELECT :first UNION ALL SELECT start + :width FROM bucket WHERE start + :width <= :last
    )
    SELECT start,
           (SELECT count(*) FROM events
             WHERE ts >= max(datetime(start, 'unixepoch'), :lowest)
               AND ts < min(datetime(start + :width, 'unixepoch'), :highest)),
           (SELECT count(*) FROM events
             WHERE level = 'warning'
               AND ts >= max(datetime(start, 'unixepoch'), :lowest)
               AND ts < min(datetime(start + :width, 'unixepoch'), :highest))
      FROM bucket
    """
)
_STORED = "%Y-%m-%d %H:%M:%S.%f"  # how SQLAlchemy writes a DateTime into SQLite
# Sorts after every stored time. Written out in full on purpose: a text that
# looks like a number ("9999") would be compared as one, and no text is less
# than a number.
_NO_END = "9999-12-31 23:59:59.999999"


def _count_by_range(
    session: Session, filters: EventFilters, seconds: int
) -> list[tuple[int, int, int]] | None:
    """Count bucket by bucket; ``None`` if the range is too long for that to pay off."""
    in_range = []
    if filters.start is not None:
        in_range.append(Event.ts >= as_utc(filters.start))
    if filters.end is not None:
        in_range.append(Event.ts < as_utc(filters.end))
    first = session.scalar(select(func.min(Event.ts)).where(*in_range))
    last = session.scalar(select(func.max(Event.ts)).where(*in_range))
    if first is None or last is None:
        return []

    first_bucket = int(first.timestamp()) // seconds * seconds
    if (int(last.timestamp()) - first_bucket) // seconds >= MAX_PROBES:
        return None
    lowest = as_utc(filters.start or first).astimezone(UTC)
    highest = as_utc(filters.end).astimezone(UTC) if filters.end else None
    rows = session.execute(
        _RANGE_COUNTS,
        {
            "first": first_bucket,
            "last": int(last.timestamp()),
            "width": seconds,
            "lowest": lowest.strftime(_STORED),
            "highest": highest.strftime(_STORED) if highest else _NO_END,
        },
    )
    return [(start, count, warned) for start, count, warned in rows if count]
