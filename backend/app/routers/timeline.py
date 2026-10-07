"""GET /timeline: how many events happened when."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import Integer, case, cast, func, select

from app.enums import Level
from app.models import Event
from app.routers import SessionDep
from app.routers._filters import EventFilters
from app.schemas import Timeline, TimelineBucket

router = APIRouter(tags=["timeline"])

MAX_BUCKETS = 5000


class BucketWidth(StrEnum):
    MINUTE = "1m"
    FIVE_MINUTES = "5m"
    HOUR = "1h"

    @property
    def seconds(self) -> int:
        return {"1m": 60, "5m": 300, "1h": 3600}[self.value]


@router.get("/timeline")
def timeline(
    session: SessionDep,
    filters: Annotated[EventFilters, Depends()],
    bucket: BucketWidth = BucketWidth.FIVE_MINUTES,
) -> Timeline:
    """Count the selected events per time bucket, for a density chart.

    Only buckets that contain events are returned. `warnings` is the part of
    `count` that is suspicious on its own: failed logins, invalid users, denied sudo.
    """
    if session.get_bind().dialect.name == "sqlite":
        epoch = cast(func.strftime("%s", Event.ts), Integer)
    else:
        epoch = cast(func.extract("epoch", Event.ts), Integer)
    start = ((epoch // bucket.seconds) * bucket.seconds).label("start")
    warnings = func.sum(case((Event.level == Level.WARNING, 1), else_=0))

    query = filters.apply(select(start, func.count(), warnings)).group_by(start).order_by(start)
    rows = session.execute(query.limit(MAX_BUCKETS + 1)).all()
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
