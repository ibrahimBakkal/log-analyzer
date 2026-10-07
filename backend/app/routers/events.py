"""GET /events: stored log lines in time order, filtered and paginated."""

import base64
from dataclasses import replace
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, tuple_

from app.models import Event
from app.routers import SessionDep
from app.routers._filters import EventFilters, as_utc
from app.routers._present import present_events
from app.schemas import EventPage

router = APIRouter(tags=["events"])

MAX_LIMIT = 500


def _encode_cursor(event: Event) -> str:
    """An opaque token naming the last event of a page: its time and id."""
    return base64.urlsafe_b64encode(f"{event.ts.isoformat()}|{event.id}".encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        stamp, _, event_id = base64.urlsafe_b64decode(cursor).decode().partition("|")
        ts = datetime.fromisoformat(stamp)
        if ts.tzinfo is None:
            raise ValueError("cursor time has no zone")
        return ts, int(event_id)
    except ValueError:  # also covers bad base64 and bad UTF-8
        raise HTTPException(status_code=400, detail="invalid cursor") from None


@router.get("/events")
def list_events(
    session: SessionDep,
    filters: Annotated[EventFilters, Depends()],
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 100,
    cursor: Annotated[str | None, Query(description="`next_cursor` of the previous page.")] = None,
    order: Annotated[
        Literal["asc", "desc"],
        Query(description="`asc`: oldest first. `desc`: newest first, for watching a log grow."),
    ] = "asc",
) -> EventPage:
    """List events in chronological order, or newest first.

    Pages are fetched with a cursor rather than an offset, so paging stays fast
    on large tables and no event is skipped or repeated while new ones arrive.

    An event that is evidence for an alert carries `highlights`: the alert, its
    rule and the part of the message that made it count.
    """
    position = tuple_(Event.ts, Event.id)
    after = None
    if cursor is not None:
        ts, event_id = _decode_cursor(cursor)
        # The cursor is a tighter bound than the time filter on the same side.
        # Left in, that filter can make the database start its search at the
        # beginning of the range instead of at the cursor.
        if order == "asc":
            after = position > (ts, event_id)
            if filters.start is None or ts >= as_utc(filters.start):
                filters = replace(filters, start=None)
        else:
            after = position < (ts, event_id)
            if filters.end is None or ts < as_utc(filters.end):
                filters = replace(filters, end=None)

    query = filters.apply(select(Event))
    if order == "asc":
        query = query.order_by(Event.ts, Event.id)
    else:
        query = query.order_by(Event.ts.desc(), Event.id.desc())
    if after is not None:
        query = query.where(after)

    # One extra row tells us whether another page follows.
    events = session.scalars(query.limit(limit + 1)).all()
    page = events[:limit]
    more = len(events) > limit
    return EventPage(
        items=present_events(session, page),
        next_cursor=_encode_cursor(page[-1]) if more else None,
    )
