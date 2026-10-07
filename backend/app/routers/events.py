"""GET /events: stored log lines, oldest first, filtered and paginated."""

import base64
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import and_, or_, select

from app.enums import Action, Level
from app.models import Event
from app.routers import SessionDep
from app.schemas import EventPage

router = APIRouter(tags=["events"])

MAX_LIMIT = 500


def _as_utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


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
    start: Annotated[
        datetime | None,
        Query(description="Only events at or after this time. ISO 8601; UTC if no offset."),
    ] = None,
    end: Annotated[
        datetime | None,
        Query(description="Only events before this time. ISO 8601; UTC if no offset."),
    ] = None,
    host: str | None = None,
    service: Annotated[str | None, Query(description="Program name, e.g. sshd.")] = None,
    ip: Annotated[str | None, Query(description="Source or destination address.")] = None,
    level: Level | None = None,
    action: Action | None = None,
    parsed: Annotated[
        bool | None, Query(description="false: only lines that no pattern recognized.")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 100,
    cursor: Annotated[str | None, Query(description="`next_cursor` of the previous page.")] = None,
) -> EventPage:
    """List events in chronological order.

    Pages are fetched with a cursor rather than an offset, so paging stays fast
    on large tables and no event is skipped or repeated while new ones arrive.
    """
    query = select(Event).order_by(Event.ts, Event.id)
    if start is not None:
        query = query.where(Event.ts >= _as_utc(start))
    if end is not None:
        query = query.where(Event.ts < _as_utc(end))
    if host is not None:
        query = query.where(Event.host == host)
    if service is not None:
        query = query.where(Event.service == service)
    if ip is not None:
        query = query.where(or_(Event.src_ip == ip, Event.dst_ip == ip))
    if level is not None:
        query = query.where(Event.level == level)
    if action is not None:
        query = query.where(Event.action == action)
    if parsed is not None:
        query = query.where(Event.parsed == parsed)
    if cursor is not None:
        ts, event_id = _decode_cursor(cursor)
        query = query.where(or_(Event.ts > ts, and_(Event.ts == ts, Event.id > event_id)))

    # One extra row tells us whether another page follows.
    events = session.scalars(query.limit(limit + 1)).all()
    page = events[:limit]
    more = len(events) > limit
    return EventPage(items=page, next_cursor=_encode_cursor(page[-1]) if more else None)
