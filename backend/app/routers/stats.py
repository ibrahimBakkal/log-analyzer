"""GET /stats: the numbers for a dashboard."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.enums import Action
from app.models import Alert, Event
from app.routers import SessionDep
from app.routers._filters import as_utc
from app.schemas import SourceStats, Stats

router = APIRouter(tags=["stats"])

TOP_SOURCES = 5


@router.get("/stats")
def stats(
    session: SessionDep,
    start: Annotated[
        datetime | None, Query(description="Only count from this time on. UTC if no offset.")
    ] = None,
    end: Annotated[
        datetime | None, Query(description="Only count up to this time. UTC if no offset.")
    ] = None,
) -> Stats:
    """Totals over all events and alerts, or over those of a time range."""
    in_range = []
    alert_in_range = []
    if start is not None:
        in_range.append(Event.ts >= as_utc(start))
        alert_in_range.append(Alert.last_seen >= as_utc(start))
    if end is not None:
        in_range.append(Event.ts < as_utc(end))
        alert_in_range.append(Alert.first_seen < as_utc(end))

    # Asked one by one, each of these is answered from an index alone. Asked
    # together they would force a pass over every row of the table.
    events = session.scalar(select(func.count()).select_from(Event).where(*in_range)) or 0
    first = session.scalar(select(func.min(Event.ts)).where(*in_range))
    last = session.scalar(select(func.max(Event.ts)).where(*in_range))
    # A line is "parsed" exactly when a pattern gave it an action.
    parsed = (
        session.scalar(
            select(func.count()).select_from(Event).where(Event.action.is_not(None), *in_range)
        )
        or 0
    )
    sources = session.scalar(select(func.count(func.distinct(Event.src_ip))).where(*in_range)) or 0
    actions = dict(
        session.execute(
            select(Event.action, func.count())
            .where(Event.action.is_not(None), *in_range)
            .group_by(Event.action)
        ).all()
    )
    severities = dict(
        session.execute(
            select(Alert.severity, func.count()).where(*alert_in_range).group_by(Alert.severity)
        ).all()
    )

    by_source = Event.src_ip.is_not(None)
    totals = (
        select(Event.src_ip, func.count().label("events"))
        .where(by_source, *in_range)
        .group_by(Event.src_ip)
        .subquery()
    )
    failed = (
        select(Event.src_ip, func.count().label("failures"))
        .where(Event.action == Action.AUTH_FAIL, by_source, *in_range)
        .group_by(Event.src_ip)
        .subquery()
    )
    failures = func.coalesce(failed.c.failures, 0)
    top = session.execute(
        select(totals.c.src_ip, totals.c.events, failures)
        .outerjoin(failed, failed.c.src_ip == totals.c.src_ip)
        .order_by(failures.desc(), totals.c.events.desc(), totals.c.src_ip)
        .limit(TOP_SOURCES)
    ).all()

    return Stats(
        events=events,
        parsed=parsed,
        unparsed=events - parsed,
        unparsed_ratio=round((events - parsed) / events, 4) if events else 0.0,
        first_event=first,
        last_event=last,
        sources=sources,
        actions=actions,
        alerts=sum(severities.values()),
        alerts_by_severity=severities,
        top_sources=[
            SourceStats(src_ip=address, events=count, failures=failed)
            for address, count, failed in top
        ],
    )
