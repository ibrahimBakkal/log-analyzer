"""GET /alerts: what the rules found."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.enums import Severity
from app.models import Alert, AlertEvent, Event
from app.routers import SessionDep
from app.routers._filters import as_utc
from app.routers._present import present_events
from app.schemas import AlertList, AlertOut

router = APIRouter(tags=["alerts"])

MAX_LIMIT = 500
EVIDENCE_PER_ALERT = 100


@router.get("/alerts")
def list_alerts(
    session: SessionDep,
    rule_id: str | None = None,
    severity: Severity | None = None,
    group_key: Annotated[
        str | None, Query(description="The value alerts are about, e.g. a source address.")
    ] = None,
    start: Annotated[
        datetime | None,
        Query(description="Only alerts still active at or after this time. UTC if no offset."),
    ] = None,
    end: Annotated[
        datetime | None,
        Query(description="Only alerts that began before this time. UTC if no offset."),
    ] = None,
    include_events: Annotated[
        bool,
        Query(
            description=f"Attach each alert's first {EVIDENCE_PER_ALERT} evidence events. "
            "`GET /events?alert_id=` pages through all of them."
        ),
    ] = False,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 100,
) -> AlertList:
    """List alerts, newest first."""
    query = select(Alert)
    if rule_id is not None:
        query = query.where(Alert.rule_id == rule_id)
    if severity is not None:
        query = query.where(Alert.severity == severity)
    if group_key is not None:
        query = query.where(Alert.group_key == group_key)
    if start is not None:
        query = query.where(Alert.last_seen >= as_utc(start))
    if end is not None:
        query = query.where(Alert.first_seen < as_utc(end))

    total = session.scalar(select(func.count()).select_from(query.subquery()))
    alerts = session.scalars(
        query.order_by(Alert.first_seen.desc(), Alert.id.desc()).limit(limit)
    ).all()

    items = [AlertOut.model_validate(alert) for alert in alerts]
    if include_events:
        for item in items:
            evidence = session.scalars(
                select(Event)
                .join(AlertEvent, AlertEvent.event_id == Event.id)
                .where(AlertEvent.alert_id == item.id)
                .order_by(Event.ts, Event.id)
                .limit(EVIDENCE_PER_ALERT)
            ).all()
            item.events = present_events(session, evidence)
    return AlertList(items=items, total=total or 0)
