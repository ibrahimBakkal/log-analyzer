"""The event filters shared by /events, /timeline and /stats."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Query
from sqlalchemy import Select, or_, select

from app.enums import Action, Level
from app.models import Alert, AlertEvent, Event


def as_utc(moment: datetime) -> datetime:
    """Times given without an offset are taken to be UTC."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


@dataclass
class EventFilters:
    """Query parameters that select events. Use as ``Annotated[EventFilters, Depends()]``."""

    start: Annotated[
        datetime | None,
        Query(description="Only events at or after this time. ISO 8601; UTC if no offset."),
    ] = None
    end: Annotated[
        datetime | None,
        Query(description="Only events before this time. ISO 8601; UTC if no offset."),
    ] = None
    host: Annotated[str | None, Query()] = None
    service: Annotated[str | None, Query(description="Program name, e.g. sshd.")] = None
    ip: Annotated[str | None, Query(description="Source or destination address.")] = None
    level: Annotated[Level | None, Query()] = None
    action: Annotated[Action | None, Query()] = None
    parsed: Annotated[
        bool | None, Query(description="false: only lines that no pattern recognized.")
    ] = None
    alert_id: Annotated[int | None, Query(description="Only the evidence of this alert.")] = None
    rule_id: Annotated[
        str | None, Query(description="Only events that are evidence for alerts of this rule.")
    ] = None

    def apply(self, query: Select) -> Select:
        """Narrow a query on :class:`Event` down to the selected events."""
        if self.start is not None:
            query = query.where(Event.ts >= as_utc(self.start))
        if self.end is not None:
            query = query.where(Event.ts < as_utc(self.end))
        if self.host is not None:
            query = query.where(Event.host == self.host)
        if self.service is not None:
            query = query.where(Event.service == self.service)
        if self.ip is not None:
            query = query.where(or_(Event.src_ip == self.ip, Event.dst_ip == self.ip))
        if self.level is not None:
            query = query.where(Event.level == self.level)
        if self.action is not None:
            query = query.where(Event.action == self.action)
        if self.parsed is not None:
            query = query.where(Event.parsed == self.parsed)
        if self.alert_id is not None:
            evidence = select(AlertEvent.event_id).where(AlertEvent.alert_id == self.alert_id)
            query = query.where(Event.id.in_(evidence))
        if self.rule_id is not None:
            evidence = (
                select(AlertEvent.event_id)
                .join(Alert, Alert.id == AlertEvent.alert_id)
                .where(Alert.rule_id == self.rule_id)
            )
            query = query.where(Event.id.in_(evidence))
        return query
