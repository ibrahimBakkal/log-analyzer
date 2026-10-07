"""Turning stored events into API objects, with their highlights attached."""

from collections import defaultdict
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, Event
from app.schemas import EventOut, Highlight

_CHUNK = 500  # stay well below the number of parameters a database accepts per query


def present_events(session: Session, events: Sequence[Event]) -> list[EventOut]:
    """Convert *events* for the API. An event that is evidence for alerts says which,
    and which parts of its message matter."""
    marks: defaultdict[int, list[Highlight]] = defaultdict(list)
    ids = [event.id for event in events]
    for offset in range(0, len(ids), _CHUNK):
        rows = session.execute(
            select(
                AlertEvent.event_id,
                AlertEvent.alert_id,
                AlertEvent.spans,
                Alert.rule_id,
                Alert.severity,
            )
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .where(AlertEvent.event_id.in_(ids[offset : offset + _CHUNK]))
            .order_by(AlertEvent.alert_id)
        )
        for event_id, alert_id, spans, rule_id, severity in rows:
            # No span: the event is evidence as a whole, without a part to point at.
            for start, end in spans or [(None, None)]:
                marks[event_id].append(
                    Highlight(
                        alert_id=alert_id, rule_id=rule_id, severity=severity, start=start, end=end
                    )
                )
    return [
        EventOut.model_validate(event).model_copy(update={"highlights": marks.get(event.id, [])})
        for event in events
    ]
