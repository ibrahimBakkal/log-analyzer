"""Running the rules over the stored events and keeping the alerts table in step.

Alerts are derived data: :func:`evaluate` works out, from the events and the
current rules alone, which alerts should exist, then makes the table match.
Running it twice changes nothing, and an alert keeps its id for as long as the
burst of events behind it stays the same.
"""

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sqlalchemy import ColumnElement, Select, and_, delete, insert, or_, select
from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, Event
from app.rules.evaluators import EventRow, Evidence, create_evaluator
from app.rules.schema import (
    EventFilter,
    KeywordRule,
    PortScanRule,
    RarePortRule,
    Rule,
    SequenceRule,
)


@dataclass
class Detection:
    """An alert in the making: the events of one group that belong together."""

    rule: Rule
    key: str
    evidence: list[Evidence]

    @property
    def first(self) -> Evidence:
        return self.evidence[0]

    @property
    def last(self) -> Evidence:
        return self.evidence[-1]


@dataclass(frozen=True)
class Evaluation:
    """What an evaluation did to the alerts table."""

    total: int
    created: int
    updated: int
    removed: int


def detect(rule: Rule, events: Iterable[EventRow]) -> list[Detection]:
    """Apply one rule to *events*, which must be in time order.

    A detection opens when the rule's condition is met for a group. Later
    events that count for the rule join it for as long as each comes within
    ``cooldown_seconds`` of the one before; after a longer silence the group
    starts from scratch.
    """
    evaluator = create_evaluator(rule)
    allowlisted = _Allowlist(rule)
    open_detections: dict[str, Detection] = {}
    finished: list[Detection] = []

    for event in events:
        if event.src_ip is not None and event.src_ip in allowlisted:
            continue
        key = getattr(event, rule.group_by)
        if not key:
            continue
        spans = evaluator.spans(event, key)
        if spans is None:
            continue
        evidence = Evidence(event.id, event.ts, spans, event.dst_port)

        current = open_detections.get(key)
        if current is not None:
            if (event.ts - current.last.ts).total_seconds() <= rule.cooldown_seconds:
                current.evidence.append(evidence)
                continue
            finished.append(open_detections.pop(key))
        opening = evaluator.trigger(key, evidence, event)
        if opening is not None:
            open_detections[key] = Detection(rule, key, opening)

    finished.extend(open_detections.values())
    return sorted(finished, key=lambda detection: (detection.first.ts, detection.first.event_id))


def evaluate(session: Session, rules: Sequence[Rule]) -> Evaluation:
    """Recompute all alerts from the stored events and the enabled *rules*."""
    detections = [
        detection
        for rule in rules
        if rule.enabled
        for detection in detect(rule, session.execute(_events_for(rule)).yield_per(2000))
    ]

    existing = {alert.key: alert for alert in session.scalars(select(Alert))}
    created = updated = 0
    evidence_rows = []
    for detection in detections:
        key = f"{detection.rule.id}:{detection.key}:{detection.first.event_id}"
        fields = _alert_fields(detection)
        alert = existing.pop(key, None)
        if alert is None:
            alert = Alert(key=key, **fields)
            session.add(alert)
            session.flush()  # assigns the id the evidence rows need
            created += 1
        elif any(getattr(alert, name) != value for name, value in fields.items()):
            for name, value in fields.items():
                setattr(alert, name, value)
            updated += 1
        evidence_rows += [
            {
                "alert_id": alert.id,
                "event_id": item.event_id,
                "spans": [list(s) for s in item.spans],
            }
            for item in detection.evidence
        ]

    for stale in existing.values():
        session.delete(stale)
    # Evidence is rebuilt rather than compared: a changed rule can highlight the
    # same events differently.
    session.execute(delete(AlertEvent))
    if evidence_rows:
        session.execute(insert(AlertEvent.__table__), evidence_rows)
    session.commit()
    return Evaluation(len(detections), created, updated, len(existing))


def _alert_fields(detection: Detection) -> dict[str, object]:
    rule = detection.rule
    count = len(detection.evidence)
    # The rule's own settings (threshold, window_seconds, ...) first, then what was
    # observed, which wins where a name means both ("ports").
    placeholders = {
        name: getattr(rule, name) for name in rule.summary_fields if hasattr(rule, name)
    }
    placeholders |= {
        "key": detection.key,
        "count": count,
        "seconds": int((detection.last.ts - detection.first.ts).total_seconds()),
        "ports": len({item.port for item in detection.evidence if item.port is not None}),
        "rule_id": rule.id,
        "rule_name": rule.name,
    }
    return {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "severity": rule.severity,
        "group_by": rule.group_by,
        "group_key": detection.key,
        "first_seen": detection.first.ts,
        "last_seen": detection.last.ts,
        "count": count,
        "summary": rule.summary_template.format(**placeholders),
    }


def _events_for(rule: Rule) -> Select:
    """The events a rule has to look at, oldest first. The database discards the rest."""
    query = select(
        Event.id,
        Event.ts,
        Event.host,
        Event.service,
        Event.level,
        Event.action,
        Event.user,
        Event.src_ip,
        Event.dst_port,
        Event.message,
    ).order_by(Event.ts, Event.id)
    query = query.where(*_conditions(rule.match))

    if isinstance(rule, KeywordRule):
        # Not for non-ASCII keywords: SQLite only folds the case of ASCII letters,
        # the evaluator folds all of them.
        if rule.regex is None and all(map(str.isascii, rule.keywords)):
            contains = (Event.message.icontains(word, autoescape=True) for word in rule.keywords)
            query = query.where(or_(*contains))
    elif isinstance(rule, SequenceRule):
        query = query.where(or_(*(and_(*_conditions(step.match)) for step in rule.steps)))
    elif isinstance(rule, PortScanRule):
        query = query.where(Event.dst_port.is_not(None))
    elif isinstance(rule, RarePortRule):
        listed = Event.dst_port.in_(rule.ports)
        query = query.where(
            listed if rule.mode == "watchlist" else Event.dst_port.not_in(rule.ports)
        )
    return query


def _conditions(wanted: EventFilter) -> list[ColumnElement[bool]]:
    return [getattr(Event, name).in_(accepted) for name, accepted in wanted if accepted]


class _Allowlist:
    """``address in allowlist`` for the networks of a rule, remembering earlier answers."""

    def __init__(self, rule: Rule) -> None:
        self._networks = rule.allowlist
        self._known: dict[str, bool] = {}

    def __contains__(self, address: str) -> bool:
        if not self._networks:
            return False
        answer = self._known.get(address)
        if answer is None:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:  # a host name: cannot be on an address list
                answer = False
            else:
                answer = any(ip.version == net.version and ip in net for net in self._networks)
            self._known[address] = answer
        return answer
