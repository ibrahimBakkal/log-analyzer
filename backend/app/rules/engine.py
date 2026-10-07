"""Running the rules over the stored events and keeping the alerts table in step.

Alerts are derived data: :func:`evaluate` works out, from the events and the
current rules alone, which alerts should exist, then makes the table match.
Running it twice changes nothing, and an alert keeps its id for as long as the
burst of events behind it stays the same.
"""

import hashlib
import ipaddress
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import ColumnElement, Select, and_, delete, func, insert, or_, select
from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, Event, State
from app.rules.evaluators import EventRow, Evidence, create_evaluator
from app.rules.loader import RuleSet
from app.rules.scan import KeywordScan
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


def evaluate(session: Session, rules: Sequence[Rule], *, since: int | None = None) -> Evaluation:
    """Make the alerts table what the stored events and the enabled *rules* say it should be.

    Without *since*, every alert is worked out again from scratch.

    With *since* (an event id), only what events with a larger id can have
    changed is worked out again. Every rule looks at one group at a time (one
    source address, one user) and groups do not influence each other, so it is
    enough to redo the groups the new events belong to, each from its first
    event on. The outcome is the same as that of a full run, provided the rules
    are the ones the stored alerts were made with; :class:`AlertKeeper` sees to that.
    """
    enabled = [rule for rule in rules if rule.enabled]
    lines = _lines_with_keywords(session, enabled, since)
    created = updated = removed = 0
    for rule in enabled:
        if isinstance(rule, KeywordRule):
            work = _keyword_work(session, rule, lines[rule.id], since)
            if work is None:
                continue
            groups, events = work
        else:
            groups = None if since is None else _groups_with_news(session, rule, since)
            if groups is not None and not groups:
                continue
            if groups is None:
                events = session.execute(_events_for(rule)).yield_per(2000)
            else:
                events = _events_of_groups(session, rule, groups)
        counts = _reconcile(session, rule, groups, detect(rule, events))
        created, updated, removed = (
            created + counts[0],
            updated + counts[1],
            removed + counts[2],
        )

    if since is None:
        # Alerts of rules that are gone or switched off.
        in_use = [rule.id for rule in enabled]
        orphans = session.scalars(select(Alert).where(Alert.rule_id.not_in(in_use))).all()
        for orphan in orphans:
            session.delete(orphan)
        removed += len(orphans)
    session.commit()
    total = session.scalar(select(func.count()).select_from(Alert)) or 0
    return Evaluation(total, created, updated, removed)


def _reconcile(
    session: Session, rule: Rule, groups: Sequence[str] | None, detections: list[Detection]
) -> tuple[int, int, int]:
    """Make the alerts of *rule* (of the given groups only, if any) match *detections*."""
    in_scope = [Alert.rule_id == rule.id]
    if groups is not None:
        in_scope.append(Alert.group_key.in_(groups))
    existing = {alert.key: alert for alert in session.scalars(select(Alert).where(*in_scope))}
    # Evidence is rebuilt rather than compared: a changed rule can highlight the
    # same events differently.
    session.execute(
        delete(AlertEvent).where(AlertEvent.alert_id.in_(select(Alert.id).where(*in_scope)))
    )

    created = updated = 0
    evidence_rows = []
    for detection in detections:
        key = f"{rule.id}:{detection.key}:{detection.first.event_id}"
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
                "spans": [list(span) for span in item.spans],
            }
            for item in detection.evidence
        ]

    for stale in existing.values():
        session.delete(stale)
    session.flush()
    if evidence_rows:
        session.execute(insert(AlertEvent.__table__), evidence_rows)
    return created, updated, len(existing)


class AlertKeeper:
    """Keeps the alerts in step with the events, doing as little as it may.

    Redoing only the groups with new events is right as long as the rules have
    not changed since the alerts were made. So the database remembers a
    fingerprint of the rules its alerts were made with; whenever the rules in
    use are different (a reload, or rule files edited while the server was
    down), everything is redone.

    One evaluation at a time: an upload and the file follower would otherwise
    overwrite each other's work.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def refresh(self, session: Session, rules: RuleSet, *, since: int | None) -> Evaluation:
        """Bring the alerts up to date. *since*: the highest event id before the new events."""
        with self._lock:
            fingerprint = rules_fingerprint(rules)
            current = session.get(State, _RULES_KEY)
            everything = since is None or current is None or current.value != fingerprint
            outcome = evaluate(session, rules.enabled, since=None if everything else since)
            if current is None:
                session.add(State(key=_RULES_KEY, value=fingerprint))
            elif current.value != fingerprint:
                current.value = fingerprint
            session.commit()
            return outcome


_RULES_KEY = "rules"


def rules_fingerprint(rules: RuleSet) -> str:
    """Changes whenever a rule that is in use changes, appears or goes away."""
    described = sorted(rule.model_dump_json() for rule in rules.enabled)
    return hashlib.sha256("\n".join(described).encode()).hexdigest()


def latest_event_id(session: Session) -> int:
    """The id to pass as ``since`` later: taken before new events are stored."""
    return session.scalar(select(func.max(Event.id))) or 0


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


# A batch of new lines with more groups than this is not worth picking apart:
# the rule is run over everything instead.
MAX_GROUPS = 200

_COLUMNS = (
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
)


# Up to this many events of a few groups are put in time order here rather than
# by the database.
MAX_SORTED_HERE = 100_000


def _events_for(rule: Rule) -> Select:
    """The events a rule has to look at, oldest first. The database discards the rest."""
    return select(*_COLUMNS).where(*_selection(rule)).order_by(Event.ts, Event.id)


def _events_of_groups(session: Session, rule: Rule, groups: Sequence[str]) -> Iterable[EventRow]:
    """The events of *groups* that *rule* has to look at, oldest first.

    Asked for them in time order, SQLite tends to walk the time index and throw
    away what belongs to other groups: every event of the kind, to find a
    handful. Asked for them in any order, it goes straight to the groups. So
    they are fetched unordered and sorted here, unless there are so many that
    holding them all at once would cost more memory than the detour saves time.
    """
    wanted = select(*_COLUMNS).where(*_selection(rule), getattr(Event, rule.group_by).in_(groups))
    found = session.execute(wanted.limit(MAX_SORTED_HERE + 1)).all()
    if len(found) <= MAX_SORTED_HERE:
        return sorted(found, key=lambda event: (event.ts, event.id))
    return session.execute(wanted.order_by(Event.ts, Event.id)).yield_per(2000)


def _groups_with_news(session: Session, rule: Rule, since: int) -> list[str] | None:
    """The groups that have events newer than *since* for *rule*; ``None`` if too many to list."""
    group = getattr(Event, rule.group_by)
    found = session.scalars(
        select(group)
        .where(Event.id > since, group.is_not(None), *_selection(rule))
        .distinct()
        .limit(MAX_GROUPS + 1)
    ).all()
    return None if len(found) > MAX_GROUPS else list(found)


def _selection(rule: Rule) -> list[ColumnElement[bool]]:
    """What the database can already tell about which events matter to a rule.

    For a keyword rule that is little: which lines have its keywords is found
    by reading them (see :func:`_lines_with_keywords`).
    """
    conditions = _conditions(rule.match)
    if isinstance(rule, SequenceRule):
        conditions.append(or_(*(and_(*_conditions(step.match)) for step in rule.steps)))
    elif isinstance(rule, PortScanRule):
        conditions.append(Event.dst_port.is_not(None))
    elif isinstance(rule, RarePortRule):
        listed = Event.dst_port.in_(rule.ports)
        conditions.append(listed if rule.mode == "watchlist" else Event.dst_port.not_in(rule.ports))
    return conditions


# --- keyword rules ----------------------------------------------------------------------------

# A keyword rule with more candidate lines than this is given every line instead.
MAX_CANDIDATES = 50_000

Candidates = dict[str, list[int] | None]  # rule id -> event ids, or None for "too many to list"


def _lines_with_keywords(session: Session, rules: Sequence[Rule], since: int | None) -> Candidates:
    """The lines each keyword rule among *rules* may count, of those newer than *since* if given.

    One pass over the lines serves all the rules; see :mod:`app.rules.scan`.
    """
    keyword_rules = [rule for rule in rules if isinstance(rule, KeywordRule)]
    found: Candidates = {rule.id: [] for rule in keyword_rules}
    if not keyword_rules:
        return found

    lines = select(Event.id, Event.service, Event.message)
    if since is not None:
        lines = lines.where(Event.id > since)
    # Asked of the connection rather than the session: a million rows pass
    # through here, and the session spends twice as long on each as reading it takes.
    connection = session.connection()
    sample = connection.execute(lines.limit(_SAMPLE)).all()
    scan = KeywordScan(keyword_rules, sample)
    rows = connection.execution_options(stream_results=True).execute(lines)
    for event_id, number in scan.candidates(rows):  # type: ignore[arg-type]
        ids = found[keyword_rules[number].id]
        if ids is not None:
            ids.append(event_id)
            if len(ids) > MAX_CANDIDATES:
                found[keyword_rules[number].id] = None
    return found


_SAMPLE = 2000  # lines looked at to learn which characters are rare in this log


def _keyword_work(
    session: Session, rule: KeywordRule, candidates: list[int] | None, since: int | None
) -> tuple[Sequence[str] | None, Iterable[EventRow]] | None:
    """What a keyword rule has to be run on: (the groups to redo, their events in time order).

    No groups means all of them; ``None`` altogether means there is nothing to do.

    After new lines, the groups to redo are those of the new candidates, and a
    group's earlier lines need not be searched for again: every line a keyword
    rule counts is evidence of one of its alerts, so the alerts already name them.
    """
    if since is None:
        if candidates is None:
            return None, session.execute(_events_for(rule)).yield_per(2000)
        return None, _events_by_id(session, rule, candidates)

    if candidates is not None and not candidates:
        return None
    group = getattr(Event, rule.group_by)
    groups = None
    if candidates is not None:
        groups = _distinct(session, group, candidates, _selection(rule))
    if groups is not None and not groups:
        return None
    earlier = None
    if groups is not None:
        earlier = session.scalars(
            select(AlertEvent.event_id)
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .where(Alert.rule_id == rule.id, Alert.group_key.in_(groups))
            .limit(MAX_CANDIDATES + 1)
        ).all()
    if candidates is None or groups is None or earlier is None or len(earlier) > MAX_CANDIDATES:
        # Too much to pick apart: the rule starts over, on all lines.
        everything = _lines_with_keywords(session, [rule], None)[rule.id]
        return _keyword_work(session, rule, everything, None)
    wanted = sorted({*candidates, *earlier})
    return groups, _events_by_id(session, rule, wanted, group.in_(groups))


def _events_by_id(
    session: Session, rule: Rule, ids: Sequence[int], *more: ColumnElement[bool]
) -> list[EventRow]:
    """The events with these *ids* that pass the rule's filter, oldest first."""
    found: list[EventRow] = []
    for start in range(0, len(ids), _IDS_PER_QUERY):
        chunk = ids[start : start + _IDS_PER_QUERY]
        found += session.execute(
            select(*_COLUMNS).where(Event.id.in_(chunk), *_selection(rule), *more)
        ).all()  # type: ignore[arg-type]
    return sorted(found, key=lambda event: (event.ts, event.id))


def _distinct(
    session: Session, column: Any, ids: Sequence[int], conditions: Sequence[ColumnElement[bool]]
) -> list[str] | None:
    """The values *column* has among the events with these *ids*; ``None`` beyond MAX_GROUPS."""
    values: set[str] = set()
    for start in range(0, len(ids), _IDS_PER_QUERY):
        chunk = ids[start : start + _IDS_PER_QUERY]
        values.update(
            session.scalars(
                select(column)
                .where(Event.id.in_(chunk), column.is_not(None), *conditions)
                .distinct()
            )
        )
        if len(values) > MAX_GROUPS:
            return None
    return sorted(values)


_IDS_PER_QUERY = 5000  # well below the number of values SQLite accepts in one statement


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
