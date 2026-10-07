"""Evaluators decide, event by event, whether a rule's condition has been met.

The engine (see ``engine.py``) feeds an evaluator the events of one group, for
example one source address, in time order. An evaluator answers two questions:

* :meth:`Evaluator.spans` -- does this event count for the rule, and which part
  of its message should be highlighted?
* :meth:`Evaluator.trigger` -- now that it counts, is the condition met?
"""

import re
from abc import ABC, abstractmethod
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Generic, Protocol, TypeVar

from app.enums import Action, Level
from app.rules.schema import (
    KeywordRule,
    PortScanRule,
    RarePortRule,
    Rule,
    SequenceRule,
    ThresholdRule,
)

Span = tuple[int, int]  # [start, end) character positions in an event's message

R = TypeVar("R", KeywordRule, ThresholdRule, SequenceRule, PortScanRule, RarePortRule)


class EventRow(Protocol):
    """The event columns rules can see."""

    id: int
    ts: datetime
    host: str | None
    service: str | None
    level: Level
    action: Action | None
    user: str | None
    src_ip: str | None
    dst_port: int | None
    message: str


@dataclass(frozen=True, slots=True)
class Evidence:
    """An event that counts toward an alert."""

    event_id: int
    ts: datetime
    spans: tuple[Span, ...]
    port: int | None = None  # the event's destination port, for rules about ports


class Evaluator(ABC, Generic[R]):
    def __init__(self, rule: R) -> None:
        self.rule = rule

    @abstractmethod
    def spans(self, event: EventRow, key: str) -> tuple[Span, ...] | None:
        """Return what to highlight if *event* counts for the rule, else ``None``."""

    @abstractmethod
    def trigger(self, key: str, evidence: Evidence, event: EventRow) -> list[Evidence] | None:
        """Take note of a counting event; return the evidence for a new alert once
        the rule's condition is met for the group *key*, else ``None``."""


def merge_spans(spans: list[Span]) -> tuple[Span, ...]:
    """Sort spans and join the ones that overlap or touch."""
    merged: list[Span] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


class KeywordEvaluator(Evaluator[KeywordRule]):
    """Every line containing one of the keywords, or matching the regex, counts and alerts."""

    def __init__(self, rule: KeywordRule) -> None:
        super().__init__(rule)
        self._patterns: list[re.Pattern[str]] = []
        if rule.keywords:
            # Longest first, so that "shadow" does not win over "/etc/shadow".
            words = sorted(rule.keywords, key=len, reverse=True)
            self._patterns.append(re.compile("|".join(map(re.escape, words)), re.IGNORECASE))
        if rule.regex is not None:
            self._patterns.append(re.compile(rule.regex))

    def spans(self, event: EventRow, key: str) -> tuple[Span, ...] | None:
        found = [
            match.span()
            for pattern in self._patterns
            for match in pattern.finditer(event.message)
            if match.end() > match.start()  # a regex may match the empty string
        ]
        return merge_spans(found) or None

    def trigger(self, key: str, evidence: Evidence, event: EventRow) -> list[Evidence] | None:
        return [evidence]


class ThresholdEvaluator(Evaluator[ThresholdRule]):
    """``threshold`` matching events of one group within ``window_seconds``.

    A sliding window per group holds the events of the last ``window_seconds``.
    Two events exactly ``window_seconds`` apart are *not* in the same window.
    """

    def __init__(self, rule: ThresholdRule) -> None:
        super().__init__(rule)
        self._recent: defaultdict[str, deque[Evidence]] = defaultdict(deque)

    def spans(self, event: EventRow, key: str) -> tuple[Span, ...] | None:
        # Every event the rule's filter let through counts; point at the group's value.
        return _span_of(event.message, key)

    def trigger(self, key: str, evidence: Evidence, event: EventRow) -> list[Evidence] | None:
        window = self._recent[key]
        window.append(evidence)
        while (evidence.ts - window[0].ts).total_seconds() >= self.rule.window_seconds:
            window.popleft()
        if len(window) < self.rule.threshold:
            return None
        del self._recent[key]
        return list(window)


class SequenceEvaluator(Evaluator[SequenceRule]):
    """The rule's steps, in order, within ``within_seconds``.

    Per group, the events of the last ``within_seconds`` that match any step are
    kept. When one arrives that matches the last step, the kept events are read
    as a small state machine: stay on a step until it has seen its ``count``,
    then move on. If that walks through every step, the sequence is complete.
    An event serves one step only, even if it would match several.

    Anchoring the time limit at the final event rather than the first one means
    a long run-up (ten minutes of failed logins, then a success) is still caught
    by its last stretch. As with thresholds, two events exactly
    ``within_seconds`` apart are *not* within the limit.
    """

    def __init__(self, rule: SequenceRule) -> None:
        super().__init__(rule)
        self._recent: defaultdict[str, deque[tuple[Evidence, frozenset[int]]]] = defaultdict(deque)
        # Each step's filter as plain (field, accepted values) pairs: asked for
        # every event, so not through the model.
        self._tests = [
            tuple((name, frozenset(accepted)) for name, accepted in step.match if accepted)
            for step in rule.steps
        ]
        self._last: tuple[int, frozenset[int]] = (-1, frozenset())

    def _steps(self, event: EventRow) -> frozenset[int]:
        """The steps *event* could serve. Asked twice per event; remembered once."""
        if self._last[0] != event.id:
            steps = frozenset(
                index
                for index, tests in enumerate(self._tests)
                if all(getattr(event, name) in accepted for name, accepted in tests)
            )
            self._last = (event.id, steps)
        return self._last[1]

    def spans(self, event: EventRow, key: str) -> tuple[Span, ...] | None:
        return _span_of(event.message, key) if self._steps(event) else None

    def trigger(self, key: str, evidence: Evidence, event: EventRow) -> list[Evidence] | None:
        steps = self._steps(event)
        recent = self._recent[key]
        recent.append((evidence, steps))
        while (evidence.ts - recent[0][0].ts).total_seconds() >= self.rule.within_seconds:
            recent.popleft()
        last = len(self.rule.steps) - 1
        if last not in steps:  # only an event of the last step can complete the sequence
            return None

        stage = seen = 0
        for _, item_steps in recent:
            if stage in item_steps:
                seen += 1
                if seen >= self.rule.steps[stage].count:
                    stage, seen = stage + 1, 0
                    if stage > last:
                        break
        if stage <= last:
            return None
        del self._recent[key]
        return [item for item, _ in recent]


class PortScanEvaluator(Evaluator[PortScanRule]):
    """``min_ports`` different destination ports from one group within ``window_seconds``.

    The same sliding window as a threshold's, but what is counted is the number
    of different ports in it, so hammering one port never looks like a scan.
    """

    def __init__(self, rule: PortScanRule) -> None:
        super().__init__(rule)
        self._recent: defaultdict[str, deque[Evidence]] = defaultdict(deque)
        # Packets per port in each group's window, so that a flood does not have
        # to be recounted on every packet.
        self._ports: defaultdict[str, Counter[int | None]] = defaultdict(Counter)

    def spans(self, event: EventRow, key: str) -> tuple[Span, ...] | None:
        if event.dst_port is None:
            return None
        return merge_spans(
            [*_span_of(event.message, key), *_port_span(event.message, event.dst_port)]
        )

    def trigger(self, key: str, evidence: Evidence, event: EventRow) -> list[Evidence] | None:
        window, ports = self._recent[key], self._ports[key]
        window.append(evidence)
        ports[evidence.port] += 1
        while (evidence.ts - window[0].ts).total_seconds() >= self.rule.window_seconds:
            gone = window.popleft().port
            ports[gone] -= 1
            if not ports[gone]:
                del ports[gone]
        if len(ports) < self.rule.min_ports:
            return None
        del self._recent[key], self._ports[key]
        return list(window)


class RarePortEvaluator(Evaluator[RarePortRule]):
    """Every connection to a port on the watchlist, or to one that is not on the allowlist."""

    def __init__(self, rule: RarePortRule) -> None:
        super().__init__(rule)
        self._listed = frozenset(rule.ports)
        self._listed_is_suspicious = rule.mode == "watchlist"

    def spans(self, event: EventRow, key: str) -> tuple[Span, ...] | None:
        if event.dst_port is None:
            return None
        if (event.dst_port in self._listed) != self._listed_is_suspicious:
            return None
        return _port_span(event.message, event.dst_port)

    def trigger(self, key: str, evidence: Evidence, event: EventRow) -> list[Evidence] | None:
        return [evidence]


def _span_of(message: str, text: str) -> tuple[Span, ...]:
    """Where *text* first occurs in *message*, or nothing."""
    start = message.find(text)
    return ((start, start + len(text)),) if start >= 0 else ()


def _port_span(message: str, port: int) -> tuple[Span, ...]:
    """The destination port in a packet log line (``DPT=23``, as a word of its own)."""
    # Plain search rather than a regular expression per port: there are 65,536
    # of them, far more than the pattern cache holds.
    field = f"DPT={port}"
    start = message.find(field)
    while start >= 0:
        end = start + len(field)
        if not (start and _in_word(message[start - 1])) and not (
            end < len(message) and _in_word(message[end])
        ):
            return ((start + 4, end),)
        start = message.find(field, start + 1)
    return ()


def _in_word(character: str) -> bool:
    return character.isalnum() or character == "_"


_EVALUATORS: dict[type, type[Evaluator]] = {
    KeywordRule: KeywordEvaluator,
    ThresholdRule: ThresholdEvaluator,
    SequenceRule: SequenceEvaluator,
    PortScanRule: PortScanEvaluator,
    RarePortRule: RarePortEvaluator,
}


def create_evaluator(rule: Rule) -> Evaluator:
    try:
        return _EVALUATORS[type(rule)](rule)
    except KeyError:
        raise TypeError(f"no evaluator for rule type {type(rule).__name__}") from None
