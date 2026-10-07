"""Evaluators decide, event by event, whether a rule's condition has been met.

The engine (see ``engine.py``) feeds an evaluator the events of one group, for
example one source address, in time order. An evaluator answers two questions:

* :meth:`Evaluator.spans` -- does this event count for the rule, and which part
  of its message should be highlighted?
* :meth:`Evaluator.trigger` -- now that it counts, is the condition met?
"""

import re
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Generic, Protocol, TypeVar

from app.rules.schema import KeywordRule, Rule, ThresholdRule

Span = tuple[int, int]  # [start, end) character positions in an event's message

R = TypeVar("R", KeywordRule, ThresholdRule)


class EventRow(Protocol):
    """The event columns rules can see."""

    id: int
    ts: datetime
    host: str | None
    service: str | None
    user: str | None
    src_ip: str | None
    message: str


@dataclass(frozen=True, slots=True)
class Evidence:
    """An event that counts toward an alert."""

    event_id: int
    ts: datetime
    spans: tuple[Span, ...]


class Evaluator(ABC, Generic[R]):
    def __init__(self, rule: R) -> None:
        self.rule = rule

    @abstractmethod
    def spans(self, event: EventRow, key: str) -> tuple[Span, ...] | None:
        """Return what to highlight if *event* counts for the rule, else ``None``."""

    @abstractmethod
    def trigger(self, key: str, evidence: Evidence) -> list[Evidence] | None:
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

    def trigger(self, key: str, evidence: Evidence) -> list[Evidence] | None:
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
        start = event.message.find(key)
        return ((start, start + len(key)),) if start >= 0 else ()

    def trigger(self, key: str, evidence: Evidence) -> list[Evidence] | None:
        window = self._recent[key]
        window.append(evidence)
        while (evidence.ts - window[0].ts).total_seconds() >= self.rule.window_seconds:
            window.popleft()
        if len(window) < self.rule.threshold:
            return None
        del self._recent[key]
        return list(window)


def create_evaluator(rule: Rule) -> Evaluator:
    if isinstance(rule, KeywordRule):
        return KeywordEvaluator(rule)
    if isinstance(rule, ThresholdRule):
        return ThresholdEvaluator(rule)
    raise TypeError(f"no evaluator for rule type {type(rule).__name__}")
