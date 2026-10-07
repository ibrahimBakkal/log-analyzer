"""Finding, in one pass over many lines, the lines that keyword rules may count.

Asking the database for the lines that contain one of a rule's keywords means
one pattern test per keyword and line: a quarter of a second per keyword on a
million lines, and a set of rules can have hundreds of keywords. Nearly all of
that work is spent on lines that have nothing to do with any rule.

So the lines are read once, and each is tested for a few single characters
first. Every keyword is stood for by its rarest character, as counted on a
sample of the lines themselves: a line without that character cannot contain
the keyword, and most keywords have a character that ordinary log lines do not
have. Only for the keywords that are left is the line searched.

The outcome is a list of candidates, not a verdict: a line with a piece of a
keyword in it. Whether the line counts (the whole keyword, what the
rule requires and excludes) is for the rule's evaluator to say.
"""

import re
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence

from app.rules.evaluators import any_keyword
from app.rules.schema import KeywordRule, keyword_parts

Row = tuple[int, str | None, str]  # an event's id, the program that wrote it, its message


class KeywordScan:
    """Tells which of *rules* may count a line. *sample*: some of the lines to come."""

    def __init__(self, rules: Sequence[KeywordRule], sample: Iterable[Row] = ()) -> None:
        seen = Counter[str]()
        for _, service, message in sample:
            seen.update(_line(service, message).lower())

        # character -> the texts it stands for, each with the number of its rule
        self._gates: dict[str, list[tuple[str, int]]] = {}
        # For lines and keywords outside ASCII, where letters have more than
        # two cases and lowering both sides is not what ignoring case means.
        self._keywords: list[tuple[re.Pattern[str], int]] = []
        self._beyond_ascii: list[tuple[re.Pattern[str], int]] = []
        self._regexes: list[tuple[re.Pattern[str], int]] = []
        for number, rule in enumerate(rules):
            if rule.regex is not None:
                self._regexes.append((re.compile(rule.regex), number))
            if not rule.keywords:
                continue
            pattern = any_keyword(rule.keywords)
            self._keywords.append((pattern, number))
            if not all(map(str.isascii, rule.keywords)):
                self._beyond_ascii.append((pattern, number))
                continue
            for keyword in rule.keywords:
                # Any piece of the keyword will do; the one with the rarest character is best.
                pieces = [part.lower() for part in keyword_parts(keyword)]
                gates = [min(piece, key=lambda character: seen[character]) for piece in pieces]
                gate, text = min(zip(gates, pieces, strict=True), key=lambda pair: seen[pair[0]])
                self._gates.setdefault(gate, []).append((text, number))

    def candidates(self, rows: Iterable[Row]) -> Iterator[tuple[int, int]]:
        """(event id, number of the rule) for every line a rule may count."""
        gates = list(self._gates.items())
        keywords, beyond_ascii, regexes = self._keywords, self._beyond_ascii, self._regexes
        for event_id, service, message in rows:
            line = f"{service}: {message}" if service else message  # _line(), spelled out
            found = None
            if line.isascii():
                lowered = line.lower()
                for gate, texts in gates:
                    if gate in lowered:
                        for text, number in texts:
                            if text in lowered:
                                found = _noted(found, number)
                for pattern, number in beyond_ascii:
                    if pattern.search(line):
                        found = _noted(found, number)
            else:
                for pattern, number in keywords:
                    if pattern.search(line):
                        found = _noted(found, number)
            for pattern, number in regexes:
                if pattern.search(message):
                    found = _noted(found, number)
            if found is not None:
                for number in found:
                    yield event_id, number


def _line(service: str | None, message: str) -> str:
    """A line as keyword rules read it: the program's name, then what it said."""
    return f"{service}: {message}" if service else message


def _noted(found: set[int] | None, number: int) -> set[int]:
    # Nearly every line is no rule's candidate; a set is made only for those that are.
    if found is None:
        return {number}
    found.add(number)
    return found
