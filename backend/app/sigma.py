"""Turn Sigma rules into rules of this application: ``python -m app.sigma``.

Sigma (https://github.com/SigmaHQ/sigma) is a common format for detection
rules, and SigmaHQ's repository the largest public collection of them. Most of
those rules need records this application does not have: process starts, auditd,
Windows events. The ones that look for texts in the lines of plain Linux logs
can be used, and this module rewrites them as keyword rules::

    python -m app.sigma --root ~/sigma --ref <commit> --out ../rules/sigma \
        rules/linux/builtin rules-emerging-threats

Every rule that cannot be rewritten is listed with the reason. The result keeps
the author, a link to the original and the licence, as the Detection Rule
License asks of whoever passes Sigma rules on.

What is understood of a Sigma rule's ``detection``:

* lists of texts ("keywords"), with ``*`` for any text;
* ``|all`` (every text of the list must be there);
* for sudo's log, fields such as ``USER``, which sudo writes as ``USER=value``;
* conditions made of ``and``, ``or``, ``not``, ``1 of``, ``all of`` and brackets,
  as long as they come down to: one of these texts, and one of those, and none
  of these.
"""

import argparse
import re
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.rules.schema import RULE, keyword_parts

REPOSITORY = "https://github.com/SigmaHQ/sigma"
LICENSE = "Detection Rule License 1.1 (https://github.com/SigmaHQ/Detection-Rule-License)"

SEVERITY = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Sigma names the log a rule is for; here a rule can ask for the program that
# wrote a line. Only where the two are sure to mean the same is the rule
# narrowed down; elsewhere it looks at every line, as it does in Sigma.
PROGRAMS = {
    "sshd": ["sshd"],
    "sudo": ["sudo"],
    "cron": ["cron", "CRON", "crond", "crontab"],
}
# Logs whose lines carry fields as NAME=value.
FIELDS_AS_TEXT = {"sudo"}


class NotConvertible(ValueError):
    """The Sigma rule asks for something a rule of this application cannot do."""


@dataclass
class _Wanted:
    """A condition brought down to: one text of each of ``groups``, and none of ``excluded``."""

    groups: list[list[str]] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)


def convert(sigma: dict[str, Any], *, source: str = "") -> dict[str, Any]:
    """The fields of a keyword rule that looks for what the Sigma rule looks for.

    *source* is the address of the Sigma rule. Raises :class:`NotConvertible`
    with the reason if there is no such keyword rule.
    """
    for name in ("title", "id", "logsource", "detection"):
        if not sigma.get(name):
            raise NotConvertible(f"has no {name}")
    if sigma.get("status") in ("deprecated", "unsupported"):
        raise NotConvertible(f"is {sigma['status']}")
    service = _log_of(sigma["logsource"])

    detection = dict(sigma["detection"])
    condition = detection.pop("condition", None)
    detection.pop("timeframe", None)
    if not isinstance(condition, str):
        raise NotConvertible("has several conditions or none")
    selections = {
        name: _selection(value, fields_as_text=service in FIELDS_AS_TEXT)
        for name, value in detection.items()
    }
    wanted = _Condition(condition, selections).read()
    if not wanted.groups:
        raise NotConvertible("only says what must not be in a line")

    rule: dict[str, Any] = {
        "id": f"SIGMA-{str(sigma['id'])[:8]}",
        "name": str(sigma["title"]),
        "description": " ".join(str(sigma.get("description", "")).split()),
        "type": "keyword",
        "severity": SEVERITY.get(str(sigma.get("level", "medium")), "medium"),
    }
    if service in PROGRAMS:
        rule["match"] = {"service": PROGRAMS[service]}
    rule["keywords"] = wanted.groups[0]
    if len(wanted.groups) > 1:
        rule["require"] = [group[0] if len(group) == 1 else group for group in wanted.groups[1:]]
    if wanted.excluded:
        rule["exclude"] = wanted.excluded
    if sigma.get("tags"):
        rule["tags"] = [str(tag) for tag in sigma["tags"]]
    # "Unknown" says nothing a reader could use.
    harmless = [str(item) for item in sigma.get("falsepositives") or []]
    if harmless := [item for item in harmless if item.strip().lower() != "unknown"]:
        rule["false_positives"] = harmless
    if sigma.get("author"):
        rule["author"] = str(sigma["author"])
    if source:
        rule["source"] = source
    rule["license"] = LICENSE
    if sigma.get("references"):
        rule["references"] = [str(link) for link in sigma["references"]]

    try:
        RULE.validate_python(rule)
    except ValidationError as error:
        problem = error.errors()[0]
        where = ".".join(str(part) for part in problem["loc"][1:])
        raise NotConvertible(
            f"gives a rule that does not load ({where}: {problem['msg']})"
        ) from None
    return rule


def _log_of(logsource: dict[str, Any]) -> str | None:
    """The log a Sigma rule is for, if it is one this application reads; else the reason why not."""
    if category := logsource.get("category"):
        raise NotConvertible(f"needs {category} records")
    product = logsource.get("product")
    if product != "linux":
        raise NotConvertible(
            f"is for {product} logs" if product else "does not say which logs it is for"
        )
    service = logsource.get("service")
    if service == "auditd":
        raise NotConvertible("needs auditd records")
    return service


def _selection(value: Any, *, fields_as_text: bool) -> list[list[str]]:
    """What one named part of a detection looks for: one text of each of the returned lists."""
    if isinstance(value, str | int):
        return [[_keyword(value)]]
    if isinstance(value, list):
        if all(isinstance(item, str | int) for item in value):
            return [[_keyword(item) for item in value]]
        raise NotConvertible("looks at fields of a record, not at the text of a line")
    if isinstance(value, dict):
        if set(value) == {"|all"}:
            return [[_keyword(item)] for item in _listed(value["|all"])]
        if fields_as_text and all(re.fullmatch(r"\w+", str(name)) for name in value):
            return [
                [_keyword(f"{name}={item}") for item in _listed(items)]
                for name, items in value.items()
            ]
        names = ", ".join(str(name) for name in value)
        raise NotConvertible(f"looks at fields of a record ({names}), not at the text of a line")
    raise NotConvertible("has a detection this converter cannot read")


def _listed(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _keyword(value: Any) -> str:
    r"""A Sigma text as a keyword. The two are written alike, except that Sigma also has ``?``."""
    text = str(value)
    if re.search(r"(?<!\\)(?:\\\\)*\?", text):
        raise NotConvertible("uses ? for a single character, which keywords here do not have")
    text = text.replace("\\?", "?")
    if not keyword_parts(text):
        raise NotConvertible(f"looks for the empty text {str(value)!r}")
    return text


class _Condition:
    """Reads a Sigma condition: ``selection and not filter``, ``1 of selection_*``, ...

    Grammar, loosest binding first::

        either  = both ("or" both)*
        both    = negated ("and" negated)*
        negated = "not" negated | "(" either ")" | ("1" | "all") "of" pattern | name
    """

    def __init__(self, text: str, selections: dict[str, list[list[str]]]) -> None:
        self._words = re.findall(r"\(|\)|[^\s()]+", text)
        self._selections = selections
        self._text = text

    def read(self) -> _Wanted:
        wanted = self._either()
        if self._words:
            raise self._unreadable()
        return wanted

    def _unreadable(self) -> NotConvertible:
        return NotConvertible(f"has a condition this converter cannot read ({self._text})")

    def _next(self) -> str | None:
        return self._words[0].lower() if self._words else None

    def _either(self) -> _Wanted:
        wanted = self._both()
        while self._next() == "or":
            self._words.pop(0)
            wanted = _one_of([wanted, self._both()])
        return wanted

    def _both(self) -> _Wanted:
        wanted = self._negated()
        while self._next() == "and":
            self._words.pop(0)
            other = self._negated()
            wanted = _Wanted(wanted.groups + other.groups, wanted.excluded + other.excluded)
        return wanted

    def _negated(self) -> _Wanted:
        if not self._words:
            raise self._unreadable()
        word = self._words.pop(0)
        if word.lower() == "not":
            inner = self._negated()
            # "none of these texts" is all a rule can exclude.
            if inner.excluded or len(inner.groups) != 1:
                raise NotConvertible(
                    "excludes a combination of texts, where a rule can only exclude texts"
                )
            return _Wanted(excluded=inner.groups[0])
        if word == "(":
            inner = self._either()
            if not self._words or self._words.pop(0) != ")":
                raise self._unreadable()
            return inner
        if word.lower() in ("1", "all") and self._next() == "of":
            self._words.pop(0)
            if not self._words:
                raise self._unreadable()
            named = [self._named(name) for name in self._matching(self._words.pop(0))]
            if word == "1":
                return _one_of(named)
            return _Wanted([group for wanted in named for group in wanted.groups])
        return self._named(word)

    def _matching(self, pattern: str) -> list[str]:
        names = [
            name for name in self._selections if pattern == "them" or fnmatchcase(name, pattern)
        ]
        if not names:
            raise NotConvertible(f"has a condition that names nothing ({pattern})")
        return names

    def _named(self, name: str) -> _Wanted:
        if name not in self._selections:
            raise NotConvertible(f"has a condition that names nothing ({name})")
        return _Wanted([list(group) for group in self._selections[name]])


def _one_of(alternatives: list[_Wanted]) -> _Wanted:
    """A line that satisfies any of *alternatives*: possible if each is one list of texts."""
    if any(wanted.excluded or len(wanted.groups) != 1 for wanted in alternatives):
        raise NotConvertible("offers alternatives that are more than lists of texts")
    return _Wanted([[text for wanted in alternatives for text in wanted.groups[0]]])


# --- files ------------------------------------------------------------------------------------

HEADER = """\
# SigmaHQ deposundaki bir kuraldan çevrildi: python -m app.sigma
# Özgün kural: {path}
# Elle yapılan değişiklikler, kural yeniden çevrilirse kaybolur.
"""


class _Indented(yaml.SafeDumper):
    """Writes the items of a list indented below its name, as the other rule files have them."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        super().increase_indent(flow, False)


def render(rule: dict[str, Any], *, path: str) -> str:
    """A rule file: a note on where the rule comes from, then its fields."""
    # No line folding: a keyword is easier to check when it is on one line.
    body = yaml.dump(rule, Dumper=_Indented, sort_keys=False, allow_unicode=True, width=10_000)
    return HEADER.format(path=path) + body


def sigma_files(root: Path, paths: Sequence[str]) -> Iterator[Path]:
    """The rule files named by *paths* (files, or folders to go through), below *root*."""
    for name in paths:
        path = root / name
        if path.is_dir():
            yield from sorted(path.rglob("*.yml"))
        else:
            yield path


def main(arguments: Sequence[str] | None = None) -> int:
    options = argparse.ArgumentParser(
        prog="python -m app.sigma",
        description="Rewrite Sigma rules that read plain Linux logs as keyword rules.",
    )
    options.add_argument("paths", nargs="+", help="rule files or folders, relative to --root")
    options.add_argument("--root", type=Path, required=True, help="a copy of the Sigma repository")
    options.add_argument("--out", type=Path, required=True, help="folder to write the rules to")
    options.add_argument(
        "--ref",
        default="master",
        help="commit or branch the copy is at, for the link back to each rule (default: master)",
    )
    options.add_argument(
        "--reasons", action="store_true", help="list every rule that was left out, not only counts"
    )
    chosen = options.parse_args(arguments)

    written: list[str] = []
    left_out: list[tuple[str, str]] = []
    for path in sigma_files(chosen.root, chosen.paths):
        try:
            relative = path.resolve().relative_to(chosen.root.resolve()).as_posix()
        except ValueError:
            options.error(f"{path} is not inside {chosen.root}")
        try:
            sigma = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(sigma, dict):
                raise NotConvertible("is not a rule")
            rule = convert(sigma, source=f"{REPOSITORY}/blob/{chosen.ref}/{relative}")
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
            left_out.append((relative, f"cannot be read ({str(error).splitlines()[0]})"))
            continue
        except NotConvertible as error:
            left_out.append((relative, str(error)))
            continue
        chosen.out.mkdir(parents=True, exist_ok=True)
        target = chosen.out / f"{path.stem}.yaml"
        target.write_text(render(rule, path=relative), encoding="utf-8")
        written.append(target.name)

    print(f"{len(written)} rules written to {chosen.out}")
    if left_out:
        print(f"{len(left_out)} left out:")
        if chosen.reasons:
            for relative, reason in left_out:
                print(f"  {relative}: {reason}")
        else:
            # Without what is particular to one rule, which is in brackets at the end.
            kinds = Counter(reason.split(" (")[0] for _, reason in left_out)
            for reason, count in kinds.most_common():
                print(f"  {count:5d}  {reason}")
    return 0 if written else 1


if __name__ == "__main__":
    sys.exit(main())
