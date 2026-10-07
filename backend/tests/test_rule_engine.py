"""Evaluators and the engine: thresholds, windows, cooldown, allowlists, keywords."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.models import Alert, AlertEvent, Event
from app.rules import evaluate
from app.rules.engine import detect
from app.rules.evaluators import merge_spans
from app.rules.schema import RULE

T0 = datetime(2026, 9, 9, 3, 0, 0, tzinfo=UTC)
ATTACKER = "203.0.113.45"


def threshold_rule(**overrides):
    fields = {
        "id": "SSH-900",
        "name": "Too many failures",
        "type": "threshold",
        "severity": "high",
        "match": {"action": "auth_fail"},
        "threshold": 5,
        "window_seconds": 60,
        "cooldown_seconds": 300,
    }
    return RULE.validate_python(fields | overrides)


def keyword_rule(**overrides):
    fields = {
        "id": "KW-900",
        "name": "Sensitive file",
        "type": "keyword",
        "severity": "medium",
        "keywords": ["/etc/shadow"],
    }
    return RULE.validate_python(fields | overrides)


def failures(*seconds: float, ip: str = ATTACKER, user: str = "root", first_id: int = 1):
    """Failed logins from *ip*, one per offset (in seconds after T0)."""
    return [
        SimpleNamespace(
            id=first_id + index,
            ts=T0 + timedelta(seconds=offset),
            host="web-01",
            service="sshd",
            level="warning",
            action="auth_fail",
            user=user,
            src_ip=ip,
            dst_port=None,
            message=f"Failed password for {user} from {ip} port 4242 ssh2",
        )
        for index, offset in enumerate(seconds)
    ]


def line(message: str, seconds: float = 0, *, event_id: int = 1, host: str = "web-01", **fields):
    values = {
        "service": "sudo",
        "level": "info",
        "action": None,
        "user": "bob",
        "src_ip": None,
        "dst_port": None,
    } | fields
    return SimpleNamespace(
        id=event_id, ts=T0 + timedelta(seconds=seconds), host=host, message=message, **values
    )


def ids(detection) -> list[int]:
    return [evidence.event_id for evidence in detection.evidence]


# --- threshold: the count --------------------------------------------------------------------


def test_one_event_short_of_the_threshold_is_no_alert():
    assert detect(threshold_rule(), failures(0, 10, 20, 30)) == []


def test_reaching_the_threshold_opens_an_alert_holding_the_events_that_did_it():
    [detection] = detect(threshold_rule(), failures(0, 10, 20, 30, 40))
    assert detection.key == ATTACKER
    assert ids(detection) == [1, 2, 3, 4, 5]
    assert (detection.first.ts, detection.last.ts) == (T0, T0 + timedelta(seconds=40))


def test_threshold_of_one_alerts_on_the_first_event():
    [detection] = detect(threshold_rule(threshold=1), failures(0))
    assert ids(detection) == [1]


def test_each_group_is_counted_on_its_own():
    events = sorted(
        failures(0, 10, 20, 30, ip="198.51.100.1")
        + failures(5, 15, 25, 35, ip="198.51.100.2", first_id=10),
        key=lambda event: event.ts,
    )
    assert detect(threshold_rule(), events) == []


def test_events_without_the_group_field_are_ignored():
    events = failures(0, 10, 20, 30, 40)
    for event in events:
        event.src_ip = None
    assert detect(threshold_rule(), events) == []


def test_other_fields_can_be_the_group():
    events = [
        event
        for index, ip in enumerate(["198.51.100.1", "198.51.100.2", "198.51.100.3"])
        for event in failures(index, ip=ip, user="root", first_id=index + 1)
    ]
    [detection] = detect(threshold_rule(threshold=3, group_by="user"), events)
    assert (detection.key, ids(detection)) == ("root", [1, 2, 3])


# --- threshold: the window -------------------------------------------------------------------


def test_events_spanning_exactly_the_window_are_not_within_it():
    assert detect(threshold_rule(), failures(0, 15, 30, 45, 60)) == []


def test_events_spanning_one_second_less_than_the_window_are_within_it():
    [detection] = detect(threshold_rule(), failures(0, 15, 30, 45, 59))
    assert ids(detection) == [1, 2, 3, 4, 5]


def test_many_events_spread_thinly_never_fill_a_window():
    one_every_20_seconds = failures(*range(0, 2000, 20))
    assert len(one_every_20_seconds) == 100
    assert detect(threshold_rule(), one_every_20_seconds) == []


def test_window_slides_old_events_drop_out_new_ones_complete_it():
    # 0 and 10 are too old by the time 70..100 arrive; 70, 80, 90, 100, 110 fill a window.
    [detection] = detect(threshold_rule(), failures(0, 10, 70, 80, 90, 100, 110))
    assert ids(detection) == [3, 4, 5, 6, 7]


# --- cooldown: one burst, one alert ----------------------------------------------------------


def test_further_events_join_the_open_alert():
    [detection] = detect(threshold_rule(), failures(0, 1, 2, 3, 4, 5, 6, 60, 200))
    assert ids(detection) == [1, 2, 3, 4, 5, 6, 7, 8, 9]


def test_event_exactly_at_the_end_of_the_cooldown_still_joins():
    [detection] = detect(threshold_rule(), failures(0, 1, 2, 3, 4, 304))
    assert ids(detection) == [1, 2, 3, 4, 5, 6]


def test_event_after_the_cooldown_does_not_join_and_alone_is_no_new_alert():
    [detection] = detect(threshold_rule(), failures(0, 1, 2, 3, 4, 305))
    assert ids(detection) == [1, 2, 3, 4, 5]


def test_cooldown_is_measured_from_the_last_event_not_the_first():
    # Each event comes 250 s after the one before: always inside the 300 s cooldown.
    [detection] = detect(threshold_rule(), failures(0, 1, 2, 3, 4, 254, 504, 754))
    assert len(detection.evidence) == 8


def test_second_burst_after_the_cooldown_is_a_second_alert():
    first, second = detect(threshold_rule(), failures(0, 1, 2, 3, 4, 1000, 1001, 1002, 1003, 1004))
    assert (ids(first), ids(second)) == ([1, 2, 3, 4, 5], [6, 7, 8, 9, 10])


def test_zero_cooldown_keeps_only_simultaneous_events_together():
    first, second = detect(threshold_rule(threshold=2, cooldown_seconds=0), failures(0, 1, 1, 2, 3))
    assert (ids(first), ids(second)) == ([1, 2, 3], [4, 5])


# --- allowlist -------------------------------------------------------------------------------


@pytest.mark.parametrize("entry", [ATTACKER, "203.0.113.0/24", "0.0.0.0/0"])
def test_allowlisted_sources_never_alert(entry):
    assert detect(threshold_rule(allowlist=[entry]), failures(0, 1, 2, 3, 4)) == []


@pytest.mark.parametrize("entry", ["203.0.113.46", "198.51.100.0/24", "2001:db8::/32"])
def test_allowlist_does_not_cover_other_sources(entry):
    assert len(detect(threshold_rule(allowlist=[entry]), failures(0, 1, 2, 3, 4))) == 1


def test_allowlisted_events_do_not_count_toward_a_group_of_another_kind():
    events = failures(0, 1, 2, ip="192.0.2.10") + failures(3, 4, ip=ATTACKER, first_id=4)
    rule = threshold_rule(group_by="user", allowlist=["192.0.2.0/24"])
    assert detect(rule, events) == []


def test_host_name_as_source_is_simply_not_on_the_allowlist():
    events = failures(0, 1, 2, 3, 4, ip="scanner.example.net")
    assert len(detect(threshold_rule(allowlist=["0.0.0.0/0"]), events)) == 1


# --- highlights ------------------------------------------------------------------------------


def test_threshold_evidence_points_at_the_group_value_in_the_message():
    [detection] = detect(threshold_rule(threshold=1), failures(0))
    [(start, end)] = detection.first.spans
    assert "Failed password for root from 203.0.113.45 port 4242 ssh2"[start:end] == ATTACKER


def test_threshold_evidence_without_the_value_in_the_message_has_no_span():
    event = line("authentication failure", src_ip=ATTACKER, service="sshd")
    [detection] = detect(threshold_rule(threshold=1), [event])
    assert detection.first.spans == ()


@pytest.mark.parametrize(
    ("spans", "merged"),
    [
        ([], ()),
        ([(5, 9), (0, 3)], ((0, 3), (5, 9))),
        ([(0, 5), (3, 9)], ((0, 9),)),
        ([(0, 5), (5, 9)], ((0, 9),)),
        ([(0, 9), (2, 4), (2, 4)], ((0, 9),)),
    ],
)
def test_merge_spans(spans, merged):
    assert merge_spans(spans) == merged


# --- keyword ---------------------------------------------------------------------------------

DENIED = (
    "bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; "
    "COMMAND=/usr/bin/cat /etc/shadow"
)


def marked(detection, message: str) -> list[str]:
    return [message[start:end] for start, end in detection.first.spans]


def test_keyword_alerts_on_a_line_that_contains_it_and_marks_where():
    [detection] = detect(keyword_rule(), [line(DENIED)])
    assert detection.key == "web-01"
    assert marked(detection, DENIED) == ["/etc/shadow"]


def test_keyword_matching_ignores_case():
    message = "COMMAND=/usr/bin/cat /ETC/Shadow"
    [detection] = detect(keyword_rule(), [line(message)])
    assert marked(detection, message) == ["/ETC/Shadow"]


def test_keyword_is_literal_text_not_a_pattern():
    assert detect(keyword_rule(keywords=["a.c"]), [line("abc")]) == []
    assert len(detect(keyword_rule(keywords=["a.c"]), [line("a.c")])) == 1


def test_every_occurrence_of_every_keyword_is_marked():
    message = "cat /etc/shadow /etc/sudoers /etc/shadow"
    [detection] = detect(keyword_rule(keywords=["/etc/shadow", "/etc/sudoers"]), [line(message)])
    assert marked(detection, message) == ["/etc/shadow", "/etc/sudoers", "/etc/shadow"]


def test_overlapping_keywords_give_one_mark_over_the_longer_text():
    message = "cat /etc/shadow"
    [detection] = detect(keyword_rule(keywords=["shadow", "/etc/shadow", "etc"]), [line(message)])
    assert marked(detection, message) == ["/etc/shadow"]


def test_longer_keyword_wins_over_one_that_is_its_beginning():
    message = "cat /etc/shadow"
    [detection] = detect(keyword_rule(keywords=["/etc", "/etc/shadow"]), [line(message)])
    assert marked(detection, message) == ["/etc/shadow"]


def test_regex_marks_what_it_matched():
    message = "COMMAND=/usr/bin/vim /etc/passwd"
    rule = keyword_rule(keywords=[], regex=r"/etc/(passwd|shadow)\b")
    [detection] = detect(rule, [line(message)])
    assert marked(detection, message) == ["/etc/passwd"]


def test_regex_is_case_sensitive_unless_it_says_otherwise():
    assert detect(keyword_rule(keywords=[], regex="shadow"), [line("SHADOW")]) == []
    assert len(detect(keyword_rule(keywords=[], regex="(?i)shadow"), [line("SHADOW")])) == 1


def test_regex_that_matches_nothing_visible_is_no_match():
    assert detect(keyword_rule(keywords=[], regex="x*"), [line("no such letter")]) == []


def test_lines_without_the_keyword_neither_alert_nor_join_an_alert():
    events = [
        line(DENIED, 0, event_id=1),
        line("bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id", 5, event_id=2),
        line(DENIED, 10, event_id=3),
    ]
    [detection] = detect(keyword_rule(), events)
    assert ids(detection) == [1, 3]


def test_keyword_matches_are_merged_within_the_cooldown_and_split_after_it():
    events = [line(DENIED, offset, event_id=index) for index, offset in enumerate([0, 100, 500], 1)]
    first, second = detect(keyword_rule(cooldown_seconds=300), events)
    assert (ids(first), ids(second)) == ([1, 2], [3])


def test_keyword_alerts_are_grouped_by_the_chosen_field():
    events = [
        line(DENIED, 0, event_id=1, user="bob"),
        line(DENIED.replace("bob", "eve"), 1, event_id=2, user="eve"),
    ]
    by_host = detect(keyword_rule(), events)
    by_user = detect(keyword_rule(group_by="user"), events)
    assert [d.key for d in by_host] == ["web-01"]
    assert [d.key for d in by_user] == ["bob", "eve"]


# --- evaluate: the alerts table --------------------------------------------------------------


def store(session, *events) -> None:
    """Store SimpleNamespace events as rows; ids are assigned in the order given."""
    for number, event in enumerate(events, start=1):
        session.add(
            Event(
                ts=event.ts,
                host=event.host,
                service=event.service,
                level=event.level,
                src_ip=event.src_ip,
                dst_port=event.dst_port,
                user=event.user,
                action=event.action,
                message=event.message,
                raw=event.message,
                source_file="test.log",
                line_no=session.scalar(select(func.count()).select_from(Event)) + number,
                parsed=True,
            )
        )
    session.commit()


def alerts(session) -> list[Alert]:
    return list(session.scalars(select(Alert).order_by(Alert.first_seen, Alert.id)))


def test_evaluate_stores_the_alert_with_its_evidence_and_summary(session):
    store(session, *failures(0, 10, 20, 30, 40, 85))
    rule = threshold_rule(
        summary="{key}: {count} failures in {seconds} s (limit {threshold}/{window_seconds} s)"
    )

    outcome = evaluate(session, [rule])
    [alert] = alerts(session)

    assert (outcome.total, outcome.created, outcome.updated, outcome.removed) == (1, 1, 0, 0)
    assert (alert.rule_id, alert.rule_name, alert.severity) == (
        "SSH-900",
        "Too many failures",
        "high",
    )
    assert (alert.group_by, alert.group_key, alert.count) == ("src_ip", ATTACKER, 6)
    assert (alert.first_seen, alert.last_seen) == (T0, T0 + timedelta(seconds=85))
    assert alert.summary == f"{ATTACKER}: 6 failures in 85 s (limit 5/60 s)"
    evidence = session.scalars(select(AlertEvent.event_id).order_by(AlertEvent.event_id)).all()
    assert evidence == [1, 2, 3, 4, 5, 6]


def test_evaluating_again_changes_nothing(session):
    store(session, *failures(0, 10, 20, 30, 40))
    evaluate(session, [threshold_rule()])
    before = [(alert.id, alert.key, alert.count) for alert in alerts(session)]

    outcome = evaluate(session, [threshold_rule()])

    assert (outcome.total, outcome.created, outcome.updated, outcome.removed) == (1, 0, 0, 0)
    assert [(alert.id, alert.key, alert.count) for alert in alerts(session)] == before
    assert session.scalar(select(func.count()).select_from(AlertEvent)) == 5


def test_alert_keeps_its_id_and_grows_when_its_burst_continues(session):
    store(session, *failures(0, 10, 20, 30, 40))
    evaluate(session, [threshold_rule()])
    [original] = alerts(session)
    original_id = original.id

    store(session, *failures(50, 60))
    outcome = evaluate(session, [threshold_rule()])
    session.expire_all()
    [alert] = alerts(session)

    assert (outcome.created, outcome.updated, outcome.removed) == (0, 1, 0)
    assert (alert.id, alert.count, alert.last_seen) == (original_id, 7, T0 + timedelta(seconds=60))
    assert session.scalar(select(func.count()).select_from(AlertEvent)) == 7


def test_alerts_of_rules_no_longer_in_use_are_removed_with_their_evidence(session):
    store(session, *failures(0, 10, 20, 30, 40))
    evaluate(session, [threshold_rule()])

    for rules in ([threshold_rule(enabled=False)], []):
        outcome = evaluate(session, rules)
        assert (outcome.total, outcome.removed) == (0, 1)
        assert alerts(session) == []
        assert session.scalar(select(func.count()).select_from(AlertEvent)) == 0
        evaluate(session, [threshold_rule()])  # bring it back for the next round


def test_changing_a_rule_changes_its_alerts(session):
    store(session, *failures(0, 10, 20, 30, 40))
    evaluate(session, [threshold_rule()])

    outcome = evaluate(session, [threshold_rule(threshold=6)])
    assert (outcome.total, outcome.removed) == (0, 1)

    outcome = evaluate(session, [threshold_rule(severity="critical")])
    assert alerts(session)[0].severity == "critical"


def test_only_events_the_rule_matches_are_counted(session):
    events = failures(0, 10, 20, 30, 40)
    events[2].action = "auth_ok"
    store(session, *events)

    assert evaluate(session, [threshold_rule()]).total == 0
    assert (
        evaluate(session, [threshold_rule(match={"action": ["auth_fail", "auth_ok"]})]).total == 1
    )
    assert (
        evaluate(session, [threshold_rule(match={"action": "auth_fail", "host": "db-01"})]).total
        == 0
    )


def test_keyword_rule_respects_its_match_filter(session):
    sshd_line = line(
        "Failed password for /etc/shadow from 203.0.113.45 port 1 ssh2", service="sshd"
    )
    sudo_line = line(DENIED, 5)
    sudo_line.action = "sudo_denied"
    store(session, sshd_line, sudo_line)

    evaluate(session, [keyword_rule(match={"action": ["sudo_exec", "sudo_denied"]})])
    [alert] = alerts(session)
    assert alert.count == 1
    assert session.scalars(select(AlertEvent.event_id)).all() == [2]

    evaluate(session, [keyword_rule()])
    assert alerts(session)[0].count == 2


@pytest.mark.parametrize("keyword", ["ÇÖZÜM", "çözüm", "100%", "under_score"])
def test_keywords_with_special_characters_match_literally_and_whatever_their_case(session, keyword):
    store(session, line("geçici çözüm: 100% under_score"), line("gecici cozum: 100 underXscore", 1))

    evaluate(session, [keyword_rule(keywords=[keyword])])
    [alert] = alerts(session)
    assert session.scalars(select(AlertEvent.event_id)).all() == [1]
    assert alert.count == 1


def test_evidence_spans_are_stored_for_highlighting(session):
    store(session, line(DENIED))
    evaluate(session, [keyword_rule()])
    [[start, end]] = session.scalar(select(AlertEvent.spans))
    assert DENIED[start:end] == "/etc/shadow"
