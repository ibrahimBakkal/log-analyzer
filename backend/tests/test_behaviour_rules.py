"""Rules about behaviour: sequences of steps, port scans, unexpected ports."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.models import Alert, AlertEvent, Event
from app.rules import evaluate
from app.rules.engine import detect
from app.rules.schema import RULE

T0 = datetime(2026, 9, 9, 3, 0, 0, tzinfo=UTC)
ATTACKER = "203.0.113.45"
OTHER = "198.51.100.7"
SERVER = "192.0.2.5"


def event(seconds: float, message: str, **fields):
    values = {
        "host": "web-01",
        "service": "sshd",
        "level": "info",
        "action": None,
        "user": None,
        "src_ip": None,
        "dst_port": None,
    } | fields
    return SimpleNamespace(id=0, ts=T0 + timedelta(seconds=seconds), message=message, **values)


def numbered(*events):
    """Put events in time order and give them the ids 1, 2, 3 ... in that order."""
    ordered = sorted(events, key=lambda item: item.ts)
    for number, item in enumerate(ordered, start=1):
        item.id = number
    return ordered


def fail(seconds: float, ip: str = ATTACKER, user: str = "root"):
    message = f"Failed password for {user} from {ip} port 4242 ssh2"
    return event(seconds, message, action="auth_fail", level="warning", user=user, src_ip=ip)


def ok(seconds: float, ip: str = ATTACKER, user: str = "root"):
    message = f"Accepted password for {user} from {ip} port 4242 ssh2"
    return event(seconds, message, action="auth_ok", user=user, src_ip=ip)


def sudo(seconds: float, user: str = "root"):
    message = f"{user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/id"
    return event(seconds, message, service="sudo", action="sudo_exec", user=user)


def packet(seconds: float, port: int | None, ip: str = ATTACKER, *, allowed: bool = False):
    """One line of the firewall's packet log."""
    verdict = "ALLOW" if allowed else "BLOCK"
    ports = "PROTO=ICMP TYPE=8" if port is None else f"PROTO=TCP SPT=40000 DPT={port} SYN"
    return event(
        seconds,
        f"[UFW {verdict}] IN=eth0 OUT= SRC={ip} DST={SERVER} LEN=44 {ports}",
        service="kernel",
        action="conn_allow" if allowed else "conn_block",
        level="info" if allowed else "warning",
        src_ip=ip,
        dst_port=port,
    )


def sweep(*ports: int, every: float = 1.0, start: float = 0, ip: str = ATTACKER):
    """Blocked packets from *ip* to each port in turn, *every* seconds apart."""
    return [packet(start + index * every, port, ip) for index, port in enumerate(ports)]


def ids(detection) -> list[int]:
    return [evidence.event_id for evidence in detection.evidence]


def marked(detection, events) -> list[list[str]]:
    """The highlighted text of each evidence line."""
    messages = {item.id: item.message for item in events}
    return [
        [messages[evidence.event_id][start:end] for start, end in evidence.spans]
        for evidence in detection.evidence
    ]


def store(session, *events) -> None:
    for number, item in enumerate(numbered(*events), start=1):
        session.add(
            Event(
                ts=item.ts,
                host=item.host,
                service=item.service,
                level=item.level,
                src_ip=item.src_ip,
                dst_port=item.dst_port,
                user=item.user,
                action=item.action,
                message=item.message,
                raw=item.message,
                source_file="test.log",
                line_no=number,
                parsed=item.action is not None,
            )
        )
    session.commit()


def alerts(session) -> list[Alert]:
    return list(session.scalars(select(Alert).order_by(Alert.first_seen, Alert.id)))


# --- sequence --------------------------------------------------------------------------------


def sequence_rule(**overrides):
    fields = {
        "id": "SSH-901",
        "name": "Break-in",
        "type": "sequence",
        "severity": "critical",
        "steps": [
            {"match": {"action": "auth_fail"}, "count": 3},
            {"match": {"action": "auth_ok"}},
        ],
        "within_seconds": 600,
        "cooldown_seconds": 300,
    }
    return RULE.validate_python(fields | overrides)


def test_steps_completed_in_order_open_an_alert_holding_every_step_event():
    events = numbered(fail(0), fail(10), fail(20), ok(30))
    [detection] = detect(sequence_rule(), events)
    assert (detection.key, ids(detection)) == (ATTACKER, [1, 2, 3, 4])
    assert (detection.first.ts, detection.last.ts) == (T0, T0 + timedelta(seconds=30))


def test_alert_opens_only_when_the_last_step_happens():
    assert detect(sequence_rule(), numbered(fail(0), fail(10), fail(20), fail(30))) == []


def test_one_event_short_in_an_earlier_step_is_no_alert():
    assert detect(sequence_rule(), numbered(fail(0), fail(10), ok(20))) == []


def test_last_step_alone_is_no_alert():
    assert detect(sequence_rule(), numbered(ok(0), ok(10), ok(20))) == []


def test_steps_in_the_wrong_order_are_no_alert():
    assert detect(sequence_rule(), numbered(ok(0), fail(10), fail(20), fail(30))) == []


def test_more_events_than_a_step_needs_are_all_evidence():
    events = numbered(*(fail(second) for second in range(8)), ok(8))
    [detection] = detect(sequence_rule(), events)
    assert ids(detection) == list(range(1, 10))


def test_each_group_goes_through_the_steps_on_its_own():
    events = numbered(fail(0), fail(10), fail(20, ip=OTHER), ok(30), ok(40, ip=OTHER))
    assert detect(sequence_rule(), events) == []


def test_events_that_match_no_step_neither_count_nor_get_in_the_way():
    unrelated = event(15, f"Connection closed by {ATTACKER} port 4242", src_ip=ATTACKER)
    events = numbered(fail(0), fail(10), unrelated, fail(20), ok(30))
    [detection] = detect(sequence_rule(), events)
    assert ids(detection) == [1, 2, 4, 5]


def test_steps_exactly_the_time_limit_apart_are_not_within_it():
    assert detect(sequence_rule(), numbered(fail(0), fail(10), fail(20), ok(600))) == []


def test_steps_one_second_inside_the_time_limit_are_within_it():
    [detection] = detect(sequence_rule(), numbered(fail(0), fail(10), fail(20), ok(599)))
    assert ids(detection) == [1, 2, 3, 4]


def test_long_run_up_is_caught_by_its_last_stretch():
    # A failure a minute for half an hour, then success: only the last ten minutes are kept.
    events = numbered(*(fail(minute * 60) for minute in range(30)), ok(1790))
    [detection] = detect(sequence_rule(), events)
    assert ids(detection) == list(range(21, 32))
    assert detection.first.ts == T0 + timedelta(minutes=20)


def test_earlier_steps_too_long_ago_no_longer_count():
    events = numbered(fail(0), fail(10), fail(20), fail(700), ok(710))
    assert detect(sequence_rule(), events) == []


def test_later_step_events_join_the_alert_during_the_cooldown():
    events = numbered(fail(0), fail(10), fail(20), ok(30), fail(40), ok(330), ok(631))
    [detection] = detect(sequence_rule(), events)
    assert ids(detection) == [1, 2, 3, 4, 5, 6]


def test_events_behind_an_alert_are_not_used_for_a_second_one():
    # The success at 400 s comes after the cooldown but within ten minutes of the
    # failures. They already made one alert; without new failures there is no other.
    events = numbered(fail(0), fail(10), fail(20), ok(30), ok(400))
    [detection] = detect(sequence_rule(), events)
    assert ids(detection) == [1, 2, 3, 4]


def test_sequence_repeated_after_the_cooldown_is_a_second_alert():
    again = [fail(1000), fail(1010), fail(1020), ok(1030)]
    events = numbered(fail(0), fail(10), fail(20), ok(30), *again)
    first, second = detect(sequence_rule(), events)
    assert (ids(first), ids(second)) == ([1, 2, 3, 4], [5, 6, 7, 8])


def test_last_step_can_need_several_events_too():
    rule = sequence_rule(
        steps=[
            {"match": {"action": "auth_fail"}, "count": 2},
            {"match": {"action": "auth_ok"}, "count": 2},
        ]
    )
    assert detect(rule, numbered(fail(0), fail(1), ok(2))) == []
    [detection] = detect(rule, numbered(fail(0), fail(1), ok(2), ok(3)))
    assert ids(detection) == [1, 2, 3, 4]


def test_three_steps_followed_by_user():
    rule = sequence_rule(
        group_by="user",
        steps=[
            {"match": {"action": "auth_fail"}, "count": 2},
            {"match": {"action": "auth_ok"}},
            {"match": {"action": "sudo_exec"}},
        ],
    )
    events = numbered(fail(0, user="bob"), fail(5, user="bob"), ok(10, user="bob"), sudo(60, "bob"))
    [detection] = detect(rule, events)
    assert (detection.key, ids(detection)) == ("bob", [1, 2, 3, 4])

    skipped_login = numbered(fail(0, user="bob"), fail(5, user="bob"), sudo(60, "bob"))
    other_user = numbered(fail(0, user="bob"), fail(5, user="bob"), ok(10, user="bob"), sudo(60))
    assert detect(rule, skipped_login) == detect(rule, other_user) == []


def test_an_event_serves_one_step_even_if_it_matches_two():
    rule = sequence_rule(
        steps=[{"match": {"service": "sshd"}, "count": 2}, {"match": {"action": "auth_ok"}}]
    )
    # The success is the second sshd line of step one; it cannot also be step two.
    assert detect(rule, numbered(fail(0), ok(1))) == []
    [detection] = detect(rule, numbered(fail(0), ok(1), ok(2)))
    assert ids(detection) == [1, 2, 3]


def test_allowlisted_sources_do_not_complete_a_sequence():
    events = numbered(fail(0), fail(10), fail(20), ok(30))
    assert detect(sequence_rule(allowlist=["203.0.113.0/24"]), events) == []
    assert len(detect(sequence_rule(allowlist=["198.51.100.0/24"]), events)) == 1


def test_sequence_evidence_points_at_the_group_value():
    events = numbered(fail(0), fail(10), fail(20), ok(30))
    [detection] = detect(sequence_rule(), events)
    assert marked(detection, events) == [[ATTACKER]] * 4


def test_evaluate_reads_only_the_step_events_the_rule_matches(session):
    elsewhere = [fail(100 + second, ip=OTHER) for second in range(3)] + [ok(110, ip=OTHER)]
    for item in elsewhere:
        item.host = "db-01"
    store(session, fail(0), fail(10), fail(20), ok(30), sudo(40), *elsewhere)

    rule = sequence_rule(summary="{key}: {count} lines in {seconds} s (limit {within_seconds} s)")
    assert evaluate(session, [rule]).total == 2

    evaluate(session, [sequence_rule(match={"host": "web-01"}, summary=rule.summary)])
    [alert] = alerts(session)
    assert (alert.group_key, alert.count, alert.severity) == (ATTACKER, 4, "critical")
    assert alert.summary == f"{ATTACKER}: 4 lines in 30 s (limit 600 s)"
    assert session.scalars(select(AlertEvent.event_id).order_by(AlertEvent.event_id)).all() == [
        1,
        2,
        3,
        4,
    ]


# --- port scan -------------------------------------------------------------------------------


def port_scan_rule(**overrides):
    fields = {
        "id": "NET-900",
        "name": "Port scan",
        "type": "port_scan",
        "severity": "high",
        "min_ports": 5,
        "window_seconds": 60,
        "cooldown_seconds": 300,
    }
    return RULE.validate_python(fields | overrides)


def test_one_port_short_of_the_minimum_is_no_alert():
    assert detect(port_scan_rule(), numbered(*sweep(21, 22, 23, 25))) == []


def test_enough_different_ports_open_an_alert_holding_the_packets_that_did_it():
    [detection] = detect(port_scan_rule(), numbered(*sweep(21, 22, 23, 25, 80)))
    assert (detection.key, ids(detection)) == (ATTACKER, [1, 2, 3, 4, 5])


def test_hammering_one_port_is_not_a_scan():
    assert detect(port_scan_rule(), numbered(*sweep(*[22] * 200, every=0.1))) == []


def test_a_port_tried_again_counts_once_but_every_packet_is_evidence():
    packets = numbered(*sweep(21, 22, 21, 22, 23, 23, 25))
    assert detect(port_scan_rule(), packets) == []

    [detection] = detect(port_scan_rule(), numbered(*sweep(21, 22, 21, 22, 23, 23, 25, 80)))
    assert ids(detection) == [1, 2, 3, 4, 5, 6, 7, 8]


def test_ports_spanning_exactly_the_window_are_not_within_it():
    assert detect(port_scan_rule(), numbered(*sweep(21, 22, 23, 25, 80, every=15))) == []


def test_ports_spanning_one_second_less_than_the_window_are_within_it():
    packets = numbered(*sweep(21, 22, 23, 25, every=15), packet(59, 80))
    assert len(detect(port_scan_rule(), packets)) == 1


def test_slow_scan_never_fills_a_window():
    one_port_every_20_seconds = numbered(*sweep(*range(1000, 1100), every=20))
    assert detect(port_scan_rule(), one_port_every_20_seconds) == []


def test_window_slides_old_ports_drop_out_new_ones_complete_it():
    packets = numbered(
        packet(0, 21), packet(10, 22), *sweep(23, 25, 80, 110, 143, every=10, start=70)
    )
    [detection] = detect(port_scan_rule(), packets)
    assert ids(detection) == [3, 4, 5, 6, 7]


def test_port_stays_counted_while_any_packet_to_it_is_in_the_window():
    rule = port_scan_rule(min_ports=2)
    # At 61 s the first packet to port 22 has left the window, the second has not.
    [detection] = detect(rule, numbered(packet(0, 22), packet(30, 22), packet(61, 23)))
    assert ids(detection) == [2, 3]
    assert detect(rule, numbered(packet(0, 22), packet(61, 23))) == []


def test_each_source_is_counted_on_its_own_unless_grouped_by_target():
    packets = numbered(*sweep(21, 22, 23), *sweep(25, 80, 110, ip=OTHER, start=0.5))
    assert detect(port_scan_rule(), packets) == []

    [detection] = detect(port_scan_rule(group_by="host"), packets)
    assert (detection.key, ids(detection)) == ("web-01", [1, 2, 3, 4, 5, 6])


def test_packets_without_a_port_are_ignored():
    packets = numbered(*sweep(21, 22, 23, 25), *(packet(10 + n, None) for n in range(20)))
    assert detect(port_scan_rule(), packets) == []


def test_rest_of_the_scan_joins_the_alert():
    packets = numbered(*sweep(*range(1, 101), every=0.5))
    [detection] = detect(port_scan_rule(), packets)
    assert len(detection.evidence) == 100


def test_packets_behind_an_alert_are_not_counted_for_a_second_one():
    packets = numbered(*sweep(21, 22, 23, 25, 80), packet(1000, 443), packet(1001, 8080))
    [detection] = detect(port_scan_rule(), packets)
    assert ids(detection) == [1, 2, 3, 4, 5]


def test_second_scan_after_the_cooldown_is_a_second_alert():
    packets = numbered(*sweep(21, 22, 23, 25, 80), *sweep(21, 22, 23, 25, 80, start=1000))
    first, second = detect(port_scan_rule(), packets)
    assert (ids(first), ids(second)) == ([1, 2, 3, 4, 5], [6, 7, 8, 9, 10])


def test_scan_evidence_marks_the_source_and_the_destination_port():
    # Source port and destination port are the same number here; only DPT is marked.
    odd_one = packet(4, 40000)
    packets = numbered(*sweep(21, 22, 23, 25), odd_one)
    [detection] = detect(port_scan_rule(), packets)

    assert marked(detection, packets)[0] == [ATTACKER, "21"]
    [_, (start, end)] = detection.last.spans
    assert odd_one.message[start - 4 : end] == "DPT=40000"


def test_scan_grouped_by_host_marks_only_the_port():
    packets = numbered(*sweep(21, 22, 23, 25, 80))
    [detection] = detect(port_scan_rule(group_by="host"), packets)
    assert marked(detection, packets)[0] == ["21"]


def test_evaluate_counts_only_the_packets_the_rule_matches(session):
    blocked = sweep(21, 23, 25)
    allowed = [packet(3 + index, port, allowed=True) for index, port in enumerate((22, 80, 443))]
    store(session, *blocked, *allowed, packet(9, None), packet(9.5, 21))
    summary = (
        "{key}: {ports} ports, {count} packets, {seconds} s (limit {min_ports}/{window_seconds} s)"
    )

    assert evaluate(session, [port_scan_rule(match={"action": "conn_block"})]).total == 0

    evaluate(session, [port_scan_rule(summary=summary)])
    [alert] = alerts(session)
    assert (alert.rule_id, alert.group_key, alert.count) == ("NET-900", ATTACKER, 7)
    assert alert.summary == f"{ATTACKER}: 6 ports, 7 packets, 9 s (limit 5/60 s)"


# --- rare port -------------------------------------------------------------------------------


def rare_port_rule(**overrides):
    fields = {
        "id": "NET-901",
        "name": "Unexpected port",
        "type": "rare_port",
        "severity": "medium",
        "mode": "watchlist",
        "ports": [23, 3389],
        "cooldown_seconds": 300,
    }
    return RULE.validate_python(fields | overrides)


def test_watchlist_alerts_on_the_first_connection_to_a_listed_port():
    packets = numbered(packet(0, 3389, allowed=True))
    [detection] = detect(rare_port_rule(), packets)
    assert (detection.key, ids(detection)) == (ATTACKER, [1])
    assert marked(detection, packets) == [["3389"]]


def test_watchlist_ignores_every_other_port():
    assert detect(rare_port_rule(), numbered(*sweep(22, 80, 443, 33890, 338, 2))) == []


def test_allowlist_mode_alerts_on_everything_but_the_listed_ports():
    rule = rare_port_rule(mode="allowlist", ports=[22, 80, 443])
    assert detect(rule, numbered(*sweep(22, 80, 443))) == []

    [detection] = detect(rule, numbered(*sweep(22, 8080, 443, 3306)))
    assert ids(detection) == [2, 4]


@pytest.mark.parametrize("mode", ["watchlist", "allowlist"])
def test_packets_without_a_port_are_never_unexpected(mode):
    assert detect(rare_port_rule(mode=mode), numbered(packet(0, None), packet(1, None))) == []


def test_connections_of_one_source_are_one_alert_within_the_cooldown():
    packets = numbered(packet(0, 3389), packet(20, 23), packet(200, 3389), packet(900, 3389))
    first, second = detect(rare_port_rule(), packets)
    assert (ids(first), ids(second)) == ([1, 2, 3], [4])


def test_every_source_gets_its_own_alert():
    packets = numbered(packet(0, 3389), packet(1, 3389, ip=OTHER))
    assert [detection.key for detection in detect(rare_port_rule(), packets)] == [ATTACKER, OTHER]


def test_allowlisted_sources_may_use_the_port():
    packets = numbered(packet(0, 3389), packet(1, 3389, ip=OTHER))
    [detection] = detect(rare_port_rule(allowlist=[ATTACKER]), packets)
    assert detection.key == OTHER


def test_evaluate_looks_only_at_connections_the_rule_matches(session):
    store(
        session,
        packet(0, 3389),  # blocked: the firewall did its job
        packet(5, 3389, allowed=True),
        packet(6, 23, allowed=True),
        packet(7, 3389, allowed=True),
        packet(8, 443, allowed=True),
        packet(9, None, allowed=True),
    )
    rule = rare_port_rule(match={"action": "conn_allow"}, summary="{key}: {count} to {ports} ports")

    evaluate(session, [rule])
    [alert] = alerts(session)
    assert (alert.count, alert.summary) == (3, f"{ATTACKER}: 3 to 2 ports")
    assert session.scalars(select(AlertEvent.event_id).order_by(AlertEvent.event_id)).all() == [
        2,
        3,
        4,
    ]


def test_evaluate_in_allowlist_mode_skips_listed_ports_and_portless_packets(session):
    store(session, packet(0, 22), packet(1, 8080), packet(2, None), packet(3, 443))

    evaluate(session, [rare_port_rule(mode="allowlist", ports=[22, 443])])
    [alert] = alerts(session)
    assert session.scalars(select(AlertEvent.event_id)).all() == [2]
    assert alert.summary == f"Unexpected port: {ATTACKER}, 1 beklenmeyen port"


# --- filters on the destination port ---------------------------------------------------------


def test_any_rule_can_be_limited_to_certain_destination_ports(session):
    store(
        session, *(packet(second, 22) for second in range(5)), *sweep(80, 80, 80, 80, 80, start=10)
    )
    rule = RULE.validate_python(
        {
            "id": "NET-902",
            "name": "Blocked SSH",
            "type": "threshold",
            "severity": "low",
            "match": {"action": "conn_block", "dst_port": 22},
            "threshold": 5,
            "window_seconds": 60,
        }
    )

    evaluate(session, [rule])
    [alert] = alerts(session)
    assert (alert.count, alert.last_seen) == (5, T0 + timedelta(seconds=4))
