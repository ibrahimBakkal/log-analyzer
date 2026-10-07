"""Rules and alerts through the API, including what the sample log must produce."""

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import generate  # samples/generate.py
from app.config import get_settings
from app.main import app

GOLDEN = Path(__file__).with_name("golden") / "sample_alerts.json"
SHIPPED_RULES = Path(__file__).resolve().parents[2] / "rules"
YEAR = generate.DEFAULT_START.year
LINES = generate.build_lines()
ATTACKERS = {generate.SCANNER_IP, generate.BRUTE_IP, generate.INTRUDER_IP}


def upload(client, lines: list[str] | None = None, filename: str = "auth.log"):
    """POST lines to /ingest; the whole sample log unless *lines* is given."""
    body = "\n".join(LINES if lines is None else lines).encode()
    response = client.post("/ingest", files={"file": (filename, body)}, data={"year": str(YEAR)})
    assert response.status_code == 200, response.text
    return response.json()


def alerts(client, **params) -> list[dict]:
    """Alerts matching *params*, oldest first."""
    response = client.get("/alerts", params={"limit": 500} | params)
    assert response.status_code == 200, response.text
    return response.json()["items"][::-1]


def events(client, **params) -> list[dict]:
    items, cursor = [], None
    while True:
        page = client.get("/events", params=params | ({"cursor": cursor} if cursor else {})).json()
        items += page["items"]
        cursor = page["next_cursor"]
        if cursor is None:
            return items


def burst(count: int, ip: str = "203.0.113.200") -> list[str]:
    """*count* failed logins from one address, one per second."""
    return [
        f"Sep  9 05:{second // 60:02d}:{second % 60:02d} web-01 sshd[{9000 + second}]: "
        f"Failed password for root from {ip} port {40000 + second} ssh2"
        for second in range(count)
    ]


@pytest.fixture
def loaded(client):
    """A client whose database holds the sample log and the alerts it produces."""
    upload(client)
    return client


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    """A private copy of the shipped rules that the application is configured to use."""
    directory = tmp_path / "rules"
    shutil.copytree(SHIPPED_RULES, directory)
    monkeypatch.setenv("LOG_ANALYZER_RULES_DIR", str(directory))
    get_settings.cache_clear()
    yield directory
    get_settings.cache_clear()


# --- the sample log --------------------------------------------------------------------------


def test_sample_log_produces_exactly_the_expected_alerts(client):
    """Golden file test: every field of every alert, in order."""
    report = upload(client)
    found = alerts(client)
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))

    assert report["alerts"] == len(found) == len(expected)
    assert [{name: alert[name] for name in expected[0]} for alert in found] == expected


def test_brute_force_is_reported_and_activity_below_the_threshold_is_not(loaded):
    brute_force = alerts(loaded, rule_id="SSH-001")
    assert {alert["group_key"] for alert in brute_force} == ATTACKERS

    # The slow attacker failed more often than the rule's threshold, just never quickly.
    slow = events(loaded, action="auth_fail", ip=generate.SLOW_IP)
    assert len(slow) == 29
    assert alerts(loaded, group_key=generate.SLOW_IP) == []
    assert all(event["highlights"] == [] for event in slow)


def test_log_without_the_attacks_produces_no_alerts(client):
    quiet = [
        line
        for line in LINES
        if not any(ip in line for ip in ATTACKERS) and "NOT in sudoers" not in line
    ]
    assert 600 < len(quiet) < len(LINES)
    assert any(generate.SLOW_IP in line for line in quiet)  # still there, still below the threshold

    assert upload(client, quiet)["alerts"] == 0
    assert client.get("/alerts").json() == {"items": [], "total": 0}


def test_uploading_again_neither_duplicates_alerts_nor_renumbers_them(loaded):
    before = alerts(loaded)
    assert upload(loaded)["alerts"] == 6
    assert alerts(loaded) == before


def test_alert_grows_as_more_of_its_burst_is_uploaded(client):
    lines = burst(40)
    assert upload(client, lines[:10])["alerts"] == 1
    [first] = alerts(client)

    assert upload(client, lines)["alerts"] == 1
    [grown] = alerts(client)
    assert (first["count"], grown["count"]) == (10, 40)
    assert grown["id"] == first["id"]
    assert grown["summary"] == "203.0.113.200 adresinden 39 sn içinde 40 başarısız giriş"


# --- GET /alerts -----------------------------------------------------------------------------


def test_alerts_are_listed_newest_first_with_their_total(loaded):
    body = loaded.get("/alerts", params={"limit": 2}).json()
    assert body["total"] == 6
    assert [alert["first_seen"] for alert in body["items"]] == [
        "2026-09-10T15:40:42Z",
        "2026-09-10T02:34:08Z",
    ]


@pytest.mark.parametrize(
    ("params", "count"),
    [
        ({}, 6),
        ({"rule_id": "SSH-001"}, 4),
        ({"rule_id": "KW-001"}, 1),
        ({"rule_id": "NOPE-1"}, 0),
        ({"severity": "high"}, 4),
        ({"severity": "medium"}, 1),
        ({"severity": "critical"}, 1),
        ({"severity": "low"}, 0),
        ({"group_key": generate.BRUTE_IP}, 2),
        ({"group_key": "bob"}, 1),
        ({"start": "2026-09-10T00:00:00Z"}, 4),
        ({"end": "2026-09-09T03:00:00Z"}, 1),
        # An alert that began before the window but was still active in it counts.
        ({"start": "2026-09-09T03:13:00Z", "end": "2026-09-09T03:13:30Z"}, 1),
        ({"start": "2026-09-09T03:14:04Z", "end": "2026-09-09T03:14:05Z"}, 1),  # start is inclusive
        ({"start": "2026-09-09T03:14:05Z", "end": "2026-09-09T03:15:00Z"}, 0),
        ({"start": "2026-09-09T03:00:00Z", "end": "2026-09-09T03:12:39Z"}, 0),  # end is exclusive
        (
            {"rule_id": "SSH-001", "group_key": generate.BRUTE_IP, "start": "2026-09-10T00:00:00Z"},
            1,
        ),
    ],
)
def test_alert_filters(loaded, params, count):
    body = loaded.get("/alerts", params=params).json()
    assert (len(body["items"]), body["total"]) == (count, count)


@pytest.mark.parametrize("params", [{"severity": "loud"}, {"limit": 0}, {"start": "yesterday"}])
def test_bad_alert_filters_are_rejected(loaded, params):
    assert loaded.get("/alerts", params=params).status_code == 422


def test_alerts_come_without_events_unless_asked(loaded):
    assert all(alert["events"] is None for alert in alerts(loaded))


def test_include_events_attaches_the_evidence_with_its_highlights(loaded):
    wave = alerts(loaded, group_key=generate.BRUTE_IP, include_events="true")[0]
    evidence = wave["events"]

    assert len(evidence) == wave["count"] == 71
    assert [event["ts"] for event in evidence] == sorted(event["ts"] for event in evidence)
    assert (evidence[0]["ts"], evidence[-1]["ts"]) == (wave["first_seen"], wave["last_seen"])
    for event in evidence:
        [mark] = event["highlights"]
        assert (mark["alert_id"], mark["rule_id"], mark["severity"]) == (
            wave["id"],
            "SSH-001",
            "high",
        )
        assert event["message"][mark["start"] : mark["end"]] == generate.BRUTE_IP


def test_include_events_is_capped_and_events_endpoint_has_the_rest(client):
    upload(client, burst(150))
    [alert] = alerts(client, include_events="true")

    assert (alert["count"], len(alert["events"])) == (150, 100)
    everything = events(client, alert_id=alert["id"], limit=64)
    assert len(everything) == 150
    assert [event["id"] for event in everything[:100]] == [event["id"] for event in alert["events"]]


# --- /events: highlights and evidence filters -----------------------------------------------


def test_keyword_evidence_marks_the_keyword(loaded):
    [alert] = alerts(loaded, rule_id="KW-001")
    [event] = events(loaded, alert_id=alert["id"])
    [mark] = event["highlights"]

    assert (event["action"], event["user"]) == ("sudo_denied", "bob")
    assert event["message"][mark["start"] : mark["end"]] == "/etc/shadow"
    assert (mark["alert_id"], mark["rule_id"], mark["severity"]) == (
        alert["id"],
        "KW-001",
        "medium",
    )


def test_events_that_are_no_evidence_have_no_highlights(loaded):
    closed = events(loaded, action="disconnect")
    assert len(closed) > 200
    assert all(event["highlights"] == [] for event in closed)


def test_event_can_be_evidence_for_two_alerts(loaded):
    """The intruder's failed logins count for the brute-force rule and for the sequence rule."""
    failed = events(loaded, action="auth_fail", ip=generate.INTRUDER_IP)[0]
    assert sorted(mark["rule_id"] for mark in failed["highlights"]) == ["SSH-001", "SSH-002"]
    assert {mark["severity"] for mark in failed["highlights"]} == {"high", "critical"}


def test_events_can_be_filtered_by_alert_and_by_rule(loaded):
    found = alerts(loaded)
    for alert in found:
        evidence = events(loaded, alert_id=alert["id"])
        assert len(evidence) == alert["count"]
        assert all(
            alert["id"] in {mark["alert_id"] for mark in event["highlights"]} for event in evidence
        )

    by_rule = events(loaded, rule_id="SSH-001")
    assert len(by_rule) == sum(a["count"] for a in found if a["rule_id"] == "SSH-001") == 157
    assert {event["action"] for event in by_rule} == {"auth_fail"}
    assert events(loaded, alert_id=999999) == events(loaded, rule_id="NOPE-1") == []


def test_evidence_filters_combine_with_the_others(loaded):
    late = events(loaded, rule_id="SSH-001", ip=generate.BRUTE_IP, start="2026-09-10T00:00:00Z")
    assert len(late) == 32


# --- /rules ----------------------------------------------------------------------------------


def test_rules_endpoint_lists_the_loaded_rules(client):
    body = client.get("/rules").json()
    assert body["errors"] == []
    assert [(rule["id"], rule["type"], rule["severity"]) for rule in body["rules"]] == [
        ("KW-001", "keyword", "medium"),
        ("NET-001", "port_scan", "high"),
        ("NET-002", "rare_port", "medium"),
        ("SSH-001", "threshold", "high"),
        ("SSH-002", "sequence", "critical"),
    ]
    ssh = body["rules"][3]
    assert (ssh["threshold"], ssh["window_seconds"], ssh["group_by"]) == (5, 60, "src_ip")
    assert ssh["match"]["action"] == ["auth_fail"]
    assert body["rules"][0]["keywords"] == ["/etc/shadow", "/etc/sudoers", "authorized_keys"]


def test_reload_applies_an_edited_rule_to_the_stored_events(rules_dir, loaded):
    path = rules_dir / "SSH-001.yaml"
    path.write_text(path.read_text(encoding="utf-8").replace("threshold: 5", "threshold: 33"))

    body = loaded.post("/rules/reload").json()

    # 33 failures within a minute: only the first brute-force wave (71) still qualifies.
    assert body["errors"] == []
    assert body["alerts"] == {"total": 3, "created": 0, "updated": 0, "removed": 3}
    assert [(alert["rule_id"], alert["group_key"]) for alert in alerts(loaded)] == [
        ("SSH-001", generate.BRUTE_IP),
        ("SSH-002", generate.INTRUDER_IP),
        ("KW-001", "bob"),
    ]
    assert loaded.get("/rules").json()["rules"][3]["threshold"] == 33


def test_reload_picks_up_a_new_rule(rules_dir, loaded):
    (rules_dir / "SSH-003.yaml").write_text(
        "id: SSH-003\nname: User name sweep\ntype: threshold\nseverity: low\n"
        "match: {action: invalid_user}\nthreshold: 10\nwindow_seconds: 120\n"
    )

    body = loaded.post("/rules/reload").json()

    assert [rule["id"] for rule in body["rules"]][-2:] == ["SSH-002", "SSH-003"]
    assert body["alerts"] == {"total": 7, "created": 1, "updated": 0, "removed": 0}
    [sweep] = alerts(loaded, rule_id="SSH-003")
    assert (sweep["group_key"], sweep["count"], sweep["severity"]) == (
        generate.SCANNER_IP,
        30,
        "low",
    )


def test_reload_reports_a_broken_file_and_keeps_the_other_rules_working(rules_dir, loaded):
    (rules_dir / "broken.yaml").write_text("id: X-1\nname: Oops\ntype: threshold\nseverity: high\n")

    body = loaded.post("/rules/reload").json()

    assert len(body["rules"]) == 5
    assert body["errors"] == [
        {
            "file": "broken.yaml",
            "message": "threshold: Field required; window_seconds: Field required",
        }
    ]
    assert body["alerts"] == {"total": 6, "created": 0, "updated": 0, "removed": 0}
    assert loaded.get("/rules").json()["errors"] == body["errors"]


def test_reload_without_rules_removes_all_alerts(rules_dir, loaded):
    for path in rules_dir.iterdir():
        path.unlink()

    body = loaded.post("/rules/reload").json()

    assert (body["rules"], body["alerts"]["removed"]) == ([], 6)
    assert loaded.get("/alerts").json() == {"items": [], "total": 0}
    assert all(event["highlights"] == [] for event in events(loaded, action="auth_fail"))


def test_application_starts_even_if_a_rule_file_is_broken(rules_dir):
    (rules_dir / "broken.yaml").write_text("id: [unclosed\n")

    with TestClient(app) as client:
        body = client.get("/rules").json()

    assert len(body["rules"]) == 5
    assert [error["file"] for error in body["errors"]] == ["broken.yaml"]
