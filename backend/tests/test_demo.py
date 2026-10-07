"""The recording the web interface's demo is built from must be what the API answers now."""

import json

import pytest

import build_demo  # samples/build_demo.py
import generate
import generate_ufw

HINT = "is out of date: run `python samples/build_demo.py` and commit the result"


@pytest.fixture(scope="module")
def built() -> tuple[str, str]:
    return build_demo.build()


def test_committed_snapshot_is_what_the_api_answers_now(built):
    if build_demo.SNAPSHOT.read_text(encoding="utf-8") != built[0]:
        pytest.fail(f"{build_demo.SNAPSHOT.name} {HINT}")


def test_committed_cases_are_what_the_api_answers_now(built):
    if build_demo.CASES.read_text(encoding="utf-8") != built[1]:
        pytest.fail(f"{build_demo.CASES.name} {HINT}")


def test_snapshot_holds_both_samples_with_their_alerts_and_rules(built):
    snapshot = json.loads(built[0])
    lines = len(generate.build_lines()) + len(generate_ufw.build_lines())

    assert len(snapshot["events"]) == lines
    assert {event["source_file"] for event in snapshot["events"]} == {"auth.log", "ufw.log"}
    assert [event["id"] for event in snapshot["events"]] != sorted(
        event["id"] for event in snapshot["events"]
    )  # in time order, which is not the order the two files were loaded in
    assert sorted(alert["rule_id"] for alert in snapshot["alerts"]) == [
        "KW-001",
        "NET-001",
        "NET-002",
        "SSH-001",
        "SSH-001",
        "SSH-001",
        "SSH-001",
        "SSH-002",
    ]
    assert (len(snapshot["rules"]["rules"]), snapshot["rules"]["errors"]) == (5, [])
    assert sum(len(event["highlights"]) > 0 for event in snapshot["events"]) > 250


def test_snapshot_contains_only_documentation_addresses(built):
    assert generate.leaked_ips(built[0].splitlines()) == set()


def test_cases_ask_about_every_endpoint_the_interface_uses(built):
    cases = json.loads(built[1])
    assert {case["path"] for case in cases} == {
        "/events",
        "/alerts",
        "/timeline",
        "/stats",
        "/ports",
        "/rules",
    }
    multi_page = [case for case in cases if case["path"] == "/events" and case["pages"] > 1]
    assert len(multi_page) >= 3


def test_building_the_demo_leaves_the_app_as_it_was(client):
    build_demo.build()
    assert client.get("/stats").json()["events"] == 0  # still the test's own empty database
