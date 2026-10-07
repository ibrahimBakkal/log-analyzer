"""The firewall sample: reproducible, anonymized, and what the rules make of it."""

import json
import re
from pathlib import Path

import pytest

import generate  # samples/generate.py
import generate_ufw  # samples/generate_ufw.py
from app.parsers import create_parser

SAMPLE = generate_ufw.DEFAULT_OUTPUT
GOLDEN = Path(__file__).with_name("golden")
YEAR = generate.DEFAULT_START.year
LINES = generate_ufw.build_lines()


def upload(client, lines: list[str], *, parser: str = "ufw", filename: str = "ufw.log") -> dict:
    files = {"file": (filename, "\n".join(lines).encode())}
    response = client.post("/ingest", files=files, data={"year": str(YEAR), "parser": parser})
    assert response.status_code == 200, response.text
    return response.json()


def alerts(client, **params) -> list[dict]:
    """Alerts, oldest first."""
    return client.get("/alerts", params={"limit": 500} | params).json()["items"][::-1]


def golden(name: str) -> list[dict]:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


# --- the generator -------------------------------------------------------------------------


def test_committed_sample_is_what_the_generator_produces():
    assert SAMPLE.read_text(encoding="utf-8").splitlines() == LINES


def test_output_depends_only_on_the_seed():
    assert generate_ufw.build_lines(seed=7) == generate_ufw.build_lines(seed=7)
    assert generate_ufw.build_lines(seed=7) != generate_ufw.build_lines(seed=8)


def test_log_is_chronological_anonymized_and_of_a_useful_size():
    stamps = [when for when, _ in generate_ufw.build_entries()]
    assert stamps == sorted(stamps)
    assert 600 <= len(LINES) <= 1000
    assert generate.leaked_ips(LINES) == set()
    assert all(
        re.match(r"[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d web-01 kernel: \[", line) for line in LINES
    )


def test_every_line_is_a_packet_the_ufw_parser_reads():
    parser = create_parser("ufw", year=YEAR)
    entries = [parser.parse(line) for line in LINES]
    assert all(entry is not None and entry.parsed for entry in entries)
    assert {entry.dst_ip for entry in entries} == {generate_ufw.SERVER_IP}


def test_every_ssh_connection_of_the_auth_log_was_let_through_the_firewall():
    peers = set()
    for line in generate.build_lines():
        if match := re.search(r"((?:\d{1,3}\.){3}\d{1,3}) port (\d+)", line):
            peers.add(match.groups())
    peers.discard(("0.0.0.0", "22"))  # sshd's own listen address

    allowed = {
        (match[1], match[2])
        for line in LINES
        if "[UFW ALLOW]" in line and (match := re.search(r"SRC=(\S+) .* SPT=(\d+) DPT=22 ", line))
    }
    assert len(peers) > 150
    assert peers <= allowed


# --- what the rules find -------------------------------------------------------------------


def test_scan_log_produces_exactly_the_expected_alerts(client):
    """Golden file test for the firewall sample."""
    report = upload(client, LINES)
    found = alerts(client)
    expected = golden("sample_ufw_alerts.json")

    assert (report["parsed"], report["unparsed"], report["alerts"]) == (len(LINES), 0, 2)
    assert [{name: alert[name] for name in expected[0]} for alert in found] == expected


def test_ordinary_traffic_and_the_slow_scan_produce_no_port_scan_alert(client):
    quiet = [line for line in LINES if f"SRC={generate_ufw.PORTSCAN_IP} " not in line]
    assert any(f"SRC={generate_ufw.SLOW_SCAN_IP} " in line for line in quiet)

    upload(client, quiet)
    assert alerts(client, rule_id="NET-001") == []
    assert alerts(client, group_key=generate_ufw.SLOW_SCAN_IP) == []


def test_without_the_open_remote_desktop_port_nothing_is_reported_as_exposed(client):
    upload(client, [line for line in LINES if "DPT=3389 " not in line])
    assert alerts(client, rule_id="NET-002") == []


def test_both_samples_together_produce_the_alerts_of_each(client):
    upload(client, generate.build_lines(), parser="auth", filename="auth.log")
    assert upload(client, LINES)["alerts"] == 8

    found = alerts(client)
    expected = golden("sample_alerts.json") + golden("sample_ufw_alerts.json")
    key = lambda alert: (alert["first_seen"], alert["rule_id"])  # noqa: E731
    assert sorted(({n: a[n] for n in expected[0]} for a in found), key=key) == sorted(
        expected, key=key
    )


def test_scan_evidence_marks_the_source_and_the_port(client):
    upload(client, LINES)
    [scan] = alerts(client, rule_id="NET-001")
    event = client.get("/events", params={"alert_id": scan["id"], "limit": 1}).json()["items"][0]

    marked = [event["message"][mark["start"] : mark["end"]] for mark in event["highlights"]]
    assert marked == [generate_ufw.PORTSCAN_IP, str(event["dst_port"])]
    assert (event["action"], event["service"], event["dst_ip"]) in {
        ("conn_block", "kernel", generate_ufw.SERVER_IP),
        ("conn_allow", "kernel", generate_ufw.SERVER_IP),
    }


def test_firewall_log_read_as_auth_log_is_stored_but_recognizes_nothing(client):
    report = upload(client, LINES[:50], parser="auth")
    assert (report["parsed"], report["unparsed"], report["alerts"]) == (0, 50, 0)


# --- /ports --------------------------------------------------------------------------------


@pytest.fixture
def loaded(client):
    upload(client, LINES)
    return client


def test_port_report_of_the_scanner(loaded):
    body = loaded.get("/ports", params={"ip": generate_ufw.PORTSCAN_IP}).json()

    assert (body["ip"], body["total"], body["distinct_ports"]) == (
        generate_ufw.PORTSCAN_IP,
        120,
        120,
    )
    assert len(body["ports"]) == len(body["connections"]) == 120 and not body["truncated"]
    assert all(port["count"] == 1 for port in body["ports"])
    assert sum(port["allowed"] for port in body["ports"]) == 3  # 22, 80 and 443 are open
    assert sum(port["blocked"] for port in body["ports"]) == 117
    stamps = [connection["ts"] for connection in body["connections"]]
    assert stamps == sorted(stamps)
    assert (stamps[0], stamps[-1]) == ("2026-09-09T05:20:18Z", "2026-09-09T05:20:57Z")


def test_port_report_lists_the_busiest_ports_first(loaded):
    body = loaded.get("/ports", params={"ip": generate.BRUTE_IP}).json()
    ssh, other = body["ports"]

    assert (ssh["port"], ssh["blocked"], other["count"], other["allowed"]) == (22, 0, 1, 0)
    assert ssh["count"] == ssh["allowed"] == body["total"] - 1 > 40
    assert ssh["first_seen"] < ssh["last_seen"]
    assert other["first_seen"] == other["last_seen"]
    assert body["distinct_ports"] == 2


def test_port_report_can_be_limited_to_a_time_range(loaded):
    day_two = {"ip": generate.BRUTE_IP, "start": "2026-09-10T00:00:00Z"}
    day_one = {"ip": generate.BRUTE_IP, "end": "2026-09-10T00:00:00Z"}
    everything = loaded.get("/ports", params={"ip": generate.BRUTE_IP}).json()["total"]

    counts = [loaded.get("/ports", params=params).json()["total"] for params in (day_one, day_two)]
    assert sum(counts) == everything and all(counts)


def test_port_report_of_an_unknown_address_is_empty(loaded):
    body = loaded.get("/ports", params={"ip": "192.0.2.250"}).json()
    assert (body["total"], body["distinct_ports"], body["ports"], body["connections"]) == (
        0,
        0,
        [],
        [],
    )


def test_port_report_needs_an_address(loaded):
    assert loaded.get("/ports").status_code == 422


def test_port_report_caps_the_connection_list(loaded, monkeypatch):
    monkeypatch.setattr("app.routers.ports.MAX_CONNECTIONS", 50)
    body = loaded.get("/ports", params={"ip": generate_ufw.PORTSCAN_IP}).json()
    assert (len(body["connections"]), body["truncated"], body["total"]) == (50, True, 120)
