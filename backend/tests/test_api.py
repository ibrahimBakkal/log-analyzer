"""The HTTP API: /health, /ingest and /events."""

from collections import Counter

import pytest

import generate  # samples/generate.py
from app.db import Base

SAMPLE = generate.DEFAULT_OUTPUT
YEAR = generate.DEFAULT_START.year
LINES = generate.build_lines()
TOTAL = len(LINES)


def upload(client, content: bytes | None = None, filename: str = "auth.log", **form):
    """POST a file to /ingest; the sample log unless *content* is given."""
    data = {"year": str(YEAR)} | {key: str(value) for key, value in form.items()}
    body = SAMPLE.read_bytes() if content is None else content
    return client.post("/ingest", files={"file": (filename, body)}, data=data)


def all_events(client, **params) -> list[dict]:
    """Follow next_cursor until the last page."""
    events, cursor = [], None
    while True:
        page = client.get("/events", params=params | ({"cursor": cursor} if cursor else {}))
        assert page.status_code == 200, page.text
        body = page.json()
        events += body["items"]
        cursor = body["next_cursor"]
        if cursor is None:
            return events


@pytest.fixture
def loaded(client):
    """A client whose database already holds the sample log."""
    assert upload(client).status_code == 200
    return client


# --- /health ---------------------------------------------------------------------------------


def test_health_is_ok_when_the_database_is_ready(client):
    response = client.get("/health")
    assert (response.status_code, response.json()) == (200, {"status": "ok"})


def test_health_reports_a_database_without_tables(client, engine):
    Base.metadata.drop_all(engine)
    response = client.get("/health")
    assert response.status_code == 503
    assert "alembic upgrade head" in response.json()["detail"]


# --- /ingest ---------------------------------------------------------------------------------


def test_sample_log_is_accounted_for_line_by_line(client):
    report = upload(client).json()

    assert report["source_file"] == "auth.log"
    assert report["lines"] == report["parsed"] + report["unparsed"] == TOTAL
    assert (report["duplicates"], report["conflicts"]) == (0, 0)
    assert len(all_events(client)) == TOTAL


def test_uploading_the_sample_twice_creates_no_copies(client):
    upload(client)
    report = upload(client).json()

    assert (report["parsed"], report["unparsed"]) == (0, 0)
    assert report["duplicates"] == TOTAL
    assert len(all_events(client)) == TOTAL


def test_time_zone_of_the_logging_machine_is_applied(client):
    upload(client, tz="Europe/Istanbul")
    first = client.get("/events", params={"limit": 1}).json()["items"][0]

    assert LINES[0].startswith("Sep  9 00:00:07")
    assert first["ts"] == "2026-09-08T21:00:07Z"


def test_lines_can_be_stored_under_another_source_name(client):
    assert upload(client, source="web-01/auth.log.1").json()["source_file"] == "auth.log.1"
    assert upload(client).json()["duplicates"] == 0  # "auth.log" is a different file


def test_directories_are_stripped_from_the_uploaded_file_name(client):
    report = upload(client, filename="C:\\logs\\..\\auth.log").json()
    assert report["source_file"] == "auth.log"


@pytest.mark.parametrize(
    ("form", "problem"),
    [
        ({"parser": "nginx"}, "unknown parser 'nginx'"),
        ({"tz": "Mars/Olympus_Mons"}, "unknown time zone 'Mars/Olympus_Mons'"),
        ({"tz": "../../etc/passwd"}, "unknown time zone"),
    ],
)
def test_bad_upload_options_are_explained(client, form, problem):
    response = upload(client, **form)
    assert response.status_code == 422
    assert problem in response.json()["detail"]


def test_file_that_is_not_a_log_is_refused(client):
    response = upload(client, content=b"hello\nthis is not a log file\n", filename="notes.txt")
    assert response.status_code == 422
    assert "timestamp" in response.json()["detail"]
    assert all_events(client) == []


def test_upload_without_a_file_is_a_validation_error(client):
    assert client.post("/ingest", data={"year": "2026"}).status_code == 422


# --- /events: paging -------------------------------------------------------------------------


def test_events_have_the_documented_fields(loaded):
    event = loaded.get("/events", params={"action": "auth_ok", "limit": 1}).json()["items"][0]

    assert set(event) == {
        "id", "ts", "host", "service", "level", "src_ip", "dst_ip", "src_port", "dst_port",
        "user", "action", "message", "raw", "source_file", "line_no", "parsed",
    }  # fmt: skip
    assert event["raw"] == LINES[event["line_no"] - 1]
    assert event["ts"].endswith("Z")
    assert (event["action"], event["level"], event["parsed"]) == ("auth_ok", "info", True)


def test_default_page_holds_100_events_and_points_to_the_next(loaded):
    body = loaded.get("/events").json()
    assert len(body["items"]) == 100
    assert body["next_cursor"]


def test_following_the_cursor_returns_every_event_once_in_chronological_order(loaded):
    events = all_events(loaded, limit=64)

    assert len(events) == TOTAL
    assert len({event["id"] for event in events}) == TOTAL
    keys = [(event["ts"], event["id"]) for event in events]
    assert keys == sorted(keys)
    assert [event["raw"] for event in events] == LINES  # the sample is already in time order


def test_last_page_has_no_cursor(loaded):
    body = loaded.get("/events", params={"action": "sudo_denied", "limit": 500}).json()
    assert len(body["items"]) == 2
    assert body["next_cursor"] is None


def test_page_that_ends_exactly_at_the_last_event_has_no_cursor(loaded):
    body = loaded.get("/events", params={"action": "sudo_denied", "limit": 2}).json()
    assert len(body["items"]) == 2
    assert body["next_cursor"] is None


@pytest.mark.parametrize("limit", [0, 501, "many"])
def test_limit_outside_1_to_500_is_rejected(loaded, limit):
    assert loaded.get("/events", params={"limit": limit}).status_code == 422


@pytest.mark.parametrize("cursor", ["garbage", "bm90IGEgY3Vyc29y", "MjAyNi0wOS0wOVQwMzoxMjozOXwx"])
def test_invalid_cursor_is_a_client_error(loaded, cursor):
    response = loaded.get("/events", params={"cursor": cursor})
    assert (response.status_code, response.json()["detail"]) == (400, "invalid cursor")


# --- /events: filters ------------------------------------------------------------------------


def count_lines(*needles: str) -> int:
    return sum(any(needle in line for needle in needles) for line in LINES)


def test_filter_by_action(loaded):
    events = all_events(loaded, action="auth_ok")
    assert len(events) == count_lines("]: Accepted ") == 13
    assert Counter(event["user"] for event in events) == {"alice": 4, "bob": 3, "deploy": 6}


def test_filter_by_ip(loaded):
    events = all_events(loaded, ip=generate.INTRUDER_IP)
    assert len(events) == count_lines(
        f"from {generate.INTRUDER_IP} port", f" {generate.INTRUDER_IP} port"
    )
    assert {event["src_ip"] for event in events} == {generate.INTRUDER_IP}


def test_filter_by_service(loaded):
    events = all_events(loaded, service="sudo")
    assert len(events) == count_lines(" sudo: ")
    assert {event["service"] for event in events} == {"sudo"}


def test_filter_by_host(loaded):
    assert len(all_events(loaded, host="web-01")) == TOTAL
    assert all_events(loaded, host="web-02") == []


def test_filter_by_level(loaded):
    warnings = all_events(loaded, level="warning")
    assert {event["action"] for event in warnings} == {"auth_fail", "invalid_user", "sudo_denied"}
    assert len(warnings) + len(all_events(loaded, level="info")) == TOTAL


def test_filter_by_parsed(loaded):
    unparsed = all_events(loaded, parsed="false")
    assert unparsed and {event["action"] for event in unparsed} == {None}
    assert len(unparsed) + len(all_events(loaded, parsed="true")) == TOTAL


def test_time_window_includes_its_start_and_excludes_its_end(loaded):
    # The hourly cron job logs two lines at exactly 03:17:01 and 04:17:01.
    window = {"service": "CRON", "start": "2026-09-09T03:17:01Z", "end": "2026-09-09T04:17:01Z"}
    events = all_events(loaded, **window)
    assert [event["ts"] for event in events] == ["2026-09-09T03:17:01Z"] * 2


def test_time_without_offset_is_read_as_utc_and_offsets_are_honoured(loaded):
    naive = all_events(
        loaded, service="CRON", start="2026-09-09T03:17:01", end="2026-09-09T03:17:02"
    )
    shifted = all_events(
        loaded, service="CRON", start="2026-09-09T06:17:01+03:00", end="2026-09-09T06:17:02+03:00"
    )
    assert len(naive) == 2
    assert naive == shifted


def test_filters_combine(loaded):
    events = all_events(
        loaded, action="auth_fail", ip=generate.BRUTE_IP, start="2026-09-10T00:00:00Z"
    )
    # The second, shorter wave of the brute-force story.
    assert len(events) == sum(
        "Failed password" in line and generate.BRUTE_IP in line and line.startswith("Sep 10")
        for line in LINES
    )
    assert 20 < len(events) < 50


def test_filters_apply_across_pages(loaded):
    events = all_events(loaded, action="auth_fail", limit=50)
    assert len(events) == count_lines("]: Failed password for ")
    assert {event["action"] for event in events} == {"auth_fail"}


@pytest.mark.parametrize(
    "params",
    [{"action": "teleport"}, {"level": "loud"}, {"start": "yesterday"}, {"parsed": "maybe"}],
)
def test_unknown_filter_values_are_rejected(loaded, params):
    assert loaded.get("/events", params=params).status_code == 422
