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


def test_new_file_can_be_stored_under_a_chosen_name(client):
    assert upload(client, source="web-01/auth.log.1").json()["source_file"] == "auth.log.1"


def test_file_is_recognized_whatever_name_it_comes_back_under(client):
    upload(client)
    for filename in ("auth.log.1", "copy-of-auth.log", "auth.log"):
        report = upload(client, filename=filename).json()
        assert (report["source_file"], report["duplicates"]) == ("auth.log", TOTAL)
        assert report["parsed"] + report["unparsed"] == 0


def test_rotation_is_followed_without_storing_a_line_twice(client):
    """Monday's auth.log is Tuesday's auth.log.1; a new auth.log has taken its place."""
    monday = "\n".join(LINES[:400]).encode()
    rotated = "\n".join(LINES[:600]).encode()  # it grew before it was rotated
    fresh = "\n".join(LINES[600:]).encode()

    upload(client, monday)
    old = upload(client, rotated, filename="auth.log.1").json()
    new = upload(client, fresh).json()

    assert (old["source_file"], old["duplicates"], old["parsed"] + old["unparsed"]) == (
        "auth.log",
        400,
        200,
    )
    assert (new["source_file"], new["duplicates"], new["conflicts"]) == (
        "auth.log (2026-09-09)",
        0,
        0,
    )
    assert new["parsed"] + new["unparsed"] == TOTAL - 600
    assert len(all_events(client, limit=500)) == TOTAL


@pytest.mark.parametrize("pack", ["gzip", "bz2", "lzma"])
def test_compressed_file_is_unpacked(client, pack):
    import importlib

    packed = importlib.import_module(pack).compress(SAMPLE.read_bytes())
    report = upload(client, packed, filename="auth.log.2.gz").json()
    assert (report["lines"], report["parsed"], report["unparsed"]) == (TOTAL, 605, 452)

    # ... and it is the same file as the plain one.
    assert upload(client).json()["duplicates"] == TOTAL


def test_compression_is_told_from_the_content_not_the_name(client):
    report = upload(client, filename="auth.log.gz").json()  # plain text behind a .gz name
    assert (report["lines"], report["source_file"]) == (TOTAL, "auth.log.gz")


def test_damaged_compressed_file_is_refused_with_the_line_it_broke_at(client):
    import gzip

    packed = gzip.compress(SAMPLE.read_bytes())
    response = upload(client, packed[: len(packed) // 2], filename="auth.log.1.gz")
    assert response.status_code == 422
    assert "compressed file is damaged after line" in response.json()["detail"]
    assert "The lines before that were stored." in response.json()["detail"]

    # What could be read was stored and the rules have seen it ...
    salvaged = len(all_events(client, limit=500))
    assert 100 < salvaged < TOTAL
    assert client.get("/alerts").json()["total"] >= 1

    # ... and the whole file fills in the rest.
    report = upload(client).json()
    assert (report["duplicates"], report["parsed"] + report["unparsed"]) == (
        salvaged,
        TOTAL - salvaged,
    )


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
        "user", "action", "message", "raw", "source_file", "line_no", "parsed", "highlights",
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


# --- /events: newest first -------------------------------------------------------------------


def test_events_can_be_listed_newest_first(loaded):
    oldest_first = all_events(loaded, limit=500)
    newest_first = all_events(loaded, limit=500, order="desc")
    assert [event["id"] for event in newest_first] == [event["id"] for event in oldest_first][::-1]


def test_newest_first_pages_neither_skip_nor_repeat(loaded):
    in_small_pages = all_events(loaded, limit=37, order="desc", ip="203.0.113.45")
    at_once = all_events(loaded, limit=500, order="desc", ip="203.0.113.45")
    assert in_small_pages == at_once
    assert len({event["id"] for event in in_small_pages}) == len(in_small_pages) > 100


def test_newest_first_starts_with_the_last_line_of_the_log(loaded):
    [newest] = loaded.get("/events", params={"order": "desc", "limit": 1}).json()["items"]
    assert newest["ts"] == loaded.get("/stats").json()["last_event"]


def test_unknown_order_is_rejected(loaded):
    assert loaded.get("/events", params={"order": "sideways"}).status_code == 422
