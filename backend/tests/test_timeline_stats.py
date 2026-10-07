"""GET /timeline and GET /stats, and the CORS setting the web interface needs."""

from datetime import UTC, datetime, timedelta

import pytest

import generate  # samples/generate.py
from app.routers import timeline as timeline_router

YEAR = generate.DEFAULT_START.year
ENTRIES = generate.build_entries()
LINES = generate.build_lines()
TOTAL = len(LINES)


@pytest.fixture
def loaded(client):
    body = "\n".join(LINES).encode()
    response = client.post("/ingest", files={"file": ("auth.log", body)}, data={"year": str(YEAR)})
    assert response.status_code == 200
    return client


def buckets(client, **params) -> list[dict]:
    response = client.get("/timeline", params=params)
    assert response.status_code == 200, response.text
    return response.json()["buckets"]


def floor(moment: datetime, seconds: int) -> str:
    """The bucket a (naive, UTC) generator timestamp falls into, as the API writes it."""
    epoch = int(moment.replace(tzinfo=UTC).timestamp()) // seconds * seconds
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


# --- /timeline -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("bucket", "seconds"), [("1m", 60), ("5m", 300), ("1h", 3600), ("1d", 86400)]
)
def test_timeline_counts_every_event_in_the_bucket_it_falls_into(loaded, bucket, seconds):
    expected: dict[str, int] = {}
    for moment, _ in ENTRIES:
        expected[floor(moment, seconds)] = expected.get(floor(moment, seconds), 0) + 1

    body = loaded.get("/timeline", params={"bucket": bucket}).json()

    assert body["bucket_seconds"] == seconds
    assert {item["ts"]: item["count"] for item in body["buckets"]} == expected
    assert [item["ts"] for item in body["buckets"]] == sorted(expected)


def test_timeline_defaults_to_five_minute_buckets(loaded):
    assert loaded.get("/timeline").json()["bucket_seconds"] == 300


def test_timeline_reports_the_warning_share_of_each_bucket(loaded):
    for item in buckets(loaded, bucket="1h"):
        window = {"start": item["ts"], "end": _plus(item["ts"], hours=1), "level": "warning"}
        assert item["warnings"] == sum(b["count"] for b in buckets(loaded, bucket="1h", **window))
        assert 0 <= item["warnings"] <= item["count"]


def _plus(stamp: str, **delta) -> str:
    moment = datetime.fromisoformat(stamp.replace("Z", "+00:00")) + timedelta(**delta)
    return moment.isoformat().replace("+00:00", "Z")


def test_timeline_takes_the_same_filters_as_events(loaded):
    params = {"action": "auth_fail", "ip": generate.BRUTE_IP, "bucket": "1h"}
    found = buckets(loaded, **params)

    assert [item["ts"] for item in found] == ["2026-09-09T03:00:00Z", "2026-09-10T15:00:00Z"]
    assert [item["count"] for item in found] == [71, 32]
    assert [item["warnings"] for item in found] == [71, 32]

    late = buckets(loaded, **params, start="2026-09-10T00:00:00Z")
    assert [item["count"] for item in late] == [32]
    assert sum(item["count"] for item in buckets(loaded, rule_id="KW-001")) == 1


TIME_RANGES = [
    {},
    {"start": "2026-09-10T00:00:00Z"},
    {"end": "2026-09-10T00:00:00Z"},
    # Edges in the middle of a bucket: the first and last bucket are counted in part.
    {"start": "2026-09-09T03:12:40Z", "end": "2026-09-09T03:13:10Z"},
    {"start": "2026-09-09T03:12:41+03:00", "end": "2026-09-10T15:40:50Z"},
    {"start": "2026-09-09T10:17:00", "end": "2026-09-09T21:03:30"},
    {"start": "2027-01-01T00:00:00Z"},
    {"end": "2020-01-01T00:00:00Z"},
]


@pytest.mark.parametrize("bucket", ["1m", "5m", "1h", "1d"])
@pytest.mark.parametrize("time_range", TIME_RANGES)
def test_counting_from_the_index_gives_what_grouping_gives(loaded, monkeypatch, bucket, time_range):
    quick = buckets(loaded, bucket=bucket, **time_range)
    monkeypatch.setattr("app.routers.timeline._only_by_time", lambda filters: False)
    grouped = buckets(loaded, bucket=bucket, **time_range)

    assert quick == grouped
    if not time_range:
        assert sum(item["count"] for item in quick) == TOTAL


def test_quick_count_is_used_exactly_when_only_time_is_filtered(loaded, monkeypatch):
    calls = []
    original = timeline_router._count_by_range
    monkeypatch.setattr(
        timeline_router,
        "_count_by_range",
        lambda *arguments: calls.append(1) or original(*arguments),
    )
    buckets(loaded, bucket="1h")
    buckets(loaded, bucket="1h", start="2026-09-10T00:00:00Z")
    assert len(calls) == 2
    for narrowed in ({"ip": generate.BRUTE_IP}, {"level": "warning"}, {"rule_id": "SSH-001"}):
        buckets(loaded, bucket="1h", **narrowed)
    assert len(calls) == 2


def test_very_long_range_is_grouped_instead_of_probed_bucket_by_bucket(loaded, monkeypatch):
    expected = buckets(loaded, bucket="1m")
    monkeypatch.setattr(timeline_router, "MAX_PROBES", 100)  # the sample spans 2,880 minutes
    assert buckets(loaded, bucket="1m") == expected


def test_day_buckets_start_at_midnight_utc(loaded):
    days = buckets(loaded, bucket="1d")
    assert [item["ts"] for item in days] == ["2026-09-09T00:00:00Z", "2026-09-10T00:00:00Z"]
    assert sum(item["count"] for item in days) == TOTAL


def test_timeline_of_an_empty_database_is_empty(client):
    assert client.get("/timeline").json() == {"bucket_seconds": 300, "buckets": []}


def test_timeline_rejects_unknown_bucket_widths(loaded):
    assert loaded.get("/timeline", params={"bucket": "2h"}).status_code == 422


def test_timeline_refuses_to_return_an_unreasonable_number_of_buckets(client, monkeypatch):
    monkeypatch.setattr("app.routers.timeline.MAX_BUCKETS", 10)
    lines = [f"Sep  9 {hour:02d}:00:00 web-01 CRON[1]: tick" for hour in range(11)]
    client.post(
        "/ingest", files={"file": ("cron.log", "\n".join(lines).encode())}, data={"year": "2026"}
    )

    assert client.get("/timeline", params={"bucket": "1h"}).status_code == 422
    assert len(buckets(client, bucket="1h", end="2026-09-09T10:00:00Z")) == 10


# --- /stats ----------------------------------------------------------------------------------


def test_stats_of_an_empty_database(client):
    body = client.get("/stats").json()
    assert (body["events"], body["alerts"], body["unparsed_ratio"]) == (0, 0, 0.0)
    assert (body["first_event"], body["last_event"], body["top_sources"]) == (None, None, [])


def test_stats_of_the_sample(loaded):
    body = loaded.get("/stats").json()

    def count(*needles: str) -> int:
        return sum(any(needle in line for needle in needles) for line in LINES)

    assert body["events"] == body["parsed"] + body["unparsed"] == TOTAL
    assert body["unparsed_ratio"] == round(body["unparsed"] / TOTAL, 4)
    assert (body["first_event"], body["last_event"]) == (
        "2026-09-09T00:00:07Z",
        "2026-09-10T23:17:01Z",
    )
    assert body["actions"]["auth_fail"] == count("]: Failed password for ")
    assert body["actions"]["auth_ok"] == count("]: Accepted ") == 13
    assert sum(body["actions"].values()) == body["parsed"]
    assert body["alerts"] == 6
    assert body["alerts_by_severity"] == {"critical": 1, "high": 4, "medium": 1}
    assert body["sources"] == 3 + 4 + 56  # known users, the four stories, background noise


def test_stats_rank_sources_by_failed_logins(loaded):
    top = loaded.get("/stats").json()["top_sources"]

    assert [source["src_ip"] for source in top[:4]] == [
        generate.BRUTE_IP,
        generate.SCANNER_IP,
        generate.SLOW_IP,
        generate.INTRUDER_IP,
    ]
    assert [source["failures"] for source in top[:4]] == [103, 30, 29, 24]
    assert len(top) == 5 and all(source["events"] >= source["failures"] for source in top)


def test_stats_can_be_limited_to_a_time_range(loaded):
    day_two = loaded.get("/stats", params={"start": "2026-09-10T00:00:00Z"}).json()
    day_one = loaded.get("/stats", params={"end": "2026-09-10T00:00:00Z"}).json()

    assert day_one["events"] + day_two["events"] == TOTAL
    assert day_one["events"] == sum(line.startswith("Sep  9") for line in LINES)
    assert (day_one["alerts"], day_two["alerts"]) == (2, 4)
    assert day_two["first_event"] >= "2026-09-10T00:00:00Z" > day_one["last_event"]
    assert day_two["top_sources"][0]["src_ip"] == generate.BRUTE_IP
    assert day_two["top_sources"][0]["failures"] == 32


# --- CORS ------------------------------------------------------------------------------------


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173"])
def test_the_dev_server_of_the_web_interface_may_call_the_api(client, origin):
    response = client.get("/health", headers={"Origin": origin})
    assert response.headers["access-control-allow-origin"] == origin

    preflight = client.options(
        "/ingest", headers={"Origin": origin, "Access-Control-Request-Method": "POST"}
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == origin


def test_other_origins_get_no_cors_permission(client):
    response = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in response.headers
