#!/usr/bin/env python3
"""Record what the API answers for the sample logs, for the web interface's demo.

The demo is the web interface without a server: a build that carries the two
sample logs with it, already turned into events and alerts, and answers its own
questions about them in the browser. This script produces what that build needs:

``frontend/src/demo/snapshot.json``
    Events (with their highlights), alerts, and rules, exactly as the API
    returns them after loading ``auth.log`` and ``ufw.log``.

``frontend/src/demo/cases.json``
    Questions and the real API's answers to them. The frontend's tests put the
    same questions to the demo and expect the same answers, so the demo cannot
    quietly drift away from the API.

Usage (in the backend's virtual environment)::

    python samples/build_demo.py           # rewrites both files
"""

import argparse
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import generate
import generate_ufw
from app.db import Base, get_session, make_engine
from app.main import app

DEMO_DIR = Path(__file__).resolve().parents[1] / "frontend" / "src" / "demo"
SNAPSHOT = DEMO_DIR / "snapshot.json"
CASES = DEMO_DIR / "cases.json"

YEAR = generate.DEFAULT_START.year
SAMPLES = (
    ("auth.log", generate.build_lines),
    ("ufw.log", generate_ufw.build_lines),
)
PAGE = 200  # the page size the web interface asks for

BRUTE, INTRUDER, SLOW = generate.BRUTE_IP, generate.INTRUDER_IP, generate.SLOW_IP
SCANNER, RDP_VISITOR = generate_ufw.PORTSCAN_IP, generate_ufw.RARE_PORT_IP
DAY_ONE, DAY_TWO, DAY_THREE = (
    "2026-09-09T00:00:00Z",
    "2026-09-10T00:00:00Z",
    "2026-09-11T00:00:00Z",
)


@contextmanager
def loaded_api() -> Iterator[TestClient]:
    """The API on a database of its own that holds the sample logs."""
    engine = make_engine("sqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)

    def session() -> Iterator[Session]:
        with Session(engine, expire_on_commit=False) as database:
            yield database

    previous = dict(app.dependency_overrides)
    app.dependency_overrides[get_session] = session
    try:
        with TestClient(app) as client:
            for name, build_lines in SAMPLES:
                files = {"file": (name, "\n".join(build_lines()).encode())}
                client.post("/ingest", files=files, data={"year": str(YEAR)}).raise_for_status()
            yield client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)
        engine.dispose()


def get(client: TestClient, path: str, **params: Any) -> Any:
    response = client.get(path, params=params)
    response.raise_for_status()
    return response.json()


def all_events(client: TestClient, **params: Any) -> tuple[list[dict[str, Any]], int]:
    """Every event the filters select, and the number of pages it took to get them."""
    events: list[dict[str, Any]] = []
    pages, cursor = 0, None
    while True:
        extra = {"cursor": cursor} if cursor else {}
        page = get(client, "/events", limit=PAGE, **params, **extra)
        events += page["items"]
        pages += 1
        cursor = page["next_cursor"]
        if cursor is None:
            return events, pages


def build_snapshot(client: TestClient) -> dict[str, Any]:
    events, _ = all_events(client)
    return {
        "events": events,
        "alerts": get(client, "/alerts", limit=500)["items"],
        "rules": get(client, "/rules"),
    }


def build_cases(client: TestClient) -> list[dict[str, Any]]:
    alerts = get(client, "/alerts", limit=500)["items"]
    brute = next(a for a in alerts if a["rule_id"] == "SSH-001" and a["count"] == 71)
    scan = next(a for a in alerts if a["rule_id"] == "NET-001")
    burst = {"start": "2026-09-09T03:11:39Z", "end": "2026-09-09T03:15:05Z"}
    morning = {"start": "2026-09-09T05:19:00Z", "end": "2026-09-09T05:22:00Z"}

    event_filters: list[dict[str, Any]] = [
        {},
        {"start": DAY_TWO},
        {"end": DAY_TWO},
        burst,
        {"ip": INTRUDER},
        {"ip": INTRUDER, "level": "warning"},
        {"ip": generate_ufw.SERVER_IP, "start": DAY_TWO, "action": "conn_block"},
        {"service": "sudo"},
        {"host": "web-01", "service": "CRON", "end": DAY_TWO},
        {"level": "warning", **morning},
        {"action": "auth_ok"},
        {"parsed": False, "start": DAY_TWO},
        {"parsed": True, "service": "sshd", "end": "2026-09-09T06:00:00Z"},
        {"rule_id": "SSH-001"},
        {"rule_id": "NET-002"},
        {"alert_id": brute["id"]},
        {"alert_id": brute["id"], **burst, "level": "warning"},
        {"alert_id": scan["id"], "ip": SCANNER},
        {"ip": "192.0.2.250"},
        {"rule_id": "NO-SUCH-RULE"},
        {"order": "desc"},
        {"order": "desc", "ip": INTRUDER, "level": "warning"},
        {"order": "desc", "start": DAY_TWO, "service": "kernel"},
    ]
    cases: list[dict[str, Any]] = []
    for params in event_filters:
        events, pages = all_events(client, **params)
        cases.append(
            {
                "path": "/events",
                "params": params,
                "ids": [event["id"] for event in events],
                "pages": pages,
            }
        )

    questions: list[tuple[str, dict[str, Any]]] = [
        ("/timeline", {"bucket": "1h", "start": DAY_ONE, "end": DAY_THREE}),
        ("/timeline", {"bucket": "1h"}),
        ("/timeline", {"bucket": "1d"}),
        ("/timeline", {"bucket": "1d", "ip": BRUTE}),
        ("/timeline", {"bucket": "5m", "start": "2026-09-09T00:00:00Z", "end": DAY_TWO}),
        ("/timeline", {"bucket": "1m", **burst}),
        ("/timeline", {"bucket": "1m", **burst, "alert_id": brute["id"]}),
        ("/timeline", {"bucket": "5m", "ip": SLOW}),
        ("/timeline", {"bucket": "1h", "rule_id": "SSH-001"}),
        ("/timeline", {"bucket": "1h", "level": "warning", "service": "kernel"}),
        ("/timeline", {"bucket": "1m", "ip": "192.0.2.250"}),
        ("/ports", {"ip": SCANNER}),
        ("/ports", {"ip": SCANNER, **morning}),
        ("/ports", {"ip": BRUTE}),
        ("/ports", {"ip": BRUTE, "start": DAY_TWO}),
        ("/ports", {"ip": BRUTE, "end": DAY_TWO}),
        ("/ports", {"ip": RDP_VISITOR}),
        ("/ports", {"ip": generate_ufw.SLOW_SCAN_IP}),
        ("/ports", {"ip": "192.0.2.250"}),
        ("/stats", {}),
        ("/stats", {"start": DAY_TWO}),
        ("/stats", {"end": DAY_TWO}),
        ("/stats", burst),
        ("/stats", {"start": "2027-01-01T00:00:00Z"}),
        ("/alerts", {"limit": 500}),
        ("/alerts", {"limit": 3}),
        ("/alerts", {"rule_id": "SSH-001"}),
        ("/alerts", {"severity": "critical"}),
        ("/alerts", {"group_key": BRUTE}),
        ("/alerts", {"start": DAY_TWO}),
        ("/alerts", {"end": DAY_TWO, "severity": "high"}),
        ("/alerts", burst),
        ("/rules", {}),
    ]
    for path, params in questions:
        cases.append({"path": path, "params": params, "response": get(client, path, **params)})
    return cases


def _lines(items: list[Any]) -> str:
    """A JSON array with one compact item per line: small, and diffs stay readable."""
    rows = (json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in items)
    return "[\n" + ",\n".join(rows) + "\n]"


def render_snapshot(snapshot: dict[str, Any]) -> str:
    rules = json.dumps(snapshot["rules"], ensure_ascii=False, separators=(",", ":"))
    return (
        '{\n"rules":'
        + rules
        + ',\n"alerts":'
        + _lines(snapshot["alerts"])
        + ',\n"events":'
        + _lines(snapshot["events"])
        + "\n}\n"
    )


def render_cases(cases: list[dict[str, Any]]) -> str:
    return _lines(cases) + "\n"


def build() -> tuple[str, str]:
    """The text of the two files."""
    with loaded_api() as client:
        return render_snapshot(build_snapshot(client)), render_cases(build_cases(client))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="only say whether the files are current"
    )
    arguments = parser.parse_args()

    snapshot, cases = build()
    if arguments.check:
        stale = [
            path.name
            for path, text in ((SNAPSHOT, snapshot), (CASES, cases))
            if not path.exists() or path.read_text(encoding="utf-8") != text
        ]
        if stale:
            raise SystemExit(f"out of date: {', '.join(stale)} (run samples/build_demo.py)")
        print("demo files are up to date")
        return

    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(snapshot, encoding="utf-8", newline="\n")
    CASES.write_text(cases, encoding="utf-8", newline="\n")
    print(f"wrote {SNAPSHOT.relative_to(DEMO_DIR.parents[2])} ({len(snapshot) // 1024} kB)")
    print(f"wrote {CASES.relative_to(DEMO_DIR.parents[2])} ({len(cases) // 1024} kB)")


if __name__ == "__main__":
    main()
