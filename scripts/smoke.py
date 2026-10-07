#!/usr/bin/env python3
"""Check that a running installation answers the way one with the sample logs should.

For the Docker setup: after ``docker compose up``, this asks the web server and,
through it, the API for the things a visitor's browser would ask for.

    python scripts/smoke.py                          # http://localhost:8080
    python scripts/smoke.py http://localhost:9000

Needs nothing but Python. Exits with 1 and says what was wrong if anything is.
"""

import json
import re
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
# What the two sample logs amount to; the README describes them.
EVENTS, UNPARSED, ALERTS, AUTH_LINES = 1838, 452, 8, 1057

problems: list[str] = []


def check(what: str, passed: bool, found: object = "") -> None:
    print(
        f"{'ok  ' if passed else 'FAIL'} {what}"
        + (f": {found}" if found != "" and not passed else "")
    )
    if not passed:
        problems.append(what)


def get(url: str) -> tuple[int, dict[str, str], bytes]:
    """Status, headers and body of the answer; status 0 if there was none."""
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()
    except OSError as error:  # nobody listening, or no answer in time
        return 0, {}, str(error).encode()


def get_json(url: str) -> dict:
    """What the API answered, or nothing at all if it did not answer with an object."""
    status, _, body = get(url)
    try:
        answer = json.loads(body)
    except ValueError:
        return {}
    return answer if status == 200 and isinstance(answer, dict) else {}


def upload(url: str, path: Path, fields: dict[str, str]) -> tuple[int, bytes]:
    """POST a file as a browser's form would."""
    boundary = uuid.uuid4().hex
    parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        for name, value in fields.items()
    ]
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        "Content-Type: text/plain\r\n\r\n".encode()
        + path.read_bytes()
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    request = urllib.request.Request(
        url,
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except OSError as error:
        return 0, str(error).encode()


def main(base: str) -> int:
    base = base.rstrip("/")
    api = f"{base}/api"

    # The pages.
    status, headers, body = get(base + "/")
    page = body.decode("utf-8", "replace")
    check("the page is served", status == 200 and '<div id="root">' in page, status)
    check("the page is asked for again each time", "no-cache" in headers.get("Cache-Control", ""))
    status, _, deep = get(base + "/inceleme?ip=203.0.113.45")
    check(
        "an address inside the application is the same page", status == 200 and deep == body, status
    )
    script = re.search(r'src="(/assets/[^"]+\.js)"', page)
    check("the page names its script", script is not None)
    if script:
        status, headers, _ = get(base + script.group(1))
        cached = "immutable" in headers.get("Cache-Control", "")
        check("the script is served and may be kept", status == 200 and cached, headers)

    # The API, through the web server.
    health = get_json(api + "/health")
    check("the API is reachable under /api", health == {"status": "ok"}, health)
    stats = get_json(api + "/stats")
    found = (stats.get("events"), stats.get("unparsed"), stats.get("alerts"))
    check("both sample logs are loaded, once", found == (EVENTS, UNPARSED, ALERTS), found)
    alerts = get_json(api + "/alerts?limit=500")
    by_rule = sorted(alert["rule_id"] for alert in alerts.get("items", []))
    expected = [
        "KW-001",
        "NET-001",
        "NET-002",
        "SSH-001",
        "SSH-001",
        "SSH-001",
        "SSH-001",
        "SSH-002",
    ]
    check("the rules found the eight alerts the samples hold", by_rule == expected, by_rule)
    rules = get_json(api + "/rules")
    count, errors = len(rules.get("rules", [])), rules.get("errors")
    check(
        "the rules folder is mounted, folders inside it included",
        count > 5 and errors == [],
        (count, errors),
    )
    status, _, body = get(api + "/docs")
    check(
        "the API's documentation finds its way",
        status == 200 and b"/api/openapi.json" in body,
        status,
    )

    # What stays open and what is sent up.
    try:
        with urllib.request.urlopen(api + "/stream", timeout=10) as stream:
            first = stream.readline() + stream.readline()
        check("the event stream arrives as it is written", b"retry:" in first, first)
    except OSError as error:
        check("the event stream arrives as it is written", False, error)
    status, body = upload(api + "/ingest", SAMPLES / "auth.log", {"year": "2026"})
    try:
        report = json.loads(body) if status == 200 else {}
    except ValueError:
        report = {}
    again = (report.get("lines"), report.get("duplicates"), report.get("alerts"))
    check(
        "a log can be uploaded; one already loaded adds nothing",
        again == (AUTH_LINES, AUTH_LINES, ALERTS),
        body[:200],
    )

    if problems:
        print(f"\n{len(problems)} problem(s)")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"))
