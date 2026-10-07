"""The whole chain on a real server: a line appended to a followed file reaches /stream.

Everything else is tested piece by piece; this test starts the application the
way it runs in production (uvicorn, a database file, a follower thread) and
watches it from outside, over HTTP.
"""

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx2
import pytest
import uvicorn

import generate  # samples/generate.py
from app.config import get_settings
from app.db import Base, make_engine, session_factory
from app.main import app

LINES = generate.build_lines()
BURST = [line for line in LINES if "Failed password for root from 203.0.113.45" in line][:8]


class Server:
    def __init__(self, url: str, log: Path) -> None:
        self.url = url
        self.log = log
        self.http = httpx2.Client(base_url=url, timeout=10)
        self.left_open: tuple | None = None  # a stream a test wants to outlive it

    def get(self, path: str, **params) -> dict:
        response = self.http.get(path, params=params)
        response.raise_for_status()
        return response.json()

    def append(self, *lines: str) -> None:
        with self.log.open("a") as stream:
            stream.write("".join(line + "\n" for line in lines))

    @contextmanager
    def events(self) -> Iterator[Iterator[tuple[str, dict]]]:
        """The (name, data) events of /stream, as they arrive."""
        with self.http.stream("GET", "/stream") as response:
            assert response.headers["content-type"].startswith("text/event-stream")

            def read() -> Iterator[tuple[str, dict]]:
                name = None
                for line in response.iter_lines():
                    if line.startswith("event: "):
                        name = line.removeprefix("event: ")
                    elif line.startswith("data: ") and name:
                        yield name, json.loads(line.removeprefix("data: "))
                        name = None

            yield read()


@pytest.fixture
def server(tmp_path, monkeypatch) -> Iterator[Server]:
    log = tmp_path / "auth.log"
    database = f"sqlite:///{(tmp_path / 'live.db').as_posix()}"
    monkeypatch.setenv("LOG_ANALYZER_DATABASE_URL", database)
    monkeypatch.setenv("LOG_ANALYZER_FOLLOW", str(log))
    monkeypatch.setenv("LOG_ANALYZER_FOLLOW_INTERVAL", "0.05")
    get_settings.cache_clear()
    session_factory.cache_clear()
    engine = make_engine(database)
    Base.metadata.create_all(engine)
    engine.dispose()

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    running = uvicorn.Server(config)
    thread = threading.Thread(target=running.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not running.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert running.started, "the server did not start"
    port = running.servers[0].sockets[0].getsockname()[1]

    handle = Server(f"http://127.0.0.1:{port}", log)
    try:
        yield handle
    finally:
        # In the order of a real shutdown: the server is told to stop while clients
        # may still be connected. Closing the hub is what the signal handler does.
        app.state.hub.close()
        running.should_exit = True
        thread.join(timeout=10)
        handle.http.close()
        get_settings.cache_clear()
        session_factory.cache_clear()
    assert not thread.is_alive(), "the server did not shut down"


def next_event(events: Iterator[tuple[str, dict]], name: str) -> dict:
    for event, data in events:
        if event == name:
            return data
    raise AssertionError(f"the stream ended without a {name!r} event")


def test_appended_lines_show_up_within_seconds(server):
    with server.events() as events:
        status = next_event(events, "status")
        assert [file["state"] for file in status["following"]] == ["waiting"]

        server.append(*LINES[:5])
        started = time.monotonic()
        update = next_event(events, "update")
        assert update == {"reason": "follow", "added": 5, "alerts": 0}
        assert time.monotonic() - started < 3

        assert server.get("/stats")["events"] == 5
        [file] = server.get("/follow")["following"]
        assert (file["state"], file["source"], file["lines"]) == ("following", "auth.log", 5)

        # A burst of failed logins: the rule fires and the alert is there when the event arrives.
        server.append(*BURST)
        update = next_event(events, "update")
        assert (update["added"], update["alerts"]) == (len(BURST), 1)
        [alert] = server.get("/alerts")["items"]
        assert (alert["rule_id"], alert["group_key"], alert["count"]) == (
            "SSH-001",
            "203.0.113.45",
            len(BURST),
        )
        newest = server.get("/events", ip="203.0.113.45", limit=1)["items"][0]
        assert newest["highlights"][0]["rule_id"] == "SSH-001"


def test_upload_is_announced_to_everyone_listening(server):
    with server.events() as first, server.events() as second:
        next_event(first, "status")
        next_event(second, "status")

        files = {"file": ("ufw.log", generate.DEFAULT_OUTPUT.with_name("ufw.log").read_bytes())}
        report = server.http.post("/ingest", files=files, data={"year": "2026"}).json()

        expected = {"reason": "ingest", "added": report["parsed"], "alerts": 2}
        assert next_event(first, "update") == expected
        assert next_event(second, "update") == expected


def test_open_stream_does_not_keep_the_server_from_stopping(server):
    # Entered and never left: this client is still connected when the fixture
    # stops the server, which then has to end the stream itself.
    stream = server.events()
    events = stream.__enter__()
    server.left_open = (stream, events)  # dropping either would close the connection
    next_event(events, "status")
    server.append(LINES[0])
    assert next_event(events, "update")["added"] == 1
    assert app.state.hub.listeners == 1
