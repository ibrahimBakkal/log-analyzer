"""The notification hub, the event stream built on it, and who publishes to it."""

import asyncio
import json
import signal
import threading
import time

import pytest

import generate  # samples/generate.py
from app.live import Hub, Message, on_exit_signal
from app.routers.live import server_sent_events

YEAR = generate.DEFAULT_START.year


async def take(mailbox, count: int) -> list:
    return [await asyncio.wait_for(mailbox.get(), 2) for _ in range(count)]


# --- the hub ---------------------------------------------------------------------------------


def test_message_published_from_another_thread_reaches_every_listener():
    hub = Hub()

    async def scenario():
        with hub.listen() as first, hub.listen() as second:
            assert hub.listeners == 2
            threading.Thread(target=hub.publish, args=("update", {"added": 3})).start()
            return await take(first, 1), await take(second, 1)

    first, second = asyncio.run(scenario())
    assert first == second == [Message("update", {"added": 3})]
    assert hub.listeners == 0


def test_messages_arrive_in_the_order_they_were_published():
    hub = Hub()

    async def scenario():
        with hub.listen() as mailbox:
            for number in range(5):
                hub.publish("update", {"added": number})
            return await take(mailbox, 5)

    assert [message.data["added"] for message in asyncio.run(scenario())] == [0, 1, 2, 3, 4]


def test_publishing_without_listeners_is_fine():
    Hub().publish("update", {"added": 1})


def test_closing_ends_every_wait_and_turns_later_listeners_away():
    hub = Hub()

    async def scenario():
        with hub.listen() as mailbox:
            hub.publish("update", {"added": 1})
            hub.close()
            waiting = await take(mailbox, 2)
        with hub.listen() as late:
            hub.publish("update", {"added": 2})
            return waiting, await take(late, 1)

    # What was published before the close still arrives; nothing arrives after it.
    assert asyncio.run(scenario()) == ([Message("update", {"added": 1}), None], [None])


def test_listener_that_falls_behind_loses_updates_but_still_hears_the_close():
    hub = Hub()

    async def scenario():
        with hub.listen() as mailbox:
            for number in range(100):
                hub.publish("update", {"added": number})
            await asyncio.sleep(0)  # let the deliveries run
            kept = mailbox.qsize()
            hub.close()
            await asyncio.sleep(0)
            return kept, await take(mailbox, kept)

    kept, received = asyncio.run(scenario())
    assert 0 < kept < 100
    assert received[-1] is None and all(received[:-1])


def test_listener_whose_loop_is_gone_is_forgotten():
    hub = Hub()

    never_left = hub.listen()  # as after a crash: the block is entered and never left

    async def abandon():
        never_left.__enter__()

    asyncio.run(abandon())
    assert hub.listeners == 1
    hub.publish("update", {})
    assert hub.listeners == 0


# --- the stream ------------------------------------------------------------------------------


def parse(chunks: list[str]) -> list[tuple[str, dict]]:
    """(event name, data) of every event in a piece of an event stream."""
    events = []
    for block in "".join(chunks).split("\n\n"):
        fields = dict(
            line.split(": ", 1) for line in block.splitlines() if not line.startswith(":")
        )
        if "event" in fields:
            events.append((fields["event"], json.loads(fields["data"])))
    return events


def test_stream_starts_with_the_status_then_passes_on_what_is_published():
    hub = Hub()

    async def scenario():
        stream = server_sent_events(hub, None)
        chunks = [await anext(stream), await anext(stream)]
        hub.publish("update", {"reason": "ingest", "added": 2, "alerts": 1})
        chunks.append(await anext(stream))
        hub.close()
        chunks += [chunk async for chunk in stream]
        return chunks

    chunks = asyncio.run(scenario())
    assert chunks[0] == "retry: 2000\n\n"
    assert parse(chunks) == [
        ("status", {"following": []}),
        ("update", {"reason": "ingest", "added": 2, "alerts": 1}),
    ]
    assert hub.listeners == 0


def test_stream_sends_a_comment_while_nothing_happens():
    hub = Hub()

    async def scenario():
        stream = server_sent_events(hub, None, keep_alive=0.01)
        chunks = [await anext(stream) for _ in range(4)]
        await stream.aclose()
        return chunks

    chunks = asyncio.run(scenario())
    assert chunks[2:] == [": keep-alive\n\n", ": keep-alive\n\n"]
    assert hub.listeners == 0


def test_stream_endpoint_speaks_server_sent_events(client):
    hub = client.app.state.hub

    def publish_once_someone_listens():
        deadline = time.monotonic() + 5
        while hub.listeners == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        hub.publish("update", {"reason": "rules", "added": 0, "alerts": 4})
        hub.close()  # ends the response, which a test client reads to its end

    threading.Thread(target=publish_once_someone_listens).start()
    response = client.get("/stream")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache"
    assert parse([response.text]) == [
        ("status", {"following": []}),
        ("update", {"reason": "rules", "added": 0, "alerts": 4}),
    ]


def test_nothing_is_followed_unless_configured(client):
    assert client.get("/follow").json() == {"following": []}


# --- who publishes ---------------------------------------------------------------------------


@pytest.fixture
def published(client, monkeypatch) -> list[tuple[str, dict]]:
    seen: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        client.app.state.hub, "publish", lambda event, data: seen.append((event, data))
    )
    return seen


def upload(client, lines: list[str]):
    files = {"file": ("auth.log", "\n".join(lines).encode())}
    return client.post("/ingest", files=files, data={"year": str(YEAR)}).json()


def test_upload_that_adds_events_is_announced(client, published):
    report = upload(client, generate.build_lines())
    assert published == [
        (
            "update",
            {"reason": "ingest", "added": report["parsed"] + report["unparsed"], "alerts": 6},
        )
    ]


def test_upload_that_adds_nothing_is_not_announced(client, published):
    upload(client, generate.build_lines())
    published.clear()
    upload(client, generate.build_lines())
    assert published == []


def test_rule_reload_is_announced(client, published):
    upload(client, generate.build_lines())
    published.clear()
    client.post("/rules/reload")
    assert published == [("update", {"reason": "rules", "added": 0, "alerts": 6})]


# --- stopping --------------------------------------------------------------------------------


def test_exit_signal_runs_the_callback_and_then_the_handler_that_was_there():
    calls: list[str] = []
    original = signal.signal(signal.SIGINT, lambda number, frame: calls.append("server"))
    try:
        restore = on_exit_signal(lambda: calls.append("hub"))
        signal.raise_signal(signal.SIGINT)
        assert calls == ["hub", "server"]

        restore()
        signal.raise_signal(signal.SIGINT)
        assert calls == ["hub", "server", "server"]
    finally:
        signal.signal(signal.SIGINT, original)


def test_exit_signal_leaves_alone_what_nobody_was_handling():
    original = signal.signal(signal.SIGTERM, signal.SIG_DFL)
    try:
        restore = on_exit_signal(lambda: None)
        assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
        restore()
    finally:
        signal.signal(signal.SIGTERM, original)


def test_exit_signal_does_not_undo_a_handler_installed_after_it():
    original = signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGINT, lambda number, frame: None)
        restore = on_exit_signal(lambda: None)
        newer = signal.signal(signal.SIGINT, signal.default_int_handler)
        restore()
        assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
        assert callable(newer)
    finally:
        signal.signal(signal.SIGINT, original)


def test_exit_signal_is_left_alone_outside_the_main_thread():
    before = signal.getsignal(signal.SIGINT)
    outcome = []
    thread = threading.Thread(target=lambda: outcome.append(on_exit_signal(lambda: None)))
    thread.start()
    thread.join()
    assert signal.getsignal(signal.SIGINT) is before
    outcome[0]()  # the undo exists and does nothing
