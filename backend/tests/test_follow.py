"""Following files as they grow: appended lines, rotation, restarts."""

import os
import time
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

import generate  # samples/generate.py
from app import follow
from app.follow import Follower
from app.live import Hub
from app.models import Alert, Event, Source
from app.rules import load_rules

RULES = load_rules(Path(__file__).resolve().parents[2] / "rules")
LINES = generate.build_lines()  # timestamps from 9 September on, in the generator's year


class Recorder(Hub):
    """A hub that remembers what was published."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: list[tuple[str, dict]] = []

    def publish(self, event: str, data: dict) -> None:
        self.messages.append((event, data))

    def updates(self) -> list[dict]:
        return [data for event, data in self.messages if event == "update"]


def write(path: Path, lines: list[str], *, end: str = "\n") -> None:
    path.write_text("".join(line + "\n" for line in lines)[:-1] + end if lines else "")


def append(path: Path, *lines: str, end: str = "\n") -> None:
    with path.open("a") as stream:
        stream.write("\n".join(lines) + end)


@pytest.fixture
def log(tmp_path) -> Path:
    return tmp_path / "auth.log"


@pytest.fixture
def hub() -> Recorder:
    return Recorder()


@pytest.fixture
def follower(engine, hub, log, monkeypatch) -> Follower:
    # The sample's timestamps have no year; "now" must not make them look like next year's.
    return make_follower(engine, hub, log)


def make_follower(engine, hub, *paths: Path, interval: float = 0.02) -> Follower:
    return Follower(
        paths,
        session_factory=lambda: Session(engine, expire_on_commit=False),
        rules=lambda: RULES,
        hub=hub,
        interval=interval,
    )


def stored(session, **where) -> int:
    query = select(func.count()).select_from(Event)
    for column, value in where.items():
        query = query.where(getattr(Event, column) == value)
    session.expire_all()
    return session.scalar(query)


def raws(session, source_file: str) -> list[str]:
    session.expire_all()
    return session.scalars(
        select(Event.raw).where(Event.source_file == source_file).order_by(Event.line_no)
    ).all()


def state(follower: Follower) -> tuple:
    [file] = follower.status()
    return file["state"], file["source"], file["lines"]


# --- reading what is appended ----------------------------------------------------------------


def test_file_that_is_not_there_yet_is_waited_for(follower, log, session):
    assert follower.run_once() == 0
    assert state(follower) == ("waiting", None, 0)
    assert follower.status()[0]["detail"] == "the file does not exist yet"

    write(log, LINES[:3])
    assert follower.run_once() == 3
    assert state(follower) == ("following", "auth.log", 3)
    assert follower.status()[0]["detail"] is None
    assert raws(session, "auth.log") == LINES[:3]


def test_appended_lines_are_stored_on_the_next_look(follower, log, session):
    write(log, LINES[:5])
    assert follower.run_once() == 5
    assert follower.run_once() == 0

    append(log, *LINES[5:8])
    assert follower.run_once() == 3
    assert raws(session, "auth.log") == LINES[:8]
    assert session.scalars(select(Event.line_no).order_by(Event.line_no)).all() == list(range(1, 9))


def test_line_is_stored_only_once_it_is_complete(follower, log, session):
    write(log, LINES[:2])
    follower.run_once()

    head, tail = LINES[2][:30], LINES[2][30:]
    append(log, head, end="")
    assert follower.run_once() == 0
    append(log, tail)
    assert follower.run_once() == 1
    assert raws(session, "auth.log") == LINES[:3]


def test_empty_file_is_followed_from_its_first_line(follower, log, session):
    log.touch()
    assert follower.run_once() == 0
    assert state(follower) == ("following", None, 0)
    append(log, LINES[0])
    assert follower.run_once() == 1
    assert state(follower) == ("following", "auth.log", 1)


def test_new_lines_reach_the_rules_and_the_listeners(follower, log, session, hub):
    quiet = [line for line in LINES if "203.0.113.45" not in line][:20]
    burst = [line for line in LINES if "Failed password for root from 203.0.113.45" in line][:6]
    write(log, quiet)
    follower.run_once()
    assert session.scalar(select(func.count()).select_from(Alert)) == 0
    assert hub.updates() == [{"reason": "follow", "added": 20, "alerts": 0}]

    append(log, *burst)
    follower.run_once()
    [alert] = session.scalars(select(Alert)).all()
    assert (alert.rule_id, alert.group_key, alert.count) == ("SSH-001", "203.0.113.45", 6)
    assert hub.updates()[-1] == {"reason": "follow", "added": 6, "alerts": 1}

    follower.run_once()
    assert len(hub.updates()) == 2  # nothing new, nothing said


def test_listeners_hear_when_a_file_is_found(follower, log, hub):
    follower.run_once()
    follower.run_once()
    write(log, LINES[:1])
    follower.run_once()

    reports = [data["following"][0] for event, data in hub.messages if event == "status"]
    assert [file["state"] for file in reports] == ["waiting", "following"]
    assert reports[-1]["source"] == "auth.log"
    # The file is reported as found before its lines are announced.
    assert [event for event, _ in hub.messages] == ["status", "status", "update"]


def test_two_files_are_followed_side_by_side(engine, hub, tmp_path, session):
    first, second = tmp_path / "auth.log", tmp_path / "other.log"
    write(first, LINES[:4])
    write(second, LINES[100:103])
    follower = make_follower(engine, hub, first, second)

    assert follower.run_once() == 7
    assert (stored(session, source_file="auth.log"), stored(session, source_file="other.log")) == (
        4,
        3,
    )
    follower.stop()


# --- rotation --------------------------------------------------------------------------------


def test_renamed_file_is_read_to_its_end_and_its_successor_from_the_start(follower, log, session):
    write(log, LINES[:5])
    follower.run_once()

    # logrotate: rename, and the writer keeps writing to the old file for a moment.
    rotated = log.with_name("auth.log.1")
    log.rename(rotated)
    append(rotated, *LINES[5:7])
    assert follower.run_once() == 2  # still reading the file it has open
    write(log, LINES[7:10])
    append(rotated, LINES[10], end="")  # a last line that never got its line ending
    assert follower.run_once() == 4

    assert raws(session, "auth.log") == [*LINES[:7], LINES[10]]
    assert raws(session, "auth.log (2026-09-09)") == LINES[7:10]
    assert state(follower) == ("following", "auth.log (2026-09-09)", 3)

    append(log, LINES[11])
    assert follower.run_once() == 1
    assert stored(session) == 12


def test_old_file_is_left_only_once_it_has_gone_quiet(follower, log, session):
    write(log, LINES[:5])
    follower.run_once()

    rotated = log.with_name("auth.log.1")
    log.rename(rotated)
    write(log, LINES[10:12])
    append(rotated, *LINES[5:8])  # the writer has not let go of the old file yet

    assert follower.run_once() == 3
    assert state(follower) == ("following", "auth.log", 8)
    append(rotated, LINES[8])
    assert follower.run_once() == 1
    assert follower.run_once() == 2  # quiet now: on to the new file
    assert state(follower) == ("following", "auth.log (2026-09-09)", 2)
    assert raws(session, "auth.log") == LINES[:9]


def test_file_emptied_and_written_again_starts_from_its_first_line(follower, log, session):
    write(log, LINES[:6])
    follower.run_once()

    write(log, LINES[6:8])  # copytruncate: same file, shorter than what was read
    assert follower.run_once() == 2
    assert raws(session, "auth.log (2026-09-09)") == LINES[6:8]
    assert session.scalars(
        select(Event.line_no).where(Event.source_file == "auth.log (2026-09-09)")
    ).all() == [1, 2]


def test_shorter_file_is_new_content_even_before_a_first_line_was_seen(follower, log, session):
    # Only the beginning of a line so far: nothing to store, nothing to know the file by.
    log.write_text(LINES[0][:60])
    assert follower.run_once() == 0
    assert follower.run_once() == 0

    write(log, [LINES[1][:40]])  # emptied and started again, shorter than what was read
    assert follower.run_once() == 1
    assert raws(session, "auth.log") == [LINES[1][:40]]


def test_file_emptied_and_left_empty_is_followed_from_its_start(follower, log, session):
    write(log, LINES[:4])
    follower.run_once()

    log.write_text("")
    assert follower.run_once() == 0
    assert state(follower) == ("following", None, 0)
    append(log, LINES[4])
    assert follower.run_once() == 1
    assert raws(session, "auth.log (2026-09-09)") == [LINES[4]]


def test_file_replaced_by_a_longer_one_is_noticed_by_its_first_line(follower, log, session):
    write(log, LINES[:3])
    follower.run_once()

    replacement = LINES[3:20]
    identity = os.stat(log).st_ino
    write(log, replacement)  # written in place: the same file on disk, new content
    assert os.stat(log).st_ino == identity
    assert follower.run_once() == len(replacement)
    assert raws(session, "auth.log (2026-09-09)") == replacement
    assert stored(session) == 20


def test_rotated_copy_uploaded_later_adds_nothing(follower, log, session, client):
    write(log, LINES[:40])
    follower.run_once()

    files = {"file": ("auth.log.1", "\n".join(LINES[:40]).encode())}
    report = client.post("/ingest", files=files, data={"year": "2026"}).json()
    assert (report["source_file"], report["duplicates"], report["parsed"], report["unparsed"]) == (
        "auth.log",
        40,
        0,
        0,
    )


# --- restarts and trouble --------------------------------------------------------------------


def test_restart_picks_up_where_the_file_was_left(engine, hub, log, session):
    write(log, LINES[:30])
    first = make_follower(engine, hub, log)
    first.run_once()
    first.stop()
    append(log, *LINES[30:34])

    second = make_follower(engine, hub, log)
    assert second.run_once() == 4
    assert state(second) == ("following", "auth.log", 34)
    assert raws(session, "auth.log") == LINES[:34]
    assert session.scalar(select(func.count()).select_from(Source)) == 1
    second.stop()


def test_file_that_is_not_a_log_is_reported_and_given_up_until_it_is_replaced(
    follower, log, session, monkeypatch
):
    monkeypatch.setattr("app.ingest.MAX_UNDATED_LINES", 20)
    write(log, [f"line {number} of something else" for number in range(30)])
    assert follower.run_once() == 0
    assert state(follower)[0] == "error"
    assert "not a log file" in follower.status()[0]["detail"]

    append(log, "more of the same")
    assert follower.run_once() == 0
    assert stored(session) == 0

    write(log, LINES[:2])
    assert follower.run_once() == 2
    assert state(follower) == ("following", "auth.log", 2)


def test_unreadable_file_is_reported(engine, hub, tmp_path):
    folder = tmp_path / "a-folder.log"
    folder.mkdir()
    follower = make_follower(engine, hub, folder)
    follower.run_once()
    [file] = follower.status()
    assert file["state"] == "error" and file["detail"]
    follower.stop()


def test_lines_survive_a_database_that_is_busy(follower, log, session, monkeypatch, caplog):
    write(log, LINES[:5])

    def busy():
        raise OperationalError("COMMIT", {}, Exception("database is locked"))

    with monkeypatch.context() as patched:
        patched.setattr(follower._session, "commit", busy)
        assert follower.run_once() == 0
    assert "trying again" in caplog.text
    assert stored(session) == 0

    append(log, LINES[5])
    assert follower.run_once() == 6
    assert raws(session, "auth.log") == LINES[:6]


def test_large_file_is_taken_in_portions_and_the_rules_wait_for_the_last(
    follower, log, session, hub, monkeypatch
):
    monkeypatch.setattr(follow, "LINES_PER_LOOK", 400)
    write(log, LINES)

    assert follower.run_once() == 400
    assert follower.behind
    assert session.scalar(select(func.count()).select_from(Alert)) == 0  # 71 failures are in

    assert follower.run_once() == 400
    assert follower.run_once() == len(LINES) - 800
    assert not follower.behind
    assert session.scalar(select(func.count()).select_from(Alert)) == 6
    assert [update["added"] for update in hub.updates()] == [400, 400, len(LINES) - 800]
    assert raws(session, "auth.log") == LINES


# --- the thread ------------------------------------------------------------------------------


def wait_for(condition, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


def test_running_follower_stores_an_appended_line_within_moments(follower, log, session):
    write(log, LINES[:3])
    follower.start()
    try:
        assert wait_for(lambda: stored(session) == 3)
        append(log, LINES[3])
        assert wait_for(lambda: stored(session) == 4)
    finally:
        follower.stop()
    assert not follower._thread.is_alive()


def test_follow_status_is_served(client, follower, log):
    write(log, LINES[:2])
    follower.run_once()
    client.app.state.follower = follower
    try:
        [file] = client.get("/follow").json()["following"]
    finally:
        client.app.state.follower = None

    assert (file["path"], file["state"], file["source"], file["lines"]) == (
        str(log),
        "following",
        "auth.log",
        2,
    )
    assert file["detail"] is None and file["read_at"].endswith("Z")
