"""Following log files as they grow, the way ``tail -F`` does.

A :class:`Follower` looks at its files once a second from a thread of its own.
New lines are stored, the rules run again, and whoever listens on ``/stream``
is told. Rotation is followed in both of its forms: the file is renamed and a
new one created in its place, or the file is emptied and written again.
"""

import logging
import os
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path
from typing import IO, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ingest import _READ_BYTES, Ingestor, LineReader, NoTimestampsError
from app.live import Hub
from app.models import Alert
from app.parsers import BaseParser, create_parser
from app.rules import RuleSet, evaluate

log = logging.getLogger(__name__)

# How much of a file is read in one go. A large file found at startup is taken
# in in portions, so that the first of it shows up, and a stop is heard, long
# before the last of it has been read.
LINES_PER_LOOK = 20_000


class FollowedFile:
    """One file that is being followed.

    The file is kept open, so that after a rename the lines written to it until
    its writer lets go can still be read. Whether the path still leads to the
    file that is open is checked before every look: by the file's identity on
    disk, by its size, and by its first line (a file removed and created again
    can get the same identity, but hardly the same first line).
    """

    def __init__(self, path: Path, session: Session, parser: BaseParser) -> None:
        self.path = path
        self.state = "waiting"  # "waiting" for the file, "following", or "error"
        self.detail: str | None = None  # why, when not following
        self.read_at: datetime | None = None  # when lines were last read
        self._session = session
        self._parser = parser
        self._handle: IO[bytes] | None = None
        self._identity: tuple[int, int] | None = None  # device and inode of the open file
        self._first_line: bytes | None = None
        self._reader: LineReader | None = None
        self._ingestor: Ingestor | None = None
        self._refused = False  # the file's content is not a log; wait for another one
        self.behind = False  # the last look stopped at its limit: there is more to read

    @property
    def source(self) -> str | None:
        """The name the file's lines are stored under, once the first one has been read."""
        return self._ingestor.result.source_file if self._ingestor and self.lines else None

    @property
    def lines(self) -> int:
        return self._reader.line_no if self._reader else 0

    def poll(self) -> int:
        """Read what is new and return how many events that added."""
        if self._handle is None and not self._open():
            return 0
        # While catching up with a backlog, first get to the end of this file.
        change = None if self.behind else self._changed()
        if change == "rewritten":
            # What was at the old position is gone. Opened again rather than rewound:
            # the open file may still hold a piece of the old content in its buffer.
            self.close()
            return self._read() if self._open() else 0

        added = self._read()
        if change == "rotated" and not added and not self.behind:
            # The path leads to a new file and the old one has gone quiet (its writer
            # may have kept writing to it for a moment after the rename). Take its
            # last line even if that never got a line ending, then move on.
            added += self._read(to_the_end=True)
            self.close()
            if self._open():
                added += self._read()
        return added

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
        self._handle = self._reader = self._ingestor = None
        self.behind = False

    def retry(self) -> None:
        """Forget a failed write to the database, so that the next look repeats it."""
        self._session.rollback()

    def _open(self) -> bool:
        try:
            self._handle = self.path.open("rb")
        except FileNotFoundError:
            self.state, self.detail = "waiting", "the file does not exist yet"
            return False
        except OSError as error:
            self.state, self.detail = "error", error.strerror or str(error)
            return False
        info = os.fstat(self._handle.fileno())
        self._identity = (info.st_dev, info.st_ino)
        self._begin()
        return True

    def _begin(self) -> None:
        """Start on a file's first line: a new file, or the same one written anew."""
        assert self._handle is not None
        self._first_line = None
        self._refused = False
        self._reader = LineReader(self._handle)
        self._ingestor = Ingestor(
            self._session, name=self.path.name, parser=self._parser, resume=True
        )
        self.state, self.detail = "following", None

    def _read(self, *, to_the_end: bool = False) -> int:
        assert self._reader is not None and self._ingestor is not None
        if self._refused:
            return 0
        before = self._ingestor.result.added
        first = self._reader.line_no
        try:
            if to_the_end:
                self._ingestor.feed(self._reader.read())
                self._ingestor.feed(self._reader.finish())
            else:
                self._ingestor.feed(islice(self._reader.read(), LINES_PER_LOOK))
            self._ingestor.flush()
        except NoTimestampsError as error:
            self._refused = True
            self.behind = False
            self.state, self.detail = "error", str(error)
            return 0
        self.behind = not to_the_end and self._reader.line_no - first >= LINES_PER_LOOK
        added = self._ingestor.result.added - before
        if added:
            self.read_at = datetime.now(UTC)
        return added

    def _changed(self) -> str | None:
        """Whether the path now leads to another file ("rotated") or new content ("rewritten")."""
        assert self._handle is not None
        try:
            with self.path.open("rb") as current:
                info = os.fstat(current.fileno())
                first_line = current.readline(_READ_BYTES)
        except OSError:
            # Renamed away and its successor is not there yet, or not readable
            # right now: keep reading the file that is open.
            return None
        if (info.st_dev, info.st_ino) != self._identity:
            return "rotated"
        if info.st_size < self._handle.tell():
            return "rewritten"
        if self._first_line is None:
            if first_line.endswith(b"\n"):
                self._first_line = first_line
        elif first_line != self._first_line:
            return "rewritten"
        return None

    def status(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "state": self.state,
            "detail": self.detail,
            "source": self.source,
            "lines": self.lines,
            "read_at": self.read_at,
        }


class Follower:
    """Follows a set of files from a background thread.

    *rules* is asked for the rules on every run, so that a reload takes effect.
    """

    def __init__(
        self,
        paths: Sequence[Path],
        *,
        session_factory: Callable[[], Session],
        rules: Callable[[], RuleSet],
        hub: Hub,
        tz: str = "UTC",
        interval: float = 1.0,
    ) -> None:
        self._session = session_factory()
        self._files = [
            FollowedFile(path, self._session, create_parser("auto", tz=tz)) for path in paths
        ]
        self._rules = rules
        self._hub = hub
        self._interval = interval
        self._stale = False  # events were stored that the rules have not seen yet
        self._reported: list[tuple[Any, ...]] | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self) -> int:
        """Look at every file once. Returns the number of events added."""
        added = 0
        try:
            for file in self._files:
                try:
                    added += file.poll()
                except Exception:
                    # Most likely the database was busy. Nothing is lost: what was
                    # read is still held and is written on the next look.
                    file.retry()
                    log.exception("could not store new lines of %s; trying again", file.path)
            self._report()  # a file found or lost is news even if the rules then fail
            if added:
                self._stale = True
            if self._stale and not self.behind:
                evaluate(self._session, self._rules().enabled)
                self._stale = False
            if added:
                alerts = self._session.scalar(select(func.count()).select_from(Alert)) or 0
                self._hub.publish("update", {"reason": "follow", "added": added, "alerts": alerts})
        finally:
            self._session.close()  # ends the transaction and forgets what was loaded
            self._report()
        return added

    @property
    def behind(self) -> bool:
        """True while a file still has a backlog; the rules wait until it is read."""
        return any(file.behind for file in self._files)

    def status(self) -> list[dict[str, Any]]:
        # Read without a lock: plain attributes, and a look that takes long must
        # not keep whoever asks waiting.
        return [file.status() for file in self._files]

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="log-follower", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
        for file in self._files:
            file.close()
        self._session.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("following the log files failed; trying again")
            if not self.behind:
                self._stop.wait(self._interval)

    def _report(self) -> None:
        """Tell the listeners when a file's state has changed (found, lost, renamed)."""
        status = self.status()
        summary = [(file["path"], file["state"], file["detail"], file["source"]) for file in status]
        if summary != self._reported:
            self._reported = summary
            self._hub.publish("status", {"following": status})
