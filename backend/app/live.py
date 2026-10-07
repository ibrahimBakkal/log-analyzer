"""Telling the web interface that the data has changed.

Uploads, rule reloads and the file follower :meth:`~Hub.publish` a short
message; ``GET /stream`` passes it on to every browser that is listening.
"""

import asyncio
import signal
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Message:
    event: str  # "update" or "status"
    data: dict[str, Any]


# What a listener waits on: messages, then None when the hub closes.
Mailbox = asyncio.Queue[Message | None]
_MAILBOX_SIZE = 32


class Hub:
    """Passes messages from any thread to the listeners waiting in the event loop."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._listeners: dict[Mailbox, asyncio.AbstractEventLoop] = {}
        self._closed = False

    @contextmanager
    def listen(self) -> Iterator[Mailbox]:
        """A mailbox that receives every message published while the block runs.

        Must be entered from the event loop the listener waits in.
        """
        mailbox: Mailbox = asyncio.Queue(maxsize=_MAILBOX_SIZE)
        with self._lock:
            if self._closed:
                mailbox.put_nowait(None)
            else:
                self._listeners[mailbox] = asyncio.get_running_loop()
        try:
            yield mailbox
        finally:
            with self._lock:
                self._listeners.pop(mailbox, None)

    def publish(self, event: str, data: dict[str, Any]) -> None:
        """Send a message to everyone listening. Safe to call from any thread."""
        self._send(_deliver, Message(event, data))

    def close(self) -> None:
        """End every listener's wait; later listeners are turned away at once."""
        with self._lock:
            self._closed = True
        self._send(_dismiss)

    @property
    def listeners(self) -> int:
        with self._lock:
            return len(self._listeners)

    def _send(self, action: Callable[..., None], *arguments: Any) -> None:
        with self._lock:
            listeners = list(self._listeners.items())
        for mailbox, loop in listeners:
            try:
                loop.call_soon_threadsafe(action, mailbox, *arguments)
            except RuntimeError:  # that loop has already shut down
                with self._lock:
                    self._listeners.pop(mailbox, None)


def _deliver(mailbox: Mailbox, message: Message) -> None:
    try:
        mailbox.put_nowait(message)
    except asyncio.QueueFull:
        # A listener this far behind refreshes on the messages it still has.
        pass


def _dismiss(mailbox: Mailbox) -> None:
    # What is already waiting is still delivered; only a full mailbox gives one up.
    if mailbox.full():
        mailbox.get_nowait()
    mailbox.put_nowait(None)


def on_exit_signal(callback: Callable[[], None]) -> Callable[[], None]:
    """Call *callback* when the process is asked to stop; returns a function that undoes this.

    A server waits for open responses before it shuts down, and a response that
    streams forever never ends by itself: Ctrl+C would hang until pressed twice.
    So the handlers the server installed for SIGINT and SIGTERM are wrapped; the
    callback runs first, then the server's own handler as before.

    Does nothing where signals cannot be handled (outside the main thread, as
    in tests) or where nobody was handling them.
    """
    if threading.current_thread() is not threading.main_thread():
        return lambda: None

    wrapped: dict[int, tuple[Any, Any]] = {}
    for number in (signal.SIGINT, signal.SIGTERM):
        previous = signal.getsignal(number)
        if not callable(previous):
            continue

        def handler(signum: int, frame: Any, previous: Any = previous) -> None:
            callback()
            previous(signum, frame)

        signal.signal(number, handler)
        wrapped[number] = (handler, previous)

    def restore() -> None:
        for number, (handler, previous) in wrapped.items():
            if signal.getsignal(number) is handler:
                signal.signal(number, previous)

    return restore
