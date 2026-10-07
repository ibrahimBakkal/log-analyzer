"""The interface every log format parser implements."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from app.enums import Action, Level


@dataclass(frozen=True, slots=True, kw_only=True)
class ParsedLine:
    """What a parser could read from one line.

    Only ``ts`` is required. A line whose message matched no known pattern has
    no ``action``; it is still stored, marked as unparsed.
    """

    ts: datetime  # timezone-aware, UTC
    message: str
    host: str | None = None
    service: str | None = None
    level: Level = Level.INFO
    action: Action | None = None
    user: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None

    @property
    def parsed(self) -> bool:
        return self.action is not None


class BaseParser(ABC):
    """Turns raw log lines into :class:`ParsedLine` objects.

    A parser is created once per file and fed its lines in order, so it may keep
    state between lines; the syslog parser tracks the current year that way.
    """

    name: ClassVar[str]  # the key under which the parser is registered

    @abstractmethod
    def parse(self, line: str) -> ParsedLine | None:
        """Parse one line (without its line ending).

        Return ``None`` if the line carries no readable timestamp. The caller
        then treats it as a continuation of the line before it.
        """
