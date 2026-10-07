"""Syslog lines: the shared header and its year-less timestamp.

A classic syslog line looks like this::

    Sep  9 03:12:39 web-01 sshd[1734]: Failed password for root from 203.0.113.45 port 52744 ssh2
    <timestamp>     <host> <program>   <message>

The timestamp has neither a year nor a time zone, so both must come from
outside: see :class:`SyslogClock`.
"""

import re
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

from app.parsers.base import BaseParser, ParsedLine

MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

_CLASSIC = re.compile(
    r"(?P<month>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) "
    r"(?P<hour>\d\d):(?P<minute>\d\d):(?P<second>\d\d) (?P<rest>.*)"
)
# Newer rsyslog setups write ISO 8601 instead: "2026-09-09T03:12:39.123456+03:00 web-01 ..."
_ISO = re.compile(r"(?P<stamp>\d{4}-\d\d-\d\dT\S+) (?P<rest>.*)")
_PROGRAM = re.compile(r"(?P<service>[^\s:\[]+)(?:\[\d+\])?: ?(?P<message>.*)")


class SyslogClock:
    """Turns the year-less, zone-less timestamps of one log file into UTC.

    *year* is the year of the file's first line. When it is not given, the most
    recent year in which that first line is not in the future is used.

    After the first line the clock follows the file: every timestamp is given
    the year that puts it closest to the line before it. That handles the step
    from December to January, and also lines that are slightly out of order
    around New Year. It assumes that neighbouring lines are less than about six
    months apart.

    *tz* is the time zone the logging machine's clock was set to.
    """

    def __init__(
        self, year: int | None = None, tz: str = "UTC", *, now: datetime | None = None
    ) -> None:
        self.zone = ZoneInfo(tz)
        self._year = year
        self._now = now  # injectable for tests; only used to guess a missing year
        self._last: datetime | None = None  # local time of the previous line

    def resolve(self, month: int, day: int, hour: int, minute: int, second: int) -> datetime:
        """Return the UTC time of a timestamp. Raises ``ValueError`` for impossible dates."""
        if self._last is None:
            year = self._year if self._year is not None else self._guess_year(month, day)
            local = datetime(year, month, day, hour, minute, second)
        else:
            last = self._last
            candidates = []
            for year in (last.year, last.year + 1, last.year - 1):
                try:
                    candidates.append(datetime(year, month, day, hour, minute, second))
                except ValueError:  # 29 February in a year that has none
                    continue
            if not candidates:
                raise ValueError(f"no such date: month {month}, day {day}")
            local = min(candidates, key=lambda candidate: abs(candidate - last))
        self._last = local
        return local.replace(tzinfo=self.zone).astimezone(UTC)

    def _guess_year(self, month: int, day: int) -> int:
        today = (self._now or datetime.now(UTC)).astimezone(self.zone).date()
        for year in range(today.year, today.year - 8, -1):
            try:
                candidate = date(year, month, day)
            except ValueError:
                continue
            # One day of slack for a clock that runs slightly ahead of ours.
            if candidate <= today + timedelta(days=1):
                return year
        raise ValueError(f"no such date: month {month}, day {day}")


class SyslogParser(BaseParser):
    """Reads the syslog header. Subclasses recognize the messages of particular programs."""

    def __init__(
        self, *, year: int | None = None, tz: str = "UTC", now: datetime | None = None
    ) -> None:
        self._clock = SyslogClock(year, tz, now=now)

    def parse(self, line: str) -> ParsedLine | None:
        ts, rest = self._split_timestamp(line)
        if ts is None:
            return None
        host, _, remainder = rest.partition(" ")
        program = _PROGRAM.fullmatch(remainder)
        if program is None:
            # Timestamp and host, but no "program: message" part.
            return ParsedLine(ts=ts, host=host or None, message=remainder)
        entry = ParsedLine(
            ts=ts, host=host, service=program["service"], message=program["message"].strip()
        )
        return self.recognize(entry)

    def recognize(self, entry: ParsedLine) -> ParsedLine:
        """Return *entry* with the fields its message reveals filled in.

        The default recognizes nothing, which leaves the line unparsed.
        """
        return entry

    def _split_timestamp(self, line: str) -> tuple[datetime | None, str]:
        if match := _CLASSIC.fullmatch(line):
            month = MONTHS.get(match["month"])
            if month is None:
                return None, ""
            try:
                ts = self._clock.resolve(
                    month,
                    int(match["day"]),
                    int(match["hour"]),
                    int(match["minute"]),
                    int(match["second"]),
                )
            except ValueError:
                return None, ""
            return ts, match["rest"]
        if match := _ISO.fullmatch(line):
            try:
                stamp = datetime.fromisoformat(match["stamp"])
            except ValueError:
                return None, ""
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=self._clock.zone)
            return stamp.astimezone(UTC), match["rest"]
        return None, ""
