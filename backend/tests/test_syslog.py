"""The syslog header and its year-less, zone-less timestamp."""

from datetime import UTC, datetime
from zoneinfo import ZoneInfoNotFoundError

import pytest

from app.parsers.syslog import SyslogClock, SyslogParser

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=UTC)


def utc(*parts: int) -> datetime:
    return datetime(*parts, tzinfo=UTC)


# --- SyslogClock: year ---------------------------------------------------------------------


def test_year_parameter_sets_the_year_of_the_first_line():
    assert SyslogClock(year=2024).resolve(9, 9, 3, 12, 39) == utc(2024, 9, 9, 3, 12, 39)


def test_missing_year_is_the_current_one_when_the_date_has_already_passed():
    assert SyslogClock(now=NOW).resolve(9, 9, 3, 12, 39) == utc(2026, 9, 9, 3, 12, 39)


def test_missing_year_falls_back_a_year_rather_than_dating_a_line_in_the_future():
    assert SyslogClock(now=NOW).resolve(12, 31, 23, 59, 58) == utc(2025, 12, 31, 23, 59, 58)


def test_missing_year_for_29_february_is_the_last_leap_year():
    assert SyslogClock(now=NOW).resolve(2, 29, 8, 0, 0) == utc(2024, 2, 29, 8, 0, 0)


def test_year_advances_when_december_turns_into_january():
    clock = SyslogClock(year=2026)
    assert clock.resolve(12, 31, 23, 59, 58) == utc(2026, 12, 31, 23, 59, 58)
    assert clock.resolve(1, 1, 0, 0, 3) == utc(2027, 1, 1, 0, 0, 3)
    assert clock.resolve(1, 2, 10, 0, 0) == utc(2027, 1, 2, 10, 0, 0)


def test_late_december_line_after_new_year_keeps_the_old_year():
    clock = SyslogClock(year=2026)
    clock.resolve(12, 31, 23, 59, 58)
    assert clock.resolve(1, 1, 0, 0, 0) == utc(2027, 1, 1, 0, 0, 0)
    assert clock.resolve(12, 31, 23, 59, 59) == utc(2026, 12, 31, 23, 59, 59)  # out of order
    assert clock.resolve(1, 1, 0, 0, 1) == utc(2027, 1, 1, 0, 0, 1)


def test_out_of_order_lines_at_a_month_boundary_do_not_change_the_year():
    clock = SyslogClock(year=2026)
    assert clock.resolve(10, 1, 0, 0, 1) == utc(2026, 10, 1, 0, 0, 1)
    assert clock.resolve(9, 30, 23, 59, 59) == utc(2026, 9, 30, 23, 59, 59)
    assert clock.resolve(10, 1, 0, 0, 2) == utc(2026, 10, 1, 0, 0, 2)


def test_impossible_date_is_an_error_and_leaves_the_clock_untouched():
    clock = SyslogClock(year=2026)
    clock.resolve(12, 30, 12, 0, 0)
    with pytest.raises(ValueError):
        clock.resolve(2, 30, 12, 0, 0)
    assert clock.resolve(12, 31, 12, 0, 0) == utc(2026, 12, 31, 12, 0, 0)


# --- SyslogClock: time zone ----------------------------------------------------------------


def test_local_time_is_converted_to_utc():
    istanbul = SyslogClock(year=2026, tz="Europe/Istanbul")  # UTC+3 all year
    assert istanbul.resolve(9, 9, 3, 12, 39) == utc(2026, 9, 9, 0, 12, 39)


def test_conversion_can_cross_midnight_and_new_year():
    istanbul = SyslogClock(year=2027, tz="Europe/Istanbul")
    assert istanbul.resolve(1, 1, 1, 30, 0) == utc(2026, 12, 31, 22, 30, 0)


@pytest.mark.parametrize(
    ("month", "expected_hour"),
    [(1, 11), (7, 10)],  # Berlin is UTC+1 in winter and UTC+2 in summer
)
def test_daylight_saving_time_is_respected(month, expected_hour):
    berlin = SyslogClock(year=2026, tz="Europe/Berlin")
    assert berlin.resolve(month, 15, 12, 0, 0) == utc(2026, month, 15, expected_hour, 0, 0)


def test_unknown_time_zone_is_rejected():
    with pytest.raises(ZoneInfoNotFoundError):
        SyslogClock(tz="Mars/Olympus_Mons")


# --- SyslogParser: header ------------------------------------------------------------------


def parse(line: str, **options):
    return SyslogParser(year=2026, **options).parse(line)


@pytest.mark.parametrize(
    ("line", "ts", "service", "message"),
    [
        (
            "Sep  9 03:12:39 web-01 sshd[1734]: Failed password for root",
            utc(2026, 9, 9, 3, 12, 39),
            "sshd",
            "Failed password for root",
        ),
        (
            "Sep 10 02:34:08 web-01 sudo:      bob : user NOT in sudoers",
            utc(2026, 9, 10, 2, 34, 8),
            "sudo",
            "bob : user NOT in sudoers",
        ),
        (
            "Sep 09 00:17:01 web-01 CRON[1218]: pam_unix(cron:session): session closed",
            utc(2026, 9, 9, 0, 17, 1),
            "CRON",
            "pam_unix(cron:session): session closed",
        ),
        (
            "Sep  9 09:40:07 web-01 systemd-logind[612]: New session 23 of user alice.",
            utc(2026, 9, 9, 9, 40, 7),
            "systemd-logind",
            "New session 23 of user alice.",
        ),
    ],
)
def test_header_is_split_into_time_host_program_and_message(line, ts, service, message):
    entry = parse(line)
    assert (entry.ts, entry.host, entry.service, entry.message) == (ts, "web-01", service, message)


def test_plain_syslog_parser_recognizes_no_message():
    entry = parse("Sep  9 03:12:39 web-01 sshd[1734]: Failed password for root from 203.0.113.45")
    assert entry.action is None
    assert not entry.parsed


def test_iso_timestamp_carries_its_own_year_and_offset():
    entry = parse("2025-03-01T06:12:39.123456+03:00 web-01 sshd[1]: hello", tz="Europe/Berlin")
    assert entry.ts == datetime(2025, 3, 1, 3, 12, 39, 123456, tzinfo=UTC)
    assert (entry.host, entry.service, entry.message) == ("web-01", "sshd", "hello")


def test_iso_timestamp_without_offset_uses_the_parser_time_zone():
    entry = parse("2025-03-01T06:12:39 web-01 sshd[1]: hello", tz="Europe/Istanbul")
    assert entry.ts == utc(2025, 3, 1, 3, 12, 39)


def test_line_with_timestamp_but_no_program_keeps_the_text_as_message():
    entry = parse("Sep  9 03:12:39 web-01 last message repeated 2 times")
    assert (entry.host, entry.service) == ("web-01", None)
    assert entry.message == "last message repeated 2 times"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "    at java.base/java.lang.Thread.run(Thread.java:840)",
        "Failed password for root from 203.0.113.45 port 52744 ssh2",
        "Sep 31 03:12:39 web-01 sshd[1]: no such day",
        "Foo  9 03:12:39 web-01 sshd[1]: no such month",
        "2025-13-45T99:00:00 web-01 sshd[1]: no such date",
    ],
)
def test_line_without_a_readable_timestamp_is_not_parsed(line):
    assert parse(line) is None
