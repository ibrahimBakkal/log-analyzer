"""Checks on the sample data in ``samples/``.

Later stages use ``samples/auth.log`` as the fixture for parser and rule tests, so
these tests pin down what those stages rely on: the file is reproducible, contains
no real addresses, and still tells the stories described in ``generate.py``.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import generate  # samples/generate.py, importable through `pythonpath` in pyproject.toml

SAMPLE = Path(generate.__file__).with_name("auth.log")
SYSLOG_LINE = re.compile(r"[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d web-01 [\w-]+(\[\d+\])?: +\S")
FAILED_PASSWORD = re.compile(r"Failed password for (?:invalid user )?\S+ from (\S+) port")

# The stories must not depend on one lucky seed.
SEEDS = [generate.DEFAULT_SEED, 1, 2, 3]


def failures_by_ip(seed: int) -> dict[str, list[datetime]]:
    failures = defaultdict(list)
    for timestamp, text in generate.build_entries(seed):
        if match := FAILED_PASSWORD.search(text):
            failures[match[1]].append(timestamp)
    return failures


def busiest_minute(timestamps: list[datetime]) -> int:
    """The largest number of (sorted) *timestamps* that fall within any 60 seconds."""
    best = left = 0
    for right, timestamp in enumerate(timestamps):
        while timestamp - timestamps[left] > timedelta(seconds=60):
            left += 1
        best = max(best, right - left + 1)
    return best


def test_committed_sample_is_what_the_generator_produces():
    assert SAMPLE.read_text(encoding="utf-8").splitlines() == generate.build_lines()


def test_default_sample_has_about_a_thousand_lines():
    assert 900 <= len(generate.build_lines()) <= 1100


def test_output_depends_only_on_the_seed():
    assert generate.build_lines(seed=7) == generate.build_lines(seed=7)
    assert generate.build_lines(seed=7) != generate.build_lines(seed=8)


@pytest.mark.parametrize("seed", SEEDS)
def test_log_is_chronological_and_in_syslog_format(seed):
    timestamps = [timestamp for timestamp, _ in generate.build_entries(seed)]
    assert timestamps == sorted(timestamps)
    assert all(SYSLOG_LINE.match(line) for line in generate.build_lines(seed))


@pytest.mark.parametrize("seed", SEEDS)
def test_log_contains_only_documentation_addresses(seed):
    assert generate.leaked_ips(generate.build_lines(seed)) == set()


def test_leaked_ips_reports_addresses_outside_the_documentation_ranges():
    line = "Failed password for root from 10.0.0.5 port 4242 ssh2"
    assert generate.leaked_ips([line]) == {"10.0.0.5"}


@pytest.mark.parametrize("seed", SEEDS)
def test_only_the_three_fast_attackers_burst(seed):
    fast = {generate.SCANNER_IP, generate.BRUTE_IP, generate.INTRUDER_IP}
    peaks = {ip: busiest_minute(times) for ip, times in failures_by_ip(seed).items()}
    assert {ip for ip, peak in peaks.items() if peak >= 10} == fast
    # Everyone else -- background noise, bob's typo, the slow attacker -- stays far below.
    assert all(peak <= 2 for ip, peak in peaks.items() if ip not in fast)


@pytest.mark.parametrize("seed", SEEDS)
def test_slow_attacker_keeps_guessing_without_ever_bursting(seed):
    times = failures_by_ip(seed)[generate.SLOW_IP]
    assert len(times) >= 20
    assert busiest_minute(times) == 1


@pytest.mark.parametrize("seed", SEEDS)
def test_only_the_intruder_logs_in_from_an_unknown_address(seed):
    logins = [entry for entry in generate.build_entries(seed) if "]: Accepted " in entry[1]]
    foreign = [(when, text) for when, text in logins if " from 192.0.2." not in text]
    assert len(logins) > len(foreign) == 1
    when, text = foreign[0]
    assert f"Accepted password for bob from {generate.INTRUDER_IP} " in text
    assert when > max(failures_by_ip(seed)[generate.INTRUDER_IP])
