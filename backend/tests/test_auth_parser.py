"""auth.log patterns: what each one accepts, what it must leave alone."""

from collections import Counter

import pytest

import generate  # samples/generate.py
from app.enums import Action, Level
from app.parsers import UnknownParserError, create_parser, parser_names
from app.parsers.auth import AuthLogParser

HEADER = "Sep  9 03:12:39 web-01 "
KEY = "ED25519 SHA256:2R59DOGY2f7THFWpaVRAF6+d3bZ2RsUPYzLsfDe/Vjk"


def parse(rest: str):
    """Parse a line given without its timestamp and host."""
    return AuthLogParser(year=2026).parse(HEADER + rest)


# (line, user, source address, source port)
ACCEPTED = {
    Action.AUTH_FAIL: [
        (
            "sshd[1734]: Failed password for root from 203.0.113.45 port 52744 ssh2",
            "root",
            "203.0.113.45",
            52744,
        ),
        (
            "sshd[1267]: Failed password for invalid user hadoop "
            "from 198.51.100.23 port 35027 ssh2",
            "hadoop",
            "198.51.100.23",
            35027,
        ),
        (
            f"sshd[77]: Failed publickey for deploy from 2001:db8::7 port 51022 ssh2: {KEY}",
            "deploy",
            "2001:db8::7",
            51022,
        ),
        (
            "sshd-session[9001]: Failed keyboard-interactive/pam for invalid user  "
            "from 192.0.2.99 port 4022 ssh2",
            None,  # the client sent an empty user name
            "192.0.2.99",
            4022,
        ),
    ],
    Action.AUTH_OK: [
        (
            "sshd[2412]: Accepted password for bob from 192.0.2.11 port 59291 ssh2",
            "bob",
            "192.0.2.11",
            59291,
        ),
        (
            f"sshd[2380]: Accepted publickey for alice from 192.0.2.10 port 37340 ssh2: {KEY}",
            "alice",
            "192.0.2.10",
            37340,
        ),
        (
            "sshd-session[31]: Accepted keyboard-interactive/pam for carol "
            "from 2001:db8::10 port 60000 ssh2",
            "carol",
            "2001:db8::10",
            60000,
        ),
    ],
    Action.INVALID_USER: [
        (
            "sshd[1267]: Invalid user hadoop from 198.51.100.23 port 35027",
            "hadoop",
            "198.51.100.23",
            35027,
        ),
        ("sshd[5]: Invalid user admin from 203.0.113.7", "admin", "203.0.113.7", None),
        ("sshd[6]: Invalid user  from 203.0.113.8 port 1234", None, "203.0.113.8", 1234),
        (
            "sshd[7]: Invalid user test user from 2001:db8::9 port 2222",
            "test user",
            "2001:db8::9",
            2222,
        ),
    ],
    Action.DISCONNECT: [
        (
            "sshd[2382]: Received disconnect from 192.0.2.10 port 37340:11: disconnected by user",
            None,
            "192.0.2.10",
            37340,
        ),
        (
            "sshd[2382]: Disconnected from user alice 192.0.2.10 port 37340",
            "alice",
            "192.0.2.10",
            37340,
        ),
        (
            "sshd[1704]: Disconnected from authenticating user root 203.0.113.45 port 59347 "
            "[preauth]",
            "root",
            "203.0.113.45",
            59347,
        ),
        (
            "sshd[1267]: Connection closed by invalid user hadoop 198.51.100.23 port 35027 "
            "[preauth]",
            "hadoop",
            "198.51.100.23",
            35027,
        ),
        (
            "sshd[9]: Connection closed by 203.0.113.9 port 40000 [preauth]",
            None,
            "203.0.113.9",
            40000,
        ),
        (
            "sshd[9]: Connection reset by 203.0.113.9 port 40001 [preauth]",
            None,
            "203.0.113.9",
            40001,
        ),
    ],
    Action.SUDO_EXEC: [
        (
            "sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
            "COMMAND=/usr/bin/apt update",
            "alice",
            None,
            None,
        ),
        (
            "sudo:     root : TTY=unknown ; PWD=/ ; USER=www-data ; "
            "COMMAND=/usr/bin/php /var/www/cron.php",
            "root",
            None,
            None,
        ),
        (
            "sudo: deploy : TTY=pts/2 ; PWD=/tmp ; USER=root ; ENV=DEBIAN_FRONTEND=noninteractive "
            "; COMMAND=/usr/bin/apt-get -y upgrade",
            "deploy",
            None,
            None,
        ),
    ],
    Action.SUDO_DENIED: [
        (
            "sudo:      bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; "
            "COMMAND=/usr/bin/cat /etc/shadow",
            "bob",
            None,
            None,
        ),
        (
            "sudo:    alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; "
            "USER=root ; COMMAND=/usr/bin/apt update",
            "alice",
            None,
            None,
        ),
        (
            "sudo:      bob : command not allowed ; TTY=pts/1 ; PWD=/ ; USER=root ; "
            "COMMAND=/usr/bin/vim /etc/passwd",
            "bob",
            None,
            None,
        ),
    ],
}

# Lines that resemble a pattern but must stay unparsed.
REJECTED = {
    Action.AUTH_FAIL: [
        "sshd[1]: Failed password for root",
        "sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
        "ruser= rhost=203.0.113.45  user=root",
        "sshd[1]: error: maximum authentication attempts exceeded for root "
        "from 203.0.113.45 port 52744 ssh2 [preauth]",
        "su[1]: Failed password for root from 203.0.113.45 port 52744 ssh2",
    ],
    Action.AUTH_OK: [
        "sshd[1]: Accepted password for bob",
        "sshd[1]: pam_unix(sshd:session): session opened for user bob(uid=1001) by (uid=0)",
        "sudo: Accepted password for bob from 192.0.2.11 port 59291 ssh2",
    ],
    Action.INVALID_USER: [
        "sshd[1]: Invalid user admin",
        "sshd[1]: pam_unix(sshd:auth): check pass; user unknown",
        "sshd[1]: input_userauth_request: invalid user admin [preauth]",
    ],
    Action.DISCONNECT: [
        "sshd[1]: Connection closed by 203.0.113.9",
        "sshd[1]: pam_unix(sshd:session): session closed for user alice",
        "systemd-logind[612]: Session 23 logged out. Waiting for processes to exit.",
        # Client-supplied text on both sides of the address: not safe to take apart.
        "sshd[11]: Disconnecting authenticating user root 203.0.113.45 port 52744: "
        "Too many authentication failures [preauth]",
    ],
    Action.SUDO_EXEC: [
        "sudo: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)",
        "sudo: pam_unix(sudo:session): session closed for user root",
        "sshd[1]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
    ],
    Action.SUDO_DENIED: [
        "sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 "
        "tty=/dev/pts/0 ruser=alice rhost=  user=alice",
    ],
}

ACCEPTED_CASES = [(action, *case) for action, cases in ACCEPTED.items() for case in cases]
REJECTED_CASES = [(action, line) for action, lines in REJECTED.items() for line in lines]


def test_every_pattern_has_at_least_three_positive_and_one_negative_example():
    for action in Action:
        assert len(ACCEPTED[action]) >= 3, action
        assert len(REJECTED[action]) >= 1, action


@pytest.mark.parametrize(("action", "line", "user", "src_ip", "src_port"), ACCEPTED_CASES)
def test_pattern_accepts(action, line, user, src_ip, src_port):
    entry = parse(line)
    assert entry.parsed
    assert (entry.action, entry.user, entry.src_ip, entry.src_port) == (
        action,
        user,
        src_ip,
        src_port,
    )


@pytest.mark.parametrize(("action", "line"), REJECTED_CASES)
def test_pattern_rejects(action, line):
    entry = parse(line)
    assert entry is not None, "the header is fine, so the line must still be kept"
    assert entry.action is None
    assert not entry.parsed


@pytest.mark.parametrize(
    ("action", "level"),
    [
        (Action.AUTH_FAIL, Level.WARNING),
        (Action.INVALID_USER, Level.WARNING),
        (Action.SUDO_DENIED, Level.WARNING),
        (Action.AUTH_OK, Level.INFO),
        (Action.DISCONNECT, Level.INFO),
        (Action.SUDO_EXEC, Level.INFO),
    ],
)
def test_level_follows_the_action(action, level):
    assert parse(ACCEPTED[action][0][0]).level == level


def test_unparsed_lines_are_informational():
    assert parse(REJECTED[Action.AUTH_FAIL][1]).level == Level.INFO


@pytest.mark.parametrize(
    ("line", "user"),
    [
        (
            "sshd[1]: Failed password for invalid user x from 192.0.2.1 port 22 "
            "from 203.0.113.5 port 4242 ssh2",
            "x from 192.0.2.1 port 22",
        ),
        (
            "sshd[1]: Failed password for invalid user x from 192.0.2.1 port 22 ssh2: y "
            "from 203.0.113.5 port 4242 ssh2",
            "x from 192.0.2.1 port 22 ssh2: y",
        ),
        (
            "sshd[1]: Accepted password for x from 192.0.2.1 port 22 ssh2: y "
            "from 203.0.113.5 port 4242 ssh2",
            "x from 192.0.2.1 port 22 ssh2: y",
        ),
        (
            "sshd[1]: Invalid user x from 192.0.2.1 port 22 from 203.0.113.5 port 4242",
            "x from 192.0.2.1 port 22",
        ),
        (
            "sshd[1]: Connection closed by invalid user x 192.0.2.1 port 22 "
            "203.0.113.5 port 4242 [preauth]",
            "x 192.0.2.1 port 22",
        ),
    ],
)
def test_user_name_cannot_forge_the_source_address(line, user):
    """The client picks the user name; the address at the end is written by sshd."""
    entry = parse(line)
    assert (entry.user, entry.src_ip, entry.src_port) == (user, "203.0.113.5", 4242)


# --- the whole sample ------------------------------------------------------------------------


def test_sample_log_is_read_completely_and_matches_what_the_generator_wrote():
    parser = AuthLogParser(year=generate.DEFAULT_START.year)
    entries = [parser.parse(line) for line in generate.build_lines()]

    assert None not in entries
    expected = [timestamp for timestamp, _ in generate.build_entries()]
    assert [entry.ts.replace(tzinfo=None) for entry in entries] == expected
    assert {entry.host for entry in entries} == {generate.HOST}


def test_sample_log_actions_match_a_plain_text_count():
    lines = generate.build_lines()
    parser = AuthLogParser(year=generate.DEFAULT_START.year)
    actions = Counter(parser.parse(line).action for line in lines)

    def count(*needles: str) -> int:
        return sum(any(needle in line for needle in needles) for line in lines)

    denied = count("NOT in sudoers")
    assert actions == {
        Action.AUTH_FAIL: count("]: Failed password for "),
        Action.AUTH_OK: count("]: Accepted "),
        Action.INVALID_USER: count("]: Invalid user "),
        Action.DISCONNECT: count(
            "]: Received disconnect from ", "]: Disconnected from ", "]: Connection closed by "
        ),
        Action.SUDO_EXEC: count(" ; COMMAND=") - denied,
        Action.SUDO_DENIED: denied,
        None: len(lines)
        - count(
            "]: Failed password for ",
            "]: Accepted ",
            "]: Invalid user ",
            "]: Received disconnect from ",
            "]: Disconnected from ",
            "]: Connection closed by ",
            " ; COMMAND=",
        ),
    }
    assert actions[Action.AUTH_FAIL] > 200 and actions[None] > 300  # not vacuous


# --- registry --------------------------------------------------------------------------------


def test_auth_parser_is_registered_and_created_with_its_options():
    assert "auth" in parser_names()
    parser = create_parser("auth", year=2024, tz="Europe/Istanbul")
    assert isinstance(parser, AuthLogParser)
    entry = parser.parse("Sep  9 03:12:39 web-01 sshd[1]: hello")
    assert (entry.ts.year, entry.ts.hour) == (2024, 0)


def test_unknown_parser_name_is_reported_with_the_available_ones():
    with pytest.raises(UnknownParserError, match="available: .*auth"):
        create_parser("nginx")
