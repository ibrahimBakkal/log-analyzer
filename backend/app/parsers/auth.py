"""``auth.log``: what sshd and sudo report about logins and privileged commands.

User names are chosen by whoever connects, so they are untrusted text. Every
sshd pattern therefore lets the user name match greedily and takes the address
from the *end* of the message, which sshd itself writes. A "user name" such as
``x from 192.0.2.1 port 22`` cannot pass itself off as the source address.

That only works for messages in which nothing client-supplied follows the
address. "Disconnecting ... user NAME ADDR port N: REASON" has client text on
both sides of the address, so it is deliberately left unparsed.
"""

import re
from dataclasses import dataclass, replace

from app.enums import Action, Level
from app.parsers.base import ParsedLine
from app.parsers.registry import register
from app.parsers.syslog import SyslogParser


@dataclass(frozen=True)
class Pattern:
    action: Action
    level: Level
    regex: re.Pattern[str]  # must match the whole message; named groups become fields


_PEER = r"(?P<src_ip>\S+) port (?P<src_port>\d{1,5})"
_ROLE = r"(?:(?:authenticating |invalid )?user (?P<user>.*) )?"  # "user alice ", "invalid user x "

SSHD_PATTERNS = (
    Pattern(
        Action.AUTH_OK,
        Level.INFO,
        # Accepted publickey for alice from 192.0.2.10 port 37340 ssh2: ED25519 SHA256:...
        re.compile(rf"Accepted \S+ for (?P<user>.*) from {_PEER}(?: ssh2)?(?:: .*)?"),
    ),
    Pattern(
        Action.AUTH_FAIL,
        Level.WARNING,
        # Failed password for invalid user admin from 203.0.113.7 port 40022 ssh2
        re.compile(
            rf"Failed \S+ for (?:invalid user )?(?P<user>.*) from {_PEER}(?: ssh2)?(?:: .*)?"
        ),
    ),
    Pattern(
        Action.INVALID_USER,
        Level.WARNING,
        # Invalid user admin from 203.0.113.7 port 40022      (older sshd omits the port)
        re.compile(
            r"Invalid user (?P<user>.*) from (?P<src_ip>\S+)(?: port (?P<src_port>\d{1,5}))?"
        ),
    ),
    Pattern(
        Action.DISCONNECT,
        Level.INFO,
        # Received disconnect from 192.0.2.10 port 37340:11: disconnected by user
        re.compile(rf"Received disconnect from {_PEER}:\d+: .*"),
    ),
    Pattern(
        Action.DISCONNECT,
        Level.INFO,
        # Disconnected from authenticating user root 203.0.113.45 port 59347 [preauth]
        re.compile(rf"Disconnected from {_ROLE}{_PEER}(?: \[preauth\])?"),
    ),
    Pattern(
        Action.DISCONNECT,
        Level.INFO,
        # Connection closed by invalid user hadoop 198.51.100.23 port 35027 [preauth]
        re.compile(rf"Connection (?:closed|reset) by {_ROLE}{_PEER}(?: \[preauth\])?"),
    ),
)

SUDO_PATTERNS = (
    Pattern(
        Action.SUDO_EXEC,
        Level.INFO,
        #    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
        re.compile(r"\s*(?P<user>\S+) : TTY=.* ; COMMAND=.*"),
    ),
    Pattern(
        Action.SUDO_DENIED,
        Level.WARNING,
        #      bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=...
        re.compile(r"\s*(?P<user>\S+) : (?!TTY=)[^;]+ ; TTY=.* ; COMMAND=.*"),
    ),
)

# OpenSSH 9.8 moved per-connection work into a separate "sshd-session" program.
PATTERNS = {
    "sshd": SSHD_PATTERNS,
    "sshd-session": SSHD_PATTERNS,
    "sudo": SUDO_PATTERNS,
}


@register
class AuthLogParser(SyslogParser):
    """Parser for ``/var/log/auth.log`` (Debian, Ubuntu) and ``/var/log/secure`` (RHEL)."""

    name = "auth"

    def recognize(self, entry: ParsedLine) -> ParsedLine:
        for pattern in PATTERNS.get(entry.service or "", ()):
            match = pattern.regex.fullmatch(entry.message)
            if match is None:
                continue
            found = match.groupdict()
            port = found.get("src_port")
            return replace(
                entry,
                action=pattern.action,
                level=pattern.level,
                user=found.get("user") or None,
                src_ip=found.get("src_ip"),
                src_port=int(port) if port else None,
            )
        return entry
