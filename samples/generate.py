#!/usr/bin/env python3
"""Generate a synthetic, anonymized ``auth.log`` for demos and tests.

The output mimics the classic syslog format that sshd, sudo and cron write to
``/var/log/auth.log`` on Debian/Ubuntu::

    Sep  9 03:12:39 web-01 sshd[1734]: Failed password for root from 203.0.113.45 port 52744 ssh2

Nothing in the file comes from a real machine:

* every IP address belongs to an RFC 5737 documentation range
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24);
* user names come from the fixed lists in this file;
* the same ``--seed`` and ``--start`` always produce the same lines.

Besides ordinary activity (logins, sudo, cron, stray login attempts) the log
contains four stories to test detection rules against; see ``SCANNER_IP``,
``BRUTE_IP``, ``SLOW_IP`` and ``INTRUDER_IP`` below.

Usage::

    python samples/generate.py                      # rewrites samples/auth.log
    python samples/generate.py --seed 7 -o other.log
    python samples/generate.py --start 2026-12-31   # spans the Dec -> Jan rollover
"""

import argparse
import ipaddress
import random
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

HOST = "web-01"
DEFAULT_SEED = 42
# 9 -> 10 September: the file contains both a space-padded day ("Sep  9") and "Sep 10".
# The year is not written to the file: classic syslog timestamps have none.
DEFAULT_START = datetime(2026, 9, 9)
DEFAULT_OUTPUT = Path(__file__).with_name("auth.log")
HOURS = 48

# strftime("%b") depends on the locale; syslog always uses these English abbreviations.
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# RFC 5737: reserved for documentation, never routed on the Internet.
DOC_NETWORKS = tuple(
    ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


@dataclass(frozen=True)
class Account:
    """A legitimate user of the server."""

    name: str
    uid: int
    ip: str  # where this user normally connects from
    method: str  # "password" or "publickey"
    sudoer: bool


# Legitimate users all connect from 192.0.2.0/24; everything else is a stranger.
ALICE = Account("alice", 1000, "192.0.2.10", "publickey", sudoer=True)
BOB = Account("bob", 1001, "192.0.2.11", "password", sudoer=False)
DEPLOY = Account("deploy", 1002, "192.0.2.50", "publickey", sudoer=True)

# The four stories.
SCANNER_IP = "198.51.100.23"  # tries a dictionary of user names, one password each
BRUTE_IP = "203.0.113.45"  # hammers root for about a minute, returns the next day
SLOW_IP = "198.51.100.77"  # one guess every 20-30 minutes: too slow for a rate threshold
INTRUDER_IP = "203.0.113.99"  # brute-forces bob's password and finally logs in

# Default and service account names that SSH scanners commonly try.
DICTIONARY = (
    "admin", "administrator", "ansible", "backup", "centos", "demo", "dev", "docker",
    "elastic", "es", "ftpuser", "git", "guest", "hadoop", "info", "jenkins", "kafka",
    "minecraft", "mysql", "nagios", "odoo", "operator", "oracle", "pi", "postgres",
    "redis", "server", "steam", "student", "support", "teamspeak", "test", "testuser",
    "tomcat", "ubuntu", "user", "vagrant", "webmaster", "www", "zabbix",
)  # fmt: skip

ADMIN_COMMANDS = (
    "/usr/bin/apt update",
    "/usr/bin/journalctl -u nginx --since today",
    "/usr/bin/systemctl reload nginx",
    "/usr/bin/systemctl status app",
    "/usr/bin/tail -n 100 /var/log/nginx/error.log",
    "/usr/sbin/ufw status",
)
DEPLOY_COMMAND = "/usr/bin/systemctl restart app"
INTRUDER_COMMANDS = ("/usr/bin/cat /etc/shadow", "/usr/bin/su -")

# Process prefixes. The {placeholders} are filled in once all connections are known,
# so that process and session ids grow with time like they do on a real machine.
SSHD = "sshd[{pid}]: "
SSHD_CHILD = "sshd[{cpid}]: "  # unprivileged child of a logged-in connection
CRON = "CRON[{pid}]: "
LOGIND = "systemd-logind[612]: "
SUDO = "sudo: "
SID = "{sid}"

PAM_CONTEXT = "logname= uid=0 euid=0 tty=ssh ruser="  # followed by "rhost=... [ user=...]"


@dataclass
class Conn:
    """A group of related lines: one SSH connection, one cron run, ..."""

    start: datetime
    lines: list[tuple[int, str]] = field(default_factory=list)  # (seconds after start, text)
    login: bool = False  # a successful login gets a systemd-logind session id

    def add(self, offset: int, text: str) -> None:
        self.lines.append((offset, text))


def _port(rng: random.Random) -> int:
    return rng.randint(32768, 60999)  # Linux ephemeral port range


def _fingerprint(name: str) -> str:
    """A made-up but stable SSH key fingerprint for *name*."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(random.Random(name).choices(alphabet, k=43))


def failed_login(
    rng: random.Random, start: datetime, ip: str, user: str, *, known: bool, tries: int = 1
) -> Conn:
    """A connection that guesses *tries* passwords for *user* and is rejected."""
    port = _port(rng)
    conn = Conn(start)
    if known:
        target, closer = user, "authenticating user"
        pam = f"{PAM_CONTEXT} rhost={ip}  user={user}"
    else:
        target, closer = f"invalid user {user}", "invalid user"
        pam = f"{PAM_CONTEXT} rhost={ip}"
        conn.add(0, f"{SSHD}Invalid user {user} from {ip} port {port}")
        conn.add(0, f"{SSHD}pam_unix(sshd:auth): check pass; user unknown")
    conn.add(0, f"{SSHD}pam_unix(sshd:auth): authentication failure; {pam}")
    elapsed = 0
    for _ in range(tries):
        elapsed += rng.randint(1, 3)
        conn.add(elapsed, f"{SSHD}Failed password for {target} from {ip} port {port} ssh2")
    if rng.random() < 0.7:
        conn.add(elapsed, f"{SSHD}Connection closed by {closer} {user} {ip} port {port} [preauth]")
    else:
        conn.add(elapsed, f"{SSHD}Received disconnect from {ip} port {port}:11: Bye Bye [preauth]")
        conn.add(elapsed, f"{SSHD}Disconnected from {closer} {user} {ip} port {port} [preauth]")
    if tries > 1:
        plural = "s" if tries > 2 else ""
        conn.add(elapsed, f"{SSHD}PAM {tries - 1} more authentication failure{plural}; {pam}")
    return conn


def probe(rng: random.Random, start: datetime, ip: str, user: str) -> Conn:
    """A scanner that names a non-existent user and hangs up without trying a password."""
    port = _port(rng)
    conn = Conn(start)
    conn.add(0, f"{SSHD}Invalid user {user} from {ip} port {port}")
    closed = f"{SSHD}Connection closed by invalid user {user} {ip} port {port} [preauth]"
    conn.add(rng.randint(0, 2), closed)
    return conn


def session(
    rng: random.Random,
    start: datetime,
    account: Account,
    minutes: int,
    *,
    ip: str | None = None,
    typos: int = 0,
    commands: Sequence[str] = (),
) -> Conn:
    """A successful login lasting about *minutes*, optionally running sudo *commands*.

    *typos* wrong passwords are logged before the successful one. *ip* overrides the
    address the account normally connects from.
    """
    ip = ip or account.ip
    name = account.name
    port = _port(rng)
    conn = Conn(start, login=True)

    elapsed = 0
    if typos:
        pam = f"{PAM_CONTEXT} rhost={ip}  user={name}"
        conn.add(0, f"{SSHD}pam_unix(sshd:auth): authentication failure; {pam}")
        for _ in range(typos):
            elapsed += rng.randint(2, 5)
            conn.add(elapsed, f"{SSHD}Failed password for {name} from {ip} port {port} ssh2")
        elapsed += rng.randint(3, 8)
    if account.method == "publickey":
        key = f"ED25519 SHA256:{_fingerprint(name)}"
        conn.add(elapsed, f"{SSHD}Accepted publickey for {name} from {ip} port {port} ssh2: {key}")
    else:
        conn.add(elapsed, f"{SSHD}Accepted password for {name} from {ip} port {port} ssh2")
    who = f"{name}(uid={account.uid})"
    conn.add(elapsed, f"{SSHD}pam_unix(sshd:session): session opened for user {who} by (uid=0)")
    conn.add(elapsed, f"{LOGIND}New session {SID} of user {name}.")

    end = elapsed + minutes * 60 + rng.randint(0, 59)
    offsets = sorted(rng.sample(range(elapsed + 20, end - 5), len(commands)))
    for offset, command in zip(offsets, commands, strict=True):
        run = f"TTY=pts/0 ; PWD=/home/{name} ; USER=root ; COMMAND={command}"
        if account.sudoer:
            pam = f"{SUDO}pam_unix(sudo:session):"
            conn.add(offset, f"{SUDO}{name:>8} : {run}")
            conn.add(offset, f"{pam} session opened for user root(uid=0) by {who}")
            conn.add(offset + rng.randint(0, 3), f"{pam} session closed for user root")
        else:
            conn.add(offset, f"{SUDO}{name:>8} : user NOT in sudoers ; {run}")

    conn.add(end, f"{SSHD_CHILD}Received disconnect from {ip} port {port}:11: disconnected by user")
    conn.add(end, f"{SSHD_CHILD}Disconnected from user {name} {ip} port {port}")
    conn.add(end, f"{SSHD}pam_unix(sshd:session): session closed for user {name}")
    conn.add(end, f"{LOGIND}Session {SID} logged out. Waiting for processes to exit.")
    conn.add(end, f"{LOGIND}Removed session {SID}.")
    return conn


def cron_run(start: datetime) -> Conn:
    """The hourly cron job, which only shows up as a PAM session."""
    conn = Conn(start)
    conn.add(0, f"{CRON}pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
    conn.add(0, f"{CRON}pam_unix(cron:session): session closed for user root")
    return conn


def build_entries(
    seed: int = DEFAULT_SEED, start: datetime = DEFAULT_START
) -> list[tuple[datetime, str]]:
    """Return every log entry as ``(timestamp, text after the host name)``, oldest first."""
    rng = random.Random(seed)
    conns: list[Conn] = []

    def at(day: int, hour: int, minute: int = 0) -> datetime:
        return start + timedelta(days=day, hours=hour, minutes=minute, seconds=rng.randint(0, 59))

    # --- Ordinary activity -------------------------------------------------------------
    boot = Conn(start + timedelta(seconds=7))
    boot.add(0, f"{SSHD}Server listening on 0.0.0.0 port 22.")
    boot.add(0, f"{SSHD}Server listening on :: port 22.")
    conns.append(boot)

    for hour in range(HOURS):
        conns.append(cron_run(start + timedelta(hours=hour, minutes=17, seconds=1)))

    for day in range(HOURS // 24):
        # alice administers the server: a morning session and a shorter one after lunch.
        for hour, longest, count in ((9, 90, 3), (14, 60, 2)):
            when = at(day, hour, rng.randint(0, 40))
            commands = rng.sample(ADMIN_COMMANDS, count)
            conns.append(session(rng, when, ALICE, rng.randint(20, longest), commands=commands))
        # bob logs in once a day. On the first day he mistypes his password once: a
        # failure followed by a success that must *not* look like a break-in.
        when = at(day, 10, rng.randint(20, 50))
        typos = 1 if day == 0 else 0
        conns.append(session(rng, when, BOB, rng.randint(30, 120), typos=typos))
        # The CI pipeline deploys three times a day.
        for hour in (11, 15, 19):
            when = at(day, hour, rng.randint(0, 50))
            conns.append(session(rng, when, DEPLOY, rng.randint(1, 3), commands=(DEPLOY_COMMAND,)))

    # Background noise: strangers that try once or twice, at least 15 minutes apart.
    stories = {SCANNER_IP, BRUTE_IP, SLOW_IP, INTRUDER_IP}
    strangers = [
        str(ip) for net in DOC_NETWORKS[1:] for ip in net.hosts() if str(ip) not in stories
    ]
    for ip in rng.sample(strangers, 56):
        when = start + timedelta(seconds=rng.randrange((HOURS - 2) * 3600))
        for _ in range(rng.choice((1, 1, 2))):
            if rng.random() < 0.4:
                conns.append(failed_login(rng, when, ip, "root", known=True))
            elif rng.random() < 0.5:
                conns.append(failed_login(rng, when, ip, rng.choice(DICTIONARY), known=False))
            else:
                conns.append(probe(rng, when, ip, rng.choice(DICTIONARY)))
            when += timedelta(minutes=rng.randint(15, 90))

    # --- Story 1: a scanner tries 30 unknown user names in about two minutes -------------
    when = at(0, 1, 47)
    for user in rng.sample(DICTIONARY, 30):
        conns.append(failed_login(rng, when, SCANNER_IP, user, known=False))
        when += timedelta(seconds=rng.randint(2, 5))

    # --- Story 2: brute force against root, and a shorter second wave the next day -------
    # Two bursts from one address exercise alert cooldown / deduplication.
    for when, connections in ((at(0, 3, 12), 34), (at(1, 15, 40), 15)):
        for _ in range(connections):
            tries = rng.randint(1, 3)
            conns.append(failed_login(rng, when, BRUTE_IP, "root", known=True, tries=tries))
            when += timedelta(seconds=rng.randint(1, 4))

    # --- Story 3: low and slow, one guess every 20-30 minutes for half a day ------------
    when, stop = at(0, 10), start + timedelta(hours=22)
    while when < stop:
        conns.append(failed_login(rng, when, SLOW_IP, "root", known=True))
        when += timedelta(minutes=rng.randint(20, 30))

    # --- Story 4: 24 wrong passwords for bob in about a minute, then a successful login --
    # from an address bob never uses, followed by sudo attempts that are denied.
    when = at(1, 2, 31)
    for _ in range(8):
        conns.append(failed_login(rng, when, INTRUDER_IP, BOB.name, known=True, tries=3))
        when += timedelta(seconds=rng.randint(5, 9))
    when += timedelta(seconds=10)  # the last rejected connection has finished by now
    conns.append(session(rng, when, BOB, 4, ip=INTRUDER_IP, commands=INTRUDER_COMMANDS))

    # --- Assign ids in chronological order and flatten -----------------------------------
    rows = []
    pid, sid = 1200, 20
    for order, conn in enumerate(sorted(conns, key=lambda c: c.start)):
        pid += rng.randint(3, 25)
        cpid = pid + rng.randint(1, 2)
        if conn.login:
            sid += rng.randint(1, 3)
        for index, (offset, text) in enumerate(conn.lines):
            text = text.replace("{pid}", str(pid)).replace("{cpid}", str(cpid))
            text = text.replace("{sid}", str(sid))
            rows.append((conn.start + timedelta(seconds=offset), order, index, text))
    rows.sort(key=lambda row: row[:3])  # same second: keep each connection's own order
    return [(timestamp, text) for timestamp, _, _, text in rows]


def format_line(timestamp: datetime, text: str) -> str:
    """Format one entry the way rsyslog writes it: ``Sep  9 03:12:39 web-01 <text>``."""
    month = MONTHS[timestamp.month - 1]
    return f"{month} {timestamp.day:>2} {timestamp:%H:%M:%S} {HOST} {text}"


def build_lines(seed: int = DEFAULT_SEED, start: datetime = DEFAULT_START) -> list[str]:
    """Return the complete log, one string per line (without line endings)."""
    return [format_line(timestamp, text) for timestamp, text in build_entries(seed, start)]


_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def leaked_ips(lines: Iterable[str]) -> set[str]:
    """Return the IPv4 addresses in *lines* that are not documentation addresses.

    ``0.0.0.0`` is allowed because sshd logs it as its listen address.
    """
    leaked = set()
    for line in lines:
        for raw in _IPV4.findall(line):
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:  # e.g. 999.1.1.1: not an address, but worth a look
                leaked.add(raw)
                continue
            if not (ip.is_unspecified or any(ip in net for net in DOC_NETWORKS)):
                leaked.add(raw)
    return leaked


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic, anonymized auth.log.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="file to write (default: %(default)s)",
    )
    parser.add_argument(
        "--seed", type=int, default=DEFAULT_SEED, help="random seed (default: %(default)s)"
    )
    parser.add_argument(
        "--start",
        type=datetime.fromisoformat,
        default=DEFAULT_START,
        help="first day of the log, ISO format (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    lines = build_lines(args.seed, args.start)
    if leaked := leaked_ips(lines):
        parser.exit(1, f"refusing to write: non-documentation IPs {sorted(leaked)}\n")
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(lines)} lines -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
