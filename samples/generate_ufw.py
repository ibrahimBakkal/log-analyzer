#!/usr/bin/env python3
"""Generate a synthetic, anonymized ``ufw.log`` that goes with ``auth.log``.

Both files describe the same two days on the same server, so they can be loaded
together: every SSH connection that ``generate.py`` writes to ``auth.log``
shows up here as a packet the firewall let through to port 22.

The lines mimic what UFW makes the kernel log::

    Sep  9 05:20:03 web-01 kernel: [19803.512345] [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=...

As in ``auth.log``, every address comes from a documentation range and the
same ``--seed`` and ``--start`` always produce the same lines. Besides web
traffic and stray probes the log tells three stories; see ``PORTSCAN_IP``,
``SLOW_SCAN_IP`` and ``RARE_PORT_IP`` below.

Usage::

    python samples/generate_ufw.py                  # rewrites samples/ufw.log
    python samples/generate_ufw.py --seed 7 -o other.log
"""

import argparse
import random
import re
from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path

import generate as auth  # the auth.log generator next to this file

DEFAULT_OUTPUT = Path(__file__).with_name("ufw.log")
SERVER_IP = "192.0.2.5"
MAC = "52:54:00:12:34:56:52:54:00:65:43:21:08:00"  # QEMU's address range: no real hardware

# The three stories.
PORTSCAN_IP = "198.51.100.150"  # tries 120 different ports within about 40 seconds
SLOW_SCAN_IP = "203.0.113.150"  # tries a dozen ports, one every half hour: too slow to notice
RARE_PORT_IP = "203.0.113.77"  # gets through to remote desktop, which should not be open at all

OPEN_PORTS = (22, 80, 443)
RDP = 3389  # allowed by a forgotten firewall rule
# Ports the Internet's background noise keeps knocking on.
PROBED_PORTS = (21, 23, 25, 110, 135, 139, 445, 1433, 1521, 3306, 5432, 5900, 6379, 8080, 8443)

# "... from 203.0.113.45 port 52744 ...": the client side of an SSH connection.
_PEER = re.compile(r"((?:\d{1,3}\.){3}\d{1,3}) port (\d+)")


def packet(
    rng: random.Random, verdict: str, src: str, spt: int, dpt: int, proto: str = "TCP"
) -> str:
    """The text of one packet log line, from the verdict on (the uptime stamp is added later)."""
    head = (
        f"[UFW {verdict}] IN=eth0 OUT= MAC={MAC} SRC={src} DST={SERVER_IP} "
        f"LEN={rng.choice((40, 44, 52, 60))} TOS=0x00 PREC=0x00 TTL={rng.randint(40, 250)} "
        f"ID={rng.randint(1, 65535)} "
    )
    if proto == "UDP":
        return f"{head}PROTO=UDP SPT={spt} DPT={dpt} LEN={rng.randint(20, 120)}"
    window = rng.choice((1024, 29200, 64240, 65535))
    return f"{head}DF PROTO=TCP SPT={spt} DPT={dpt} WINDOW={window} RES=0x00 SYN URGP=0"


def build_entries(
    seed: int = auth.DEFAULT_SEED, start: datetime = auth.DEFAULT_START
) -> list[tuple[datetime, str]]:
    """Return every log entry as ``(timestamp, text after the host name)``, oldest first."""
    rng = random.Random(f"ufw-{seed}")
    rows: list[tuple[datetime, str]] = []

    def port() -> int:
        return rng.randint(32768, 60999)

    def add(
        when: datetime, verdict: str, src: str, dpt: int, spt: int | None = None, proto: str = "TCP"
    ):
        rows.append((when, packet(rng, verdict, src, spt or port(), dpt, proto)))

    def at(day: int, hour: int, minute: int = 0) -> datetime:
        return start + timedelta(days=day, hours=hour, minutes=minute, seconds=rng.randint(0, 59))

    # --- Ordinary traffic --------------------------------------------------------------
    # Every SSH connection of auth.log, one second before sshd first mentions it.
    seen: set[tuple[str, str]] = set()
    for when, text in auth.build_entries(seed, start):
        peer = _PEER.search(text)
        if peer and peer.groups() not in seen and "Server listening" not in text:
            seen.add(peer.groups())
            add(max(start, when - timedelta(seconds=1)), "ALLOW", peer[1], 22, int(peer[2]))

    stories = {PORTSCAN_IP, SLOW_SCAN_IP, RARE_PORT_IP, *auth.DOC_NETWORKS[0].hosts()}
    strangers = [
        str(ip) for net in auth.DOC_NETWORKS[1:] for ip in net.hosts() if str(ip) not in stories
    ]
    # Visitors of the web site.
    for _ in range(260):
        when = start + timedelta(seconds=rng.randrange(auth.HOURS * 3600))
        add(when, "ALLOW", rng.choice(strangers), rng.choice((80, 443, 443)))
    # Stray probes of closed ports: one to three per source, at least ten minutes apart.
    for src in rng.sample(strangers, 110):
        when = start + timedelta(seconds=rng.randrange((auth.HOURS - 2) * 3600))
        for _ in range(rng.choice((1, 1, 2, 3))):
            if rng.random() < 0.15:
                add(when, "BLOCK", src, rng.choice((53, 123, 161, 1900, 5060)), proto="UDP")
            else:
                add(when, "BLOCK", src, rng.choice(PROBED_PORTS))
            when += timedelta(minutes=rng.randint(10, 40))

    # --- Story 1: a port scan, 120 different ports in about 40 seconds -------------------
    when = at(0, 5, 20)
    low = rng.sample([p for p in range(1, 1025) if p not in OPEN_PORTS], 105)
    high = rng.sample(range(1025, 10000), 12)
    targets = [*OPEN_PORTS, *low, *high]
    rng.shuffle(targets)
    for index, target in enumerate(targets):
        verdict = "ALLOW" if target in OPEN_PORTS else "BLOCK"
        add(when + timedelta(seconds=index // 3), verdict, PORTSCAN_IP, target)

    # --- Story 2: the same idea done slowly, a dozen ports over six hours ----------------
    when = at(0, 12)
    for target in rng.sample(PROBED_PORTS, 12):
        add(when, "BLOCK", SLOW_SCAN_IP, target)
        when += timedelta(minutes=rng.randint(25, 35))

    # --- Story 3: remote desktop turns out to be reachable from the Internet -------------
    when = at(1, 13, 5)
    for _ in range(3):
        add(when, "ALLOW", RARE_PORT_IP, RDP)
        when += timedelta(seconds=rng.randint(4, 20))

    # The kernel stamps each line with the seconds since boot, ten minutes before the log starts.
    rows.sort(key=lambda row: row[0])
    entries = []
    for when, text in rows:
        uptime = (when - start).total_seconds() + 600 + rng.random()
        entries.append((when, f"kernel: [{uptime:12.6f}] {text}"))
    return entries


def build_lines(seed: int = auth.DEFAULT_SEED, start: datetime = auth.DEFAULT_START) -> list[str]:
    """Return the complete log, one string per line (without line endings)."""
    return [auth.format_line(when, text) for when, text in build_entries(seed, start)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic, anonymized ufw.log.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="file to write (default: %(default)s)",
    )
    parser.add_argument(
        "--seed", type=int, default=auth.DEFAULT_SEED, help="random seed (default: %(default)s)"
    )
    parser.add_argument(
        "--start",
        type=datetime.fromisoformat,
        default=auth.DEFAULT_START,
        help="first day of the log, ISO format (default: %(default)s)",
    )
    args = parser.parse_args(argv)

    lines = build_lines(args.seed, args.start)
    if leaked := auth.leaked_ips(lines):
        parser.exit(1, f"refusing to write: non-documentation IPs {sorted(leaked)}\n")
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(lines)} lines -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
