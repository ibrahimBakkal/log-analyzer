"""UFW / iptables packet logs: verdict, addresses and ports."""

import pytest

from app.enums import Action, Level
from app.parsers import create_parser, parser_names
from app.parsers.ufw import UfwParser, parse_fields

HEADER = "Sep  9 05:20:01 web-01 "
MAC = "MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00"
TCP = "LEN=44 TOS=0x00 PREC=0x00 TTL=241 ID=54321 PROTO=TCP"


def parse(rest: str):
    return UfwParser(year=2026).parse(HEADER + rest)


def packet(
    prefix: str, src: str, dst: str, spt: int, dpt: int, stamp: str = "[19201.482913] "
) -> str:
    return (
        f"kernel: {stamp}{prefix} IN=eth0 OUT= {MAC} SRC={src} DST={dst} {TCP} "
        f"SPT={spt} DPT={dpt} WINDOW=1024 RES=0x00 SYN URGP=0"
    )


# (line, source, destination, source port, destination port)
ACCEPTED = {
    Action.CONN_BLOCK: [
        (
            packet("[UFW BLOCK]", "198.51.100.150", "192.0.2.5", 43210, 23),
            "198.51.100.150",
            "192.0.2.5",
            43210,
            23,
        ),
        (
            packet(
                "[UFW LIMIT BLOCK]", "203.0.113.45", "192.0.2.5", 52744, 22, stamp="[    7.001] "
            ),
            "203.0.113.45",
            "192.0.2.5",
            52744,
            22,
        ),
        (
            packet("iptables-dropped:", "2001:db8::66", "2001:db8::5", 40000, 3389, stamp=""),
            "2001:db8::66",
            "2001:db8::5",
            40000,
            3389,
        ),
        (
            "kernel: [19300.000001] [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=192.0.2.5 "
            "LEN=84 TTL=50 ID=1 PROTO=ICMP TYPE=8 CODE=0 ID=7 SEQ=1",
            "198.51.100.9",
            "192.0.2.5",
            None,  # ICMP has no ports
            None,
        ),
    ],
    Action.CONN_ALLOW: [
        (
            packet("[UFW ALLOW]", "192.0.2.10", "192.0.2.5", 37340, 22),
            "192.0.2.10",
            "192.0.2.5",
            37340,
            22,
        ),
        (
            packet("[UFW ALLOW]", "198.51.100.77", "192.0.2.5", 51000, 443, stamp=""),
            "198.51.100.77",
            "192.0.2.5",
            51000,
            443,
        ),
        (
            packet("ACCEPT-web", "203.0.113.200", "192.0.2.5", 60999, 80),
            "203.0.113.200",
            "192.0.2.5",
            60999,
            80,
        ),
    ],
}

REJECTED = {
    Action.CONN_BLOCK: [
        "kernel: [19201.482913] [UFW BLOCK] no packet fields here",
        "kernel: [    0.000000] Linux version 6.8.0-45-generic (buildd@lcy02-amd64-115)",
        # Not from the kernel: some program merely quoting a firewall line.
        "myapp[77]: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.150 DST=192.0.2.5 PROTO=TCP "
        "SPT=1 DPT=23",
    ],
    Action.CONN_ALLOW: [
        "kernel: [19201.482913] [UFW ALLOW] IN=eth0 OUT= SRC=192.0.2.10 PROTO=TCP SPT=1 DPT=22",
        "sshd[2380]: Accepted publickey for alice from 192.0.2.10 port 37340 ssh2",
    ],
}


def test_both_verdicts_have_at_least_three_positive_and_one_negative_example():
    for action in (Action.CONN_BLOCK, Action.CONN_ALLOW):
        assert len(ACCEPTED[action]) >= 3 and len(REJECTED[action]) >= 1


@pytest.mark.parametrize(
    ("action", "line", "src", "dst", "spt", "dpt"),
    [(action, *case) for action, cases in ACCEPTED.items() for case in cases],
)
def test_packet_line_is_recognized(action, line, src, dst, spt, dpt):
    entry = parse(line)
    assert entry.parsed and entry.service == "kernel"
    assert (entry.action, entry.src_ip, entry.dst_ip, entry.src_port, entry.dst_port) == (
        action,
        src,
        dst,
        spt,
        dpt,
    )


@pytest.mark.parametrize("line", [line for lines in REJECTED.values() for line in lines])
def test_other_lines_stay_unparsed(line):
    entry = parse(line)
    assert entry is not None
    assert (entry.action, entry.parsed) == (None, False)


def test_blocked_packets_are_warnings_and_allowed_ones_are_not():
    assert parse(ACCEPTED[Action.CONN_BLOCK][0][0]).level == Level.WARNING
    assert parse(ACCEPTED[Action.CONN_ALLOW][0][0]).level == Level.INFO


def test_packet_with_unknown_verdict_keeps_its_addresses_but_is_not_parsed():
    entry = parse(packet("[UFW AUDIT]", "198.51.100.150", "192.0.2.5", 43210, 8080))
    assert (entry.action, entry.parsed, entry.level) == (None, False, Level.INFO)
    assert (entry.src_ip, entry.dst_ip, entry.dst_port) == ("198.51.100.150", "192.0.2.5", 8080)


def test_impossible_port_numbers_are_dropped():
    entry = parse(packet("[UFW BLOCK]", "198.51.100.150", "192.0.2.5", 70000, 23))
    assert (entry.src_port, entry.dst_port) == (None, 23)


def test_parse_fields_keeps_pairs_and_skips_flags():
    assert parse_fields("IN=eth0 OUT= SRC=198.51.100.1 DF PROTO=TCP SYN URGP=0") == {
        "IN": "eth0",
        "OUT": "",
        "SRC": "198.51.100.1",
        "PROTO": "TCP",
        "URGP": "0",
    }


def test_ufw_parser_is_registered():
    assert "ufw" in parser_names()
    assert isinstance(create_parser("ufw", year=2026), UfwParser)
