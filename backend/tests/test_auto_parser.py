"""The parser for syslog files of any content, and uploads that do not name a parser."""

import generate  # samples/generate.py
import generate_ufw  # samples/generate_ufw.py
from app.enums import Action
from app.parsers import create_parser, parser_names
from app.parsers.auto import AutoParser

YEAR = generate.DEFAULT_START.year
MIXED = [
    "Sep  9 03:12:39 web-01 sshd[1734]: Failed password for root from 203.0.113.45 port 52744 ssh2",
    "Sep  9 03:12:40 web-01 kernel: [19201.482913] [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.150 "
    "DST=192.0.2.5 LEN=44 PROTO=TCP SPT=43210 DPT=23 SYN URGP=0",
    "Sep  9 03:12:41 web-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
    "COMMAND=/usr/bin/systemctl restart nginx",
    "Sep  9 03:12:42 web-01 CRON[2201]: pam_unix(cron:session): session opened for user root",
    "Sep  9 03:12:43 web-01 kernel: [19204.000001] [UFW AUDIT] IN=eth0 OUT= SRC=198.51.100.150 "
    "DST=192.0.2.5 LEN=44 PROTO=TCP SPT=43211 DPT=8080 SYN URGP=0",
]


def test_one_file_may_mix_the_lines_of_several_programs():
    parser = create_parser("auto", year=YEAR)
    entries = [parser.parse(line) for line in MIXED]

    assert [entry.action for entry in entries] == [
        Action.AUTH_FAIL,
        Action.CONN_BLOCK,
        Action.SUDO_EXEC,
        None,
        None,
    ]
    assert (entries[0].src_ip, entries[1].dst_port, entries[2].user) == (
        "203.0.113.45",
        23,
        "alice",
    )
    # A packet with an unknown verdict keeps what the firewall parser read from it.
    assert (entries[4].parsed, entries[4].dst_port) == (False, 8080)


def test_auto_reads_each_sample_exactly_as_its_own_parser_does():
    for name, lines in (("auth", generate.build_lines()), ("ufw", generate_ufw.build_lines())):
        own, auto = create_parser(name, year=YEAR), create_parser("auto", year=YEAR)
        assert [auto.parse(line) for line in lines] == [own.parse(line) for line in lines]


def test_auto_knows_every_other_registered_parser():
    assert {parser.name for parser in AutoParser.PARSERS} | {"auto"} == set(parser_names())


def test_time_zone_and_year_reach_the_timestamps():
    entry = create_parser("auto", year=2024, tz="Europe/Istanbul").parse(MIXED[0])
    assert entry.ts.isoformat() == "2024-09-09T00:12:39+00:00"


def test_upload_without_naming_a_parser_recognizes_both_samples(client):
    reports = []
    for filename, lines in (
        ("auth.log", generate.build_lines()),
        ("ufw.log", generate_ufw.build_lines()),
    ):
        files = {"file": (filename, "\n".join(lines).encode())}
        reports.append(client.post("/ingest", files=files, data={"year": str(YEAR)}).json())

    assert [(report["parsed"], report["unparsed"]) for report in reports] == [(605, 452), (781, 0)]
    assert reports[-1]["alerts"] == 8


def test_unknown_parser_is_rejected_with_the_names_that_exist(client):
    files = {"file": ("auth.log", b"Sep  9 03:12:39 web-01 sshd[1]: hello\n")}
    response = client.post("/ingest", files=files, data={"parser": "nginx"})
    assert response.status_code == 422
    assert response.json()["detail"] == "unknown parser 'nginx' (available: auth, auto, ufw)"
