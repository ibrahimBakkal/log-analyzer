"""Rule files: what is accepted, and how a bad one is reported."""

from pathlib import Path

import pytest

from app.enums import Action, Severity
from app.rules import KeywordRule, ThresholdRule, load_rules

SHIPPED_RULES = Path(__file__).resolve().parents[2] / "rules"

THRESHOLD = """\
id: SSH-900
name: Too many failures
type: threshold
severity: high
match:
  action: auth_fail
threshold: 5
window_seconds: 60
"""

KEYWORD = """\
id: KW-900
name: Shadow file
type: keyword
severity: low
keywords: [/etc/shadow]
"""


def write(directory: Path, **files: str) -> Path:
    for name, text in files.items():
        (directory / name.replace("__", ".")).write_text(text, encoding="utf-8")
    return directory


def load_one(tmp_path: Path, text: str):
    """Load a single rule file; return (rule or None, error message or None)."""
    rules = load_rules(write(tmp_path, rule__yaml=text))
    rule = rules.rules[0] if rules.rules else None
    message = rules.errors[0].message if rules.errors else None
    return rule, message


# --- what loads ------------------------------------------------------------------------------


def test_shipped_rules_load_without_errors():
    rules = load_rules(SHIPPED_RULES)
    assert rules.errors == ()
    assert [rule.id for rule in rules.rules] == ["KW-001", "SSH-001"]


def test_threshold_rule_with_defaults(tmp_path):
    rule, error = load_one(tmp_path, THRESHOLD)
    assert error is None
    assert isinstance(rule, ThresholdRule)
    assert (rule.id, rule.severity, rule.enabled) == ("SSH-900", Severity.HIGH, True)
    assert (rule.threshold, rule.window_seconds, rule.cooldown_seconds) == (5, 60, 300)
    assert (rule.group_by, rule.allowlist) == ("src_ip", [])
    assert rule.match.action == [Action.AUTH_FAIL]


def test_keyword_rule_with_defaults(tmp_path):
    rule, error = load_one(tmp_path, KEYWORD)
    assert error is None
    assert isinstance(rule, KeywordRule)
    assert (rule.keywords, rule.regex, rule.group_by) == (["/etc/shadow"], None, "host")


def test_match_takes_one_value_or_a_list(tmp_path):
    rule, _ = load_one(
        tmp_path, THRESHOLD.replace("action: auth_fail", "action: [auth_fail, invalid_user]")
    )
    assert rule.match.action == [Action.AUTH_FAIL, Action.INVALID_USER]


def test_allowlist_takes_addresses_and_networks(tmp_path):
    rule, error = load_one(
        tmp_path, THRESHOLD + "allowlist: [192.0.2.10, 198.51.100.0/24, '2001:db8::/32']\n"
    )
    assert error is None
    assert [str(network) for network in rule.allowlist] == [
        "192.0.2.10/32",
        "198.51.100.0/24",
        "2001:db8::/32",
    ]


def test_rules_load_in_file_name_order_and_other_files_are_ignored(tmp_path):
    write(tmp_path, b__yml=THRESHOLD, a__yaml=KEYWORD, README__md="not a rule", c__txt=THRESHOLD)
    rules = load_rules(tmp_path)
    assert rules.errors == ()
    assert [rule.id for rule in rules.rules] == ["KW-900", "SSH-900"]


def test_disabled_rules_are_loaded_but_not_enabled(tmp_path):
    write(tmp_path, a__yaml=KEYWORD, b__yaml=THRESHOLD + "enabled: false\n")
    rules = load_rules(tmp_path)
    assert [rule.id for rule in rules.rules] == ["KW-900", "SSH-900"]
    assert [rule.id for rule in rules.enabled] == ["KW-900"]


# --- what is rejected, and what the message says --------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            THRESHOLD.replace("threshold: 5", "treshold: 5"),
            "treshold: Extra inputs are not permitted",
        ),
        (THRESHOLD.replace("threshold: 5", "treshold: 5"), "threshold: Field required"),
        (
            THRESHOLD.replace("threshold: 5", "threshold: 0"),
            "threshold: Input should be greater than or equal to 1",
        ),
        (
            THRESHOLD.replace("severity: high", "severity: urgent"),
            "severity: Input should be 'low', 'medium', 'high' or 'critical'",
        ),
        (
            THRESHOLD.replace("action: auth_fail", "action: login_failed"),
            "match.action.0: Input should be",
        ),
        (
            THRESHOLD.replace("action: auth_fail", "actoin: auth_fail"),
            "match.actoin: Extra inputs are not permitted",
        ),
        (
            THRESHOLD.replace("type: threshold", "type: treshold"),
            "does not match any of the expected tags: 'keyword', 'threshold'",
        ),
        (
            THRESHOLD.replace("type: threshold\n", ""),
            "Unable to extract tag using discriminator 'type'",
        ),
        (
            THRESHOLD + "allowlist: [not-an-address]\n",
            "allowlist.0: value is not a valid IPv4 or IPv6 network",
        ),
        (
            THRESHOLD + "group_by: country\n",
            "group_by: Input should be 'src_ip', 'user', 'host' or 'service'",
        ),
        (
            THRESHOLD + "summary: '{ip} is noisy'\n",
            "summary: unknown placeholder {ip} (available: {count}, {key}",
        ),
        (THRESHOLD + "summary: 'unbalanced {'\n", "summary: "),
        (KEYWORD + "summary: '{threshold} lines'\n", "summary: unknown placeholder {threshold}"),
        (
            KEYWORD.replace("keywords: [/etc/shadow]", "regex: '(unclosed'"),
            "regex: not a valid regular expression",
        ),
        (
            KEYWORD.replace("keywords: [/etc/shadow]\n", ""),
            "give at least one of 'keywords' or 'regex'",
        ),
        (
            KEYWORD.replace("keywords: [/etc/shadow]", "keywords: ['']"),
            "keywords.0: String should have at least 1 character",
        ),
        (KEYWORD.replace("id: KW-900", "id: 'has spaces'"), "id: String should match pattern"),
        ("id: [unclosed\n", "not valid YAML (line 2)"),
        ("- id: A-1\n- id: A-2\n", "expected the fields of one rule"),
        ("", "expected the fields of one rule"),
    ],
)
def test_bad_rule_file_is_rejected_with_a_message_naming_the_problem(tmp_path, text, expected):
    rule, error = load_one(tmp_path, text)
    assert rule is None
    assert expected in error


def test_bad_file_does_not_stop_the_others_from_loading(tmp_path):
    write(tmp_path, a__yaml="id: [unclosed\n", b__yaml=THRESHOLD, c__yaml=KEYWORD)
    rules = load_rules(tmp_path)
    assert [rule.id for rule in rules.rules] == ["SSH-900", "KW-900"]
    assert [error.file for error in rules.errors] == ["a.yaml"]


def test_second_file_with_the_same_id_is_rejected(tmp_path):
    write(tmp_path, a__yaml=THRESHOLD, b__yaml=THRESHOLD.replace("threshold: 5", "threshold: 9"))
    rules = load_rules(tmp_path)
    assert [rule.threshold for rule in rules.rules] == [5]
    assert [(error.file, error.message) for error in rules.errors] == [
        ("b.yaml", "id 'SSH-900' is already used by a.yaml")
    ]


def test_missing_directory_is_reported_not_raised(tmp_path):
    rules = load_rules(tmp_path / "nowhere")
    assert rules.rules == ()
    assert rules.errors[0].message == "rules directory not found"
