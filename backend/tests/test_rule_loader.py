"""Rule files: what is accepted, and how a bad one is reported."""

from pathlib import Path

import pytest

from app.enums import Action, Severity
from app.rules import KeywordRule, ThresholdRule, load_rules
from app.rules.schema import PortScanRule, RarePortRule, SequenceRule

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

SEQUENCE = """\
id: SSH-901
name: Break-in
type: sequence
severity: critical
steps:
  - match: {action: auth_fail}
    count: 5
  - match: {action: auth_ok}
within_seconds: 600
"""

PORT_SCAN = """\
id: NET-900
name: Port scan
type: port_scan
severity: high
min_ports: 15
window_seconds: 60
"""

RARE_PORT = """\
id: NET-901
name: Unexpected port
type: rare_port
severity: medium
mode: watchlist
ports: [23, 3389]
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
    assert [rule.id for rule in rules.rules] == [
        "KW-001",
        "NET-001",
        "NET-002",
        "SSH-001",
        "SSH-002",
    ]


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


def test_sequence_rule_with_defaults(tmp_path):
    rule, error = load_one(tmp_path, SEQUENCE)
    assert error is None
    assert isinstance(rule, SequenceRule)
    assert [(step.match.action, step.count) for step in rule.steps] == [
        ([Action.AUTH_FAIL], 5),
        ([Action.AUTH_OK], 1),
    ]
    assert (rule.within_seconds, rule.group_by, rule.cooldown_seconds) == (600, "src_ip", 300)


def test_port_scan_rule_with_defaults(tmp_path):
    rule, error = load_one(tmp_path, PORT_SCAN)
    assert error is None
    assert isinstance(rule, PortScanRule)
    assert (rule.min_ports, rule.window_seconds, rule.group_by) == (15, 60, "src_ip")
    assert not rule.match.restricts


def test_rare_port_rule_with_defaults(tmp_path):
    rule, error = load_one(tmp_path, RARE_PORT)
    assert error is None
    assert isinstance(rule, RarePortRule)
    assert (rule.mode, rule.ports, rule.group_by) == ("watchlist", [23, 3389], "src_ip")


def test_match_can_name_destination_ports(tmp_path):
    rule, error = load_one(
        tmp_path, THRESHOLD.replace("action: auth_fail", "action: conn_block\n  dst_port: 22")
    )
    assert error is None
    assert (rule.match.action, rule.match.dst_port) == ([Action.CONN_BLOCK], [22])
    assert rule.match.restricts


@pytest.mark.parametrize(
    ("text", "placeholder"),
    [
        (SEQUENCE, "{within_seconds}"),
        (PORT_SCAN, "{ports} of at least {min_ports} in {window_seconds}"),
        (RARE_PORT, "{ports}"),
    ],
)
def test_each_rule_type_offers_its_own_summary_placeholders(tmp_path, text, placeholder):
    rule, error = load_one(tmp_path, text + f"summary: '{{key}}: {placeholder}'\n")
    assert error is None
    assert placeholder in rule.summary


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


def test_rules_in_folders_are_loaded_too_and_named_with_their_folder(tmp_path):
    folder = tmp_path / "sigma"
    folder.mkdir()
    (tmp_path / "looks-like-a-rule.yaml").mkdir()
    write(tmp_path, z__yaml=KEYWORD)
    write(folder, a__yaml=THRESHOLD, broken__yaml="id: [", LICENSE__md="not a rule")
    write(folder, again__yaml=KEYWORD)

    rules = load_rules(tmp_path)

    assert [rule.id for rule in rules.rules] == ["SSH-900", "KW-900"]
    assert [(error.file, error.message) for error in rules.errors] == [
        ("sigma/broken.yaml", rules.errors[0].message),
        ("z.yaml", "id 'KW-900' is already used by sigma/again.yaml"),
    ]


def test_where_a_rule_comes_from_can_be_written_down(tmp_path):
    rule, error = load_one(
        tmp_path,
        KEYWORD
        + "author: Jane Doe\n"
        + "source: https://example.org/rules/shadow.yml\n"
        + "license: Detection Rule License 1.1\n"
        + "references: [https://example.org/advisory]\n"
        + "tags: [attack.credential-access, attack.t1003.008]\n"
        + "false_positives: [Backup jobs]\n",
    )
    assert error is None
    assert (rule.author, rule.license) == ("Jane Doe", "Detection Rule License 1.1")
    assert rule.source == "https://example.org/rules/shadow.yml"
    assert rule.references == ["https://example.org/advisory"]
    assert rule.tags == ["attack.credential-access", "attack.t1003.008"]
    assert rule.false_positives == ["Backup jobs"]

    plain, _ = load_one(tmp_path, KEYWORD)
    assert (plain.author, plain.source, plain.license) == ("", "", "")
    assert (plain.references, plain.tags, plain.false_positives) == ([], [], [])


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
            "does not match any of the expected tags: 'keyword', 'threshold', 'sequence', "
            "'port_scan', 'rare_port'",
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
            "keywords.0: '' has nothing to look for",
        ),
        (
            KEYWORD.replace("keywords: [/etc/shadow]", "keywords: ['**']"),
            "keywords.0: '**' has nothing to look for",
        ),
        (KEYWORD + "exclude: ['**']\n", "exclude.0: '**' has nothing to look for"),
        (KEYWORD + "require: [[]]\n", "require: an entry without keywords can never be satisfied"),
        (KEYWORD + "require: [[sudo, '*']]\n", "require.0.1: '*' has nothing to look for"),
        (KEYWORD.replace("id: KW-900", "id: 'has spaces'"), "id: String should match pattern"),
        (
            THRESHOLD.replace("action: auth_fail", "dst_port: 70000"),
            "match.dst_port.0: Input should be less than or equal to 65535",
        ),
        (THRESHOLD + "summary: '{ports} ports'\n", "summary: unknown placeholder {ports}"),
        (
            SEQUENCE.replace("  - match: {action: auth_ok}\n", ""),
            "steps: List should have at least 2 items",
        ),
        (
            SEQUENCE.replace("match: {action: auth_ok}", "match: {}"),
            "steps.1: match: a step must say which events it waits for",
        ),
        (SEQUENCE.replace("  - match: {action: auth_ok}", "  - count: 2"), "steps.1.match"),
        (
            SEQUENCE.replace("count: 5", "count: 0"),
            "steps.0.count: Input should be greater than or equal to 1",
        ),
        (
            SEQUENCE.replace("count: 5", "times: 5"),
            "steps.0.times: Extra inputs are not permitted",
        ),
        (SEQUENCE.replace("within_seconds: 600\n", ""), "within_seconds: Field required"),
        (SEQUENCE + "summary: '{threshold}'\n", "summary: unknown placeholder {threshold}"),
        (
            PORT_SCAN.replace("min_ports: 15", "min_ports: 1"),
            "min_ports: Input should be greater than or equal to 2",
        ),
        (PORT_SCAN.replace("window_seconds: 60\n", ""), "window_seconds: Field required"),
        (PORT_SCAN + "ports: [22]\n", "ports: Extra inputs are not permitted"),
        (
            RARE_PORT.replace("mode: watchlist", "mode: blocklist"),
            "mode: Input should be 'watchlist' or 'allowlist'",
        ),
        (RARE_PORT.replace("mode: watchlist\n", ""), "mode: Field required"),
        (
            RARE_PORT.replace("ports: [23, 3389]", "ports: []"),
            "ports: List should have at least 1 item",
        ),
        (
            RARE_PORT.replace("ports: [23, 3389]", "ports: [23, 65536]"),
            "ports.1: Input should be less than or equal to 65535",
        ),
        (
            RARE_PORT.replace("ports: [23, 3389]", "ports: [ssh]"),
            "ports.0: Input should be a valid integer",
        ),
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
