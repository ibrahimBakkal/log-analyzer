"""Redoing only the groups with new events must give what redoing everything gives."""

import random
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

import generate  # samples/generate.py
import generate_ufw  # samples/generate_ufw.py
from app.config import get_settings
from app.db import get_session
from app.ingest import Ingestor
from app.main import app
from app.models import Alert, AlertEvent, State
from app.parsers import create_parser
from app.rules import AlertKeeper, evaluate, latest_event_id, load_rules
from app.rules import engine as rule_engine
from app.rules.loader import RuleSet
from app.rules.schema import RULE

SHIPPED = load_rules(Path(__file__).resolve().parents[2] / "rules")
YEAR = generate.DEFAULT_START.year
FILES = {"auth.log": generate.build_lines(), "ufw.log": generate_ufw.build_lines()}

# Rules that group by something other than the source address, or cannot be
# narrowed down by the database: the paths the shipped rules do not take.
EXTRA = [
    {
        "id": "T-USER",
        "name": "Failures per account",
        "type": "threshold",
        "severity": "low",
        "match": {"action": "auth_fail"},
        "group_by": "user",
        "threshold": 10,
        "window_seconds": 120,
    },
    {
        "id": "T-HOST",
        "name": "Blocked packets per machine",
        "type": "threshold",
        "severity": "low",
        "match": {"action": "conn_block"},
        "group_by": "host",
        "threshold": 20,
        "window_seconds": 60,
        "cooldown_seconds": 30,
    },
    {
        "id": "T-REGEX",
        "name": "Root over SSH",
        "type": "keyword",
        "severity": "low",
        "regex": r"for root from \S+ port",
        "group_by": "src_ip",
        "cooldown_seconds": 60,
    },
    {
        "id": "T-WORDS",
        "name": "Texts, per machine",
        "type": "keyword",
        "severity": "low",
        "keywords": ["invalid user", "session opened*root", "UFW BLOCK"],
        "require": [["port ", "DPT="]],
        "exclude": ["DPT=443 "],
        "cooldown_seconds": 120,
    },
    {
        "id": "T-ALLOW",
        "name": "Port off the list",
        "type": "rare_port",
        "severity": "low",
        "mode": "allowlist",
        "ports": [22, 80, 443],
        "match": {"action": "conn_allow"},
    },
    {
        "id": "T-SERVICE",
        "name": "Scan seen by a program",
        "type": "port_scan",
        "severity": "low",
        "group_by": "service",
        "min_ports": 30,
        "window_seconds": 30,
    },
]
RULES = RuleSet((*SHIPPED.rules, *(RULE.validate_python(rule) for rule in EXTRA)))


def table(session: Session) -> dict:
    """Everything an evaluation produces, without the ids it happened to hand out."""
    session.expire_all()
    evidence: dict[int, list] = {}
    for alert_id, event_id, spans in session.execute(
        select(AlertEvent.alert_id, AlertEvent.event_id, AlertEvent.spans)
    ):
        evidence.setdefault(alert_id, []).append((event_id, spans))
    return {
        alert.key: (
            alert.rule_id,
            alert.rule_name,
            alert.severity,
            alert.group_by,
            alert.group_key,
            alert.first_seen,
            alert.last_seen,
            alert.count,
            alert.summary,
            sorted(evidence.get(alert.id, [])),
        )
        for alert in session.scalars(select(Alert))
    }


def appends(seed: int) -> list[tuple[str, int, int]]:
    """Both sample files, cut into pieces of uneven size and shuffled together.

    Each piece is (file, first line index, end line index); the pieces of one
    file stay in order, as they would when a file grows.
    """
    rng = random.Random(seed)
    pieces = []
    for name, lines in FILES.items():
        start = 0
        while start < len(lines):
            size = rng.choice((1, 3, 17, 60, 250))
            pieces.append((name, start, min(len(lines), start + size)))
            start += size
    order = [name for name, _, _ in pieces]
    rng.shuffle(order)
    queues = {name: [piece for piece in pieces if piece[0] == name] for name in FILES}
    return [queues[name].pop(0) for name in order]


# The limits as shipped; then each so low that the way around it is taken.
@pytest.mark.parametrize("seed", range(6))
@pytest.mark.parametrize(
    "limits",
    [
        {},
        {"MAX_GROUPS": 2},
        {"MAX_SORTED_HERE": 3},
        {"MAX_CANDIDATES": 3},  # keyword rules: too many lines to list
        {"_IDS_PER_QUERY": 2, "_SAMPLE": 5},  # ... and listed lines fetched a few at a time
    ],
    ids=lambda limits: ",".join(f"{name}={value}" for name, value in limits.items()) or "shipped",
)
def test_group_by_group_gives_what_starting_over_gives(session, monkeypatch, seed, limits):
    for name, value in limits.items():
        monkeypatch.setattr(rule_engine, name, value)
    ingestors = {
        name: Ingestor(session, name=name, parser=create_parser("auto", year=YEAR))
        for name in FILES
    }
    steps = appends(seed)
    for number, (name, first, end) in enumerate(steps):
        before = latest_event_id(session)
        ingestors[name].feed(enumerate(FILES[name][first:end], start=first + 1))
        ingestors[name].flush()
        evaluate(session, RULES.enabled, since=before)

        if number % 25 == 0 or number == len(steps) - 1:
            step_by_step = table(session)
            outcome = evaluate(session, RULES.enabled)
            assert (outcome.created, outcome.updated, outcome.removed) == (0, 0, 0)
            assert table(session) == step_by_step

    final = table(session)
    assert len(final) > 8  # the shipped rules' eight alerts and those of the extra rules
    assert {key.split(":")[0] for key in final} >= {"SSH-001", "SSH-002", "NET-001", "T-USER"}


def load(session: Session, name: str = "auth.log", lines: list[str] | None = None) -> None:
    ingestor = Ingestor(session, name=name, parser=create_parser("auto", year=YEAR))
    ingestor.feed(enumerate(FILES[name] if lines is None else lines, start=1))
    ingestor.flush()


def test_groups_without_new_events_are_left_alone(session):
    load(session, "auth.log", FILES["auth.log"][:900])
    evaluate(session, SHIPPED.enabled)
    victim = session.scalars(select(Alert).where(Alert.group_key == generate.BRUTE_IP)).first()
    victim.summary = "edited by hand"
    session.commit()

    # New lines of other addresses only: the edited alert is not looked at again.
    before = latest_event_id(session)
    quiet = [line for line in FILES["auth.log"][900:] if generate.BRUTE_IP not in line][:40]
    ingestor = Ingestor(session, name="later.log", parser=create_parser("auto", year=YEAR))
    ingestor.feed(enumerate(quiet, start=1))
    ingestor.flush()
    outcome = evaluate(session, SHIPPED.enabled, since=before)
    session.expire_all()
    assert session.get(Alert, victim.id).summary == "edited by hand"
    assert outcome.total == len(table(session))

    # Starting over does look at it.
    assert evaluate(session, SHIPPED.enabled).updated == 1
    session.expire_all()
    assert session.get(Alert, victim.id).summary != "edited by hand"


def test_nothing_new_means_nothing_to_do(session, monkeypatch):
    load(session)
    evaluate(session, SHIPPED.enabled)
    monkeypatch.setattr(rule_engine, "detect", lambda *arguments: pytest.fail("looked at events"))

    outcome = evaluate(session, SHIPPED.enabled, since=latest_event_id(session))
    assert (outcome.total, outcome.created, outcome.updated, outcome.removed) == (6, 0, 0, 0)


def test_step_by_step_run_keeps_alerts_of_rules_that_are_switched_off(session):
    """Only a full run clears those away; a reload always does a full run."""
    load(session)
    evaluate(session, SHIPPED.enabled)
    only_keyword = [rule for rule in SHIPPED.enabled if rule.id == "KW-001"]

    assert evaluate(session, only_keyword, since=0).total == 6
    assert evaluate(session, only_keyword).total == 1


# --- the keeper ------------------------------------------------------------------------------


@pytest.fixture
def runs(monkeypatch) -> list[int | None]:
    """The `since` of every evaluation the keeper asks for."""
    seen: list[int | None] = []
    original = rule_engine.evaluate

    def recording(session, rules, *, since=None):
        seen.append(since)
        return original(session, rules, since=since)

    monkeypatch.setattr(rule_engine, "evaluate", recording)
    return seen


def stricter(rules: RuleSet) -> RuleSet:
    """The same rules, but SSH-001 needs 50 failures instead of 5."""
    changed = tuple(
        rule.model_copy(update={"threshold": 50}) if rule.id == "SSH-001" else rule
        for rule in rules.rules
    )
    return RuleSet(changed)


def test_keeper_starts_over_the_first_time_and_then_goes_group_by_group(session, runs):
    keeper = AlertKeeper()
    load(session, "auth.log")
    assert keeper.refresh(session, SHIPPED, since=0).total == 6

    before = latest_event_id(session)
    load(session, "ufw.log")
    assert keeper.refresh(session, SHIPPED, since=before).total == 8
    assert runs == [None, before]
    assert session.get(State, "rules").value == rule_engine.rules_fingerprint(SHIPPED)


def test_keeper_starts_over_when_the_rules_are_not_the_ones_the_alerts_were_made_with(
    session, runs
):
    keeper = AlertKeeper()
    load(session)
    keeper.refresh(session, SHIPPED, since=0)

    latest = latest_event_id(session)
    outcome = keeper.refresh(session, stricter(SHIPPED), since=latest)
    assert runs == [None, None]
    # 24, 30 and 32 failures no longer reach the threshold; 71 still does.
    assert (outcome.total, outcome.removed) == (3, 3)

    keeper.refresh(session, stricter(SHIPPED), since=latest)
    assert runs == [None, None, latest]


def test_keeper_remembers_across_restarts_which_rules_the_alerts_were_made_with(session, runs):
    load(session)
    AlertKeeper().refresh(session, SHIPPED, since=0)
    latest = latest_event_id(session)

    AlertKeeper().refresh(session, load_rules(get_settings().rules_dir), since=latest)
    assert runs == [None, latest]  # equal rules, freshly loaded: no need to start over


def test_fingerprint_follows_the_rules_in_use():
    same = RuleSet(tuple(reversed(SHIPPED.rules)))
    switched_off = RuleSet(
        tuple(
            rule.model_copy(update={"enabled": rule.enabled and rule.id != "KW-001"})
            for rule in SHIPPED.rules
        )
    )
    without = RuleSet(tuple(rule for rule in SHIPPED.rules if rule.id != "KW-001"))

    assert rule_engine.rules_fingerprint(same) == rule_engine.rules_fingerprint(SHIPPED)
    assert rule_engine.rules_fingerprint(stricter(SHIPPED)) != rule_engine.rules_fingerprint(
        SHIPPED
    )
    assert rule_engine.rules_fingerprint(switched_off) == rule_engine.rules_fingerprint(without)
    assert rule_engine.rules_fingerprint(without) != rule_engine.rules_fingerprint(SHIPPED)


# --- through the application -----------------------------------------------------------------


def upload(client: TestClient, name: str) -> dict:
    files = {"file": (name, "\n".join(FILES[name]).encode())}
    return client.post("/ingest", files=files, data={"year": str(YEAR)}).json()


def test_second_upload_only_redoes_the_groups_it_touches(client, runs):
    assert upload(client, "auth.log")["alerts"] == 6
    assert upload(client, "ufw.log")["alerts"] == 8
    # The alerts were checked against the rules when the server started, so even
    # the first upload only has to look at what it brought.
    assert runs == [0, len(FILES["auth.log"])]

    client.post("/rules/reload")
    assert runs[2] is None  # a reload always starts over


@pytest.fixture
def rules_dir(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "rules"
    directory.mkdir()
    for path in get_settings().rules_dir.glob("*.yaml"):
        (directory / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setenv("LOG_ANALYZER_RULES_DIR", str(directory))
    get_settings.cache_clear()
    yield directory
    get_settings.cache_clear()


def test_restart_applies_rules_that_were_edited_while_the_server_was_down(rules_dir, engine):
    def session():
        with Session(engine, expire_on_commit=False) as database:
            yield database

    app.dependency_overrides[get_session] = session
    try:
        with TestClient(app) as first:
            assert upload(first, "auth.log")["alerts"] == 6

        path = rules_dir / "SSH-001.yaml"
        path.write_text(path.read_text().replace("threshold: 5", "threshold: 50"))

        with TestClient(app) as second:  # no reload, no upload: just started again
            alerts = second.get("/alerts").json()
            assert alerts["total"] == 3
            assert sorted(alert["rule_id"] for alert in alerts["items"]) == [
                "KW-001",
                "SSH-001",
                "SSH-002",
            ]
    finally:
        app.dependency_overrides.clear()


def test_server_starts_on_a_database_without_tables(caplog, tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_ANALYZER_DATABASE_URL", f"sqlite:///{tmp_path / 'empty.db'}")
    get_settings.cache_clear()
    from app.db import session_factory

    session_factory.cache_clear()
    try:
        with TestClient(app) as client:
            assert client.get("/health").status_code == 503
    finally:
        get_settings.cache_clear()
        session_factory.cache_clear()
    assert "alerts were not checked against the rules" in caplog.text
