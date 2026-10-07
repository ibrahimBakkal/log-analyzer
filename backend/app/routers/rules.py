"""GET /rules and POST /rules/reload: the detection rules in use."""

from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.config import get_settings
from app.live import Hub
from app.routers import SessionDep
from app.rules import AlertKeeper, RuleSet, load_rules
from app.schemas import EvaluationOut, RuleErrorOut, RuleList, RuleReload

router = APIRouter(tags=["rules"])


def get_rules(request: Request) -> RuleSet:
    """The rules loaded at startup or by the last reload."""
    return request.app.state.rules


def get_alert_keeper(request: Request) -> AlertKeeper:
    return request.app.state.alerts


RulesDep = Annotated[RuleSet, Depends(get_rules)]
AlertKeeperDep = Annotated[AlertKeeper, Depends(get_alert_keeper)]


def _errors(rules: RuleSet) -> list[RuleErrorOut]:
    return [RuleErrorOut(file=error.file, message=error.message) for error in rules.errors]


@router.get("/rules")
def list_rules(rules: RulesDep) -> RuleList:
    """The loaded rules, and the rule files that were rejected and why."""
    return RuleList(rules=list(rules.rules), errors=_errors(rules))


@router.post("/rules/reload")
def reload_rules(request: Request, session: SessionDep) -> RuleReload:
    """Read the rule files again and re-run the rules over all stored events.

    Alerts always reflect the current rules: alerts of a rule that was removed,
    disabled or no longer loads disappear.
    """
    rules = load_rules(get_settings().rules_dir)
    request.app.state.rules = rules
    evaluation = get_alert_keeper(request).refresh(session, rules, since=None)
    hub: Hub = request.app.state.hub
    hub.publish("update", {"reason": "rules", "added": 0, "alerts": evaluation.total})
    return RuleReload(
        rules=list(rules.rules), errors=_errors(rules), alerts=EvaluationOut(**asdict(evaluation))
    )
