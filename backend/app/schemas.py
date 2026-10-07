"""Shapes of the JSON the API returns."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.enums import Action, Level, Severity
from app.rules.schema import Rule


class EventBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime = Field(description="When the line was logged, in UTC.")
    host: str | None
    service: str | None = Field(description="The program that wrote the line.")
    level: Level
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    user: str | None
    action: Action | None = Field(description="Null when no pattern recognized the line.")
    message: str = Field(description="The line without timestamp, host and program.")
    raw: str = Field(description="The line exactly as it was read.")
    source_file: str
    line_no: int
    parsed: bool


class Highlight(BaseModel):
    """Why an event is evidence for an alert, and which part of its message shows it."""

    alert_id: int
    rule_id: str
    severity: Severity
    start: int | None = Field(
        description="First character of `message` to mark. Null: the line as a whole."
    )
    end: int | None = Field(description="One past the last character to mark.")


class EventOut(EventBase):
    highlights: list[Highlight] = []


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None = Field(
        description="Pass as `cursor` to get the next page. Null on the last page."
    )


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    rule_name: str
    severity: Severity
    group_by: str = Field(description="The event field the rule groups on, e.g. src_ip.")
    group_key: str = Field(description="That field's value for this alert.")
    first_seen: datetime
    last_seen: datetime
    count: int = Field(description="Number of evidence events.")
    summary: str
    events: list[EventOut] | None = Field(
        default=None, description="The first evidence events; only with `include_events`."
    )


class AlertList(BaseModel):
    items: list[AlertOut]
    total: int = Field(description="Number of alerts matching the filters, ignoring `limit`.")


class RuleErrorOut(BaseModel):
    file: str
    message: str


class RuleList(BaseModel):
    rules: list[Rule]
    errors: list[RuleErrorOut] = Field(description="Rule files that could not be loaded.")


class EvaluationOut(BaseModel):
    """What re-running the rules did to the stored alerts."""

    total: int
    created: int
    updated: int
    removed: int


class RuleReload(RuleList):
    alerts: EvaluationOut


class IngestReport(BaseModel):
    """`lines = parsed + unparsed + duplicates + conflicts`; blank lines are not counted."""

    source_file: str
    lines: int
    parsed: int = Field(description="Stored, and a pattern recognized the message.")
    unparsed: int = Field(description="Stored as-is because no pattern matched.")
    duplicates: int = Field(description="Already stored by an earlier upload of the file.")
    conflicts: int = Field(description="Line number already stored with different text.")
    alerts: int = Field(description="Alerts that exist once the rules have run again.")
