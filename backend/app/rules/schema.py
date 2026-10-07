"""Detection rules as they are written in YAML.

Every rule has the common fields of :class:`RuleBase`; ``type`` selects the
kind of rule and with it the remaining fields. Unknown fields are errors, so a
misspelled option is reported instead of being silently ignored.
"""

import re
from string import Formatter
from typing import Annotated, Any, ClassVar, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyNetwork,
    TypeAdapter,
    field_validator,
    model_validator,
)

from app.enums import Action, Level, Severity

GroupField = Literal["src_ip", "user", "host", "service"]


class EventFilter(BaseModel):
    """Field values an event must have for a rule to look at it.

    Each field takes one value or a list of acceptable values. A field that is
    left out does not restrict anything.
    """

    model_config = ConfigDict(extra="forbid")

    action: list[Action] = []
    service: list[str] = []
    host: list[str] = []
    user: list[str] = []
    level: list[Level] = []

    @field_validator("*", mode="before")
    @classmethod
    def _one_or_many(cls, value: Any) -> Any:
        return value if isinstance(value, list) else [value]


class RuleBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Placeholders a ``summary`` may use, beyond those every rule offers.
    summary_fields: ClassVar[frozenset[str]] = frozenset()
    default_summary: ClassVar[str]

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    name: str = Field(min_length=1)
    description: str = ""
    severity: Severity
    enabled: bool = True
    match: EventFilter = Field(default_factory=EventFilter)
    allowlist: list[IPvAnyNetwork] = Field(
        default=[], description="Source addresses or networks the rule ignores."
    )
    cooldown_seconds: int = Field(
        default=300,
        ge=0,
        description="Further matches this soon after an alert's last event join that alert.",
    )
    summary: str | None = Field(
        default=None,
        description="Alert text. Placeholders: {key}, {count}, {seconds}, {rule_id}, {rule_name}.",
    )

    @model_validator(mode="after")
    def _summary_uses_known_placeholders(self) -> "RuleBase":
        allowed = {"key", "count", "seconds", "rule_id", "rule_name"} | self.summary_fields
        try:
            used = {name for _, name, _, _ in Formatter().parse(self.summary_template) if name}
        except ValueError as error:
            raise ValueError(f"summary: {error}") from None
        if unknown := sorted(used - allowed):
            raise ValueError(
                f"summary: unknown placeholder {{{unknown[0]}}} (available: "
                + ", ".join(f"{{{name}}}" for name in sorted(allowed))
                + ")"
            )
        return self

    @property
    def summary_template(self) -> str:
        return self.summary or self.default_summary


class KeywordRule(RuleBase):
    """Alerts on lines whose message contains certain text."""

    default_summary: ClassVar[str] = "{rule_name}: {key} üzerinde {count} satır"

    type: Literal["keyword"]
    keywords: list[Annotated[str, Field(min_length=1)]] = Field(
        default=[], description="Texts to look for, ignoring case."
    )
    regex: str | None = Field(default=None, description="A regular expression to look for.")
    group_by: GroupField = "host"

    @field_validator("regex")
    @classmethod
    def _regex_compiles(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as error:
                raise ValueError(f"not a valid regular expression: {error}") from None
        return value

    @model_validator(mode="after")
    def _has_something_to_look_for(self) -> "KeywordRule":
        if not self.keywords and self.regex is None:
            raise ValueError("give at least one of 'keywords' or 'regex'")
        return self


class ThresholdRule(RuleBase):
    """Alerts when one source produces many matching events in a short time."""

    summary_fields: ClassVar[frozenset[str]] = frozenset({"threshold", "window_seconds"})
    default_summary: ClassVar[str] = "{rule_name}: {key}, {seconds} sn içinde {count} olay"

    type: Literal["threshold"]
    threshold: int = Field(ge=1, description="This many matching events ...")
    window_seconds: int = Field(ge=1, description="... within this many seconds.")
    group_by: GroupField = "src_ip"


Rule = Annotated[KeywordRule | ThresholdRule, Field(discriminator="type")]
RULE = TypeAdapter(Rule)
