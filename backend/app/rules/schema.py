"""Detection rules as they are written in YAML.

Every rule has the common fields of :class:`RuleBase`; ``type`` selects the
kind of rule and with it the remaining fields. Unknown fields are errors, so a
misspelled option is reported instead of being silently ignored.
"""

import re
from string import Formatter
from typing import Annotated, Any, ClassVar, Literal

from pydantic import (
    AfterValidator,
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


def keyword_parts(keyword: str) -> list[str]:
    r"""The pieces of text a keyword is made of; ``*`` between them stands for any text.

    ``wget *; chmod +x`` is "wget ", then anything, then "; chmod +x". An
    asterisk at either end changes nothing, since a keyword is looked for
    anywhere in a line. ``\*`` is an asterisk and ``\\`` a backslash; any other
    backslash is just that. This is how Sigma writes keywords, so theirs can be
    used as they are.
    """
    parts = [""]
    position = 0
    while position < len(keyword):
        character = keyword[position]
        if character == "\\" and keyword[position + 1 : position + 2] in ("*", "\\"):
            parts[-1] += keyword[position + 1]
            position += 1
        elif character == "*":
            parts.append("")
        else:
            parts[-1] += character
        position += 1
    return [part for part in parts if part]


def _looks_for_something(keyword: str) -> str:
    if not keyword_parts(keyword):
        raise ValueError(f"{keyword!r} has nothing to look for")
    return keyword


Keyword = Annotated[str, AfterValidator(_looks_for_something)]


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
    dst_port: list[Annotated[int, Field(ge=0, le=65535)]] = []

    @field_validator("*", mode="before")
    @classmethod
    def _one_or_many(cls, value: Any) -> Any:
        return value if isinstance(value, list) else [value]

    def matches(self, event: Any) -> bool:
        """True if *event* (anything with these fields as attributes) passes the filter."""
        return all(not accepted or getattr(event, name) in accepted for name, accepted in self)

    @property
    def restricts(self) -> bool:
        return any(accepted for _, accepted in self)


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

    # Where a rule comes from. None of this changes what the rule does; it is
    # shown with the rule and with its alerts.
    author: str = ""
    source: str = Field(default="", description="Address of the rule this one was made from.")
    license: str = ""
    references: list[str] = Field(default=[], description="Further reading: articles, advisories.")
    tags: list[str] = Field(default=[], description="For example MITRE ATT&CK: attack.t1110.")
    false_positives: list[str] = Field(
        default=[], description="Harmless things known to set the rule off."
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
    """Alerts on lines whose message contains certain text.

    A line counts if it contains one of ``keywords`` (or matches ``regex``),
    and one keyword of every entry of ``require``, and none of ``exclude``.
    Case is ignored, and ``*`` in a keyword stands for any text. Keywords are
    looked for in the name of the program that wrote the line as well as in
    its message; the regex in the message only.
    """

    default_summary: ClassVar[str] = "{rule_name}: {key} üzerinde {count} satır"

    type: Literal["keyword"]
    keywords: list[Keyword] = Field(
        default=[], description="Texts to look for: one of them is enough."
    )
    regex: str | None = Field(default=None, description="A regular expression to look for.")
    require: list[list[Keyword]] = Field(
        default=[],
        description="Texts that must be there as well. Each entry is one keyword, "
        "or a list of keywords of which one is enough.",
    )
    exclude: list[Keyword] = Field(
        default=[], description="Texts that rule a line out, whatever else it contains."
    )
    group_by: GroupField = "host"

    @field_validator("require", mode="before")
    @classmethod
    def _one_or_several(cls, value: Any) -> Any:
        if not isinstance(value, list):
            return value
        return [entry if isinstance(entry, list) else [entry] for entry in value]

    @field_validator("require")
    @classmethod
    def _no_empty_entries(cls, value: list[list[str]]) -> list[list[str]]:
        if any(not entry for entry in value):
            raise ValueError("an entry without keywords can never be satisfied")
        return value

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


class SequenceStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    match: EventFilter
    count: int = Field(default=1, ge=1, description="How many matching events the step needs.")

    @model_validator(mode="after")
    def _matches_something_specific(self) -> "SequenceStep":
        if not self.match.restricts:
            raise ValueError("match: a step must say which events it waits for")
        return self


class SequenceRule(RuleBase):
    """Alerts when one source goes through a series of steps in order, quickly enough."""

    summary_fields: ClassVar[frozenset[str]] = frozenset({"within_seconds"})
    default_summary: ClassVar[str] = "{rule_name}: {key}, {seconds} sn içinde {count} olay"

    type: Literal["sequence"]
    steps: list[SequenceStep] = Field(min_length=2)
    within_seconds: int = Field(
        ge=1, description="All steps must fit in less than this many seconds."
    )
    group_by: GroupField = "src_ip"


class PortScanRule(RuleBase):
    """Alerts when one source tries many different destination ports in a short time."""

    summary_fields: ClassVar[frozenset[str]] = frozenset({"ports", "min_ports", "window_seconds"})
    default_summary: ClassVar[str] = "{rule_name}: {key}, {seconds} sn içinde {ports} farklı port"

    type: Literal["port_scan"]
    min_ports: int = Field(ge=2, description="This many different destination ports ...")
    window_seconds: int = Field(ge=1, description="... within this many seconds.")
    group_by: GroupField = "src_ip"


class RarePortRule(RuleBase):
    """Alerts on connections to ports that should not be in use.

    ``watchlist``: the listed ports are the suspicious ones.
    ``allowlist``: the listed ports are the expected ones; every other port is suspicious.
    """

    summary_fields: ClassVar[frozenset[str]] = frozenset({"ports"})
    default_summary: ClassVar[str] = "{rule_name}: {key}, {ports} beklenmeyen port"

    type: Literal["rare_port"]
    mode: Literal["watchlist", "allowlist"]
    ports: list[Annotated[int, Field(ge=0, le=65535)]] = Field(min_length=1)
    group_by: GroupField = "src_ip"


Rule = Annotated[
    KeywordRule | ThresholdRule | SequenceRule | PortScanRule | RarePortRule,
    Field(discriminator="type"),
]
RULE = TypeAdapter(Rule)
