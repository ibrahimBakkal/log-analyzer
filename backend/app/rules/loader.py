"""Reading rule files from a directory.

One YAML file holds one rule. A file that cannot be used never stops the
others from loading: it is reported with a message that says what is wrong.
"""

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.rules.schema import RULE, Rule


@dataclass(frozen=True)
class RuleError:
    file: str
    message: str


@dataclass(frozen=True)
class RuleSet:
    """The rules that loaded, in file-name order, and the files that did not."""

    rules: tuple[Rule, ...] = ()
    errors: tuple[RuleError, ...] = ()

    @property
    def enabled(self) -> tuple[Rule, ...]:
        return tuple(rule for rule in self.rules if rule.enabled)


def load_rules(directory: Path) -> RuleSet:
    if not directory.is_dir():
        return RuleSet(errors=(RuleError(str(directory), "rules directory not found"),))

    rules: dict[str, Rule] = {}
    sources: dict[str, str] = {}
    errors: list[RuleError] = []
    files = sorted(path for path in directory.iterdir() if path.suffix in {".yaml", ".yml"})
    for path in files:
        try:
            rule = _load_file(path)
        except ValueError as error:
            errors.append(RuleError(path.name, str(error)))
            continue
        if rule.id in rules:
            errors.append(
                RuleError(path.name, f"id {rule.id!r} is already used by {sources[rule.id]}")
            )
            continue
        rules[rule.id] = rule
        sources[rule.id] = path.name
    return RuleSet(tuple(rules.values()), tuple(errors))


def _load_file(path: Path) -> Rule:
    """Parse and validate one rule file. Raises ``ValueError`` with a readable reason."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.MarkedYAMLError as error:
        where = f" (line {error.problem_mark.line + 1})" if error.problem_mark else ""
        raise ValueError(f"not valid YAML{where}: {error.problem}") from None
    except (yaml.YAMLError, UnicodeDecodeError, OSError) as error:
        raise ValueError(f"cannot be read: {error}") from None
    if not isinstance(data, dict):
        raise ValueError("expected the fields of one rule (id, name, type, ...)")
    try:
        return RULE.validate_python(data)
    except ValidationError as error:
        raise ValueError(_explain(error, data.get("type"))) from None


def _explain(error: ValidationError, rule_type: object) -> str:
    """Turn pydantic's error list into ``field: what is wrong`` phrases."""
    problems = []
    for item in error.errors():
        # Errors inside a typed rule are located as (type, field, ...); the type is noise.
        # Only the first part is dropped: a threshold rule has a field named "threshold".
        parts = item["loc"][1:] if item["loc"][:1] == (rule_type,) else item["loc"]
        location = [str(part) for part in parts]
        message = item["msg"].removeprefix("Value error, ")
        field = ".".join(location)
        problems.append(
            f"{field}: {message}" if field and not message.startswith(field) else message
        )
    return "; ".join(problems)
