"""Parser registry: maps a name such as ``"auth"`` to the class that reads that format."""

from typing import Any, TypeVar

from app.parsers.base import BaseParser

P = TypeVar("P", bound=type[BaseParser])

_PARSERS: dict[str, type[BaseParser]] = {}


class UnknownParserError(LookupError):
    """No parser is registered under the requested name."""


def register(cls: P) -> P:
    """Class decorator that makes a parser available by its ``name``."""
    if cls.name in _PARSERS:
        raise ValueError(f"a parser named {cls.name!r} is already registered")
    _PARSERS[cls.name] = cls
    return cls


def parser_names() -> list[str]:
    return sorted(_PARSERS)


def create_parser(name: str, **options: Any) -> BaseParser:
    """Create a fresh parser for one file. *options* are passed to its constructor."""
    try:
        cls = _PARSERS[name]
    except KeyError:
        known = ", ".join(parser_names())
        raise UnknownParserError(f"unknown parser {name!r} (available: {known})") from None
    return cls(**options)
