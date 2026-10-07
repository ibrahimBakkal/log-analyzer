"""Log format parsers. Importing this package registers the built-in ones."""

from app.parsers import auth, auto, ufw  # noqa: F401  (registers the parsers)
from app.parsers.base import BaseParser, ParsedLine
from app.parsers.registry import UnknownParserError, create_parser, parser_names, register

__all__ = [
    "BaseParser",
    "ParsedLine",
    "UnknownParserError",
    "create_parser",
    "parser_names",
    "register",
]
