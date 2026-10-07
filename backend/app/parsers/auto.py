"""Any syslog file: recognizes the lines of every format the other parsers know.

Syslog files share one line format and differ only in which programs write to
them. ``/var/log/syslog`` may hold sshd lines next to the kernel's packet log,
and whoever uploads ``ufw.log`` should not have to say so first. This parser
asks each of the specific parsers in turn and takes the first answer.
"""

from typing import Any, ClassVar

from app.parsers.auth import AuthLogParser
from app.parsers.base import ParsedLine
from app.parsers.registry import register
from app.parsers.syslog import SyslogParser
from app.parsers.ufw import UfwParser


@register
class AutoParser(SyslogParser):
    """Parser for syslog files of any content. The default for uploads."""

    name = "auto"
    PARSERS: ClassVar[tuple[type[SyslogParser], ...]] = (AuthLogParser, UfwParser)

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        self._recognizers = [parser(**options) for parser in self.PARSERS]

    def recognize(self, entry: ParsedLine) -> ParsedLine:
        for parser in self._recognizers:
            recognized = parser.recognize(entry)
            if recognized is not entry:
                return recognized
        return entry
