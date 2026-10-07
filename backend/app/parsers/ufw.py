"""UFW and iptables: the packet log lines the kernel writes for firewall rules.

    Sep  9 05:20:01 web-01 kernel: [19201.482913] [UFW BLOCK] IN=eth0 OUT= MAC=52:54:00:...
        SRC=198.51.100.150 DST=192.0.2.5 LEN=44 TTL=241 PROTO=TCP SPT=43210 DPT=23 SYN URGP=0

(one line in the log; wrapped here).

After an optional uptime stamp comes a prefix chosen by whoever wrote the
firewall rule, then ``KEY=value`` fields describing the packet. The prefix is
the only thing that says whether the packet was let through: UFW writes
``[UFW BLOCK]`` or ``[UFW ALLOW]``, hand-written iptables rules use prefixes
such as ``iptables-dropped:``.
"""

import re
from dataclasses import replace

from app.enums import Action, Level
from app.parsers.base import ParsedLine
from app.parsers.registry import register
from app.parsers.syslog import SyslogParser

_PACKET = re.compile(r"(?:\[\s*\d+\.\d+\]\s*)?(?P<prefix>.*?)\s*(?P<fields>IN=\S*\s.*)")
_BLOCKED = ("block", "drop", "reject", "deny")
_ALLOWED = ("allow", "accept")


def parse_fields(text: str) -> dict[str, str]:
    """The ``KEY=value`` pairs of a packet log. Bare flags such as SYN or DF are skipped."""
    return dict(token.split("=", 1) for token in text.split() if "=" in token)


def _verdict(prefix: str) -> Action | None:
    prefix = prefix.lower()
    if any(word in prefix for word in _BLOCKED):
        return Action.CONN_BLOCK
    if any(word in prefix for word in _ALLOWED):
        return Action.CONN_ALLOW
    return None


def _port(value: str | None) -> int | None:
    if value is None or not value.isdigit() or int(value) > 65535:
        return None
    return int(value)


@register
class UfwParser(SyslogParser):
    """Parser for ``/var/log/ufw.log`` and other files holding the kernel's packet logs."""

    name = "ufw"

    def recognize(self, entry: ParsedLine) -> ParsedLine:
        if entry.service != "kernel":
            return entry
        packet = _PACKET.fullmatch(entry.message)
        if packet is None:
            return entry
        fields = parse_fields(packet["fields"])
        if not fields.get("SRC") or not fields.get("DST"):
            return entry
        action = _verdict(packet["prefix"])
        # A packet whose fate the prefix does not tell (e.g. [UFW AUDIT]) keeps its
        # addresses and ports but stays unparsed.
        return replace(
            entry,
            action=action,
            level=Level.WARNING if action is Action.CONN_BLOCK else Level.INFO,
            src_ip=fields["SRC"],
            dst_ip=fields["DST"],
            src_port=_port(fields.get("SPT")),
            dst_port=_port(fields.get("DPT")),
        )
