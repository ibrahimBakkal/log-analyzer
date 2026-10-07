#!/usr/bin/env python3
"""Measure what the shipped rules catch, what they miss and what they wrongly flag.

Writes a log in which every source address plays one known part: an attack of
some kind and intensity, or something harmless that resembles one. The rules
run over it, and each address is then looked up among the alerts. Because the
parts are known, every alert is either right or wrong, and every address
without one either rightly or wrongly so. The result is printed as Markdown.

The parts are chosen to straddle the rules' limits (a scan of 14 ports and one
of 15, a login after 4 failures and one after 5), so the tables show where each
rule stops seeing, which is the point; the overall percentages follow from how
many addresses were given each part and mean little by themselves.

Usage (in the backend's virtual environment)::

    python samples/measure.py
    python samples/measure.py --seed 7
"""

import argparse
import random
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.config import get_settings
from app.db import Base, make_engine
from app.ingest import ingest_lines
from app.models import Alert
from app.parsers import create_parser
from app.rules import evaluate, load_rules
from benchmark import HOST, MONTHS, dots, failed, packet

START = datetime(2026, 6, 1)
DAYS = 7
USERS = ("root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "deploy", "pi", "user")
STAFF = ("alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi")


@dataclass
class Part:
    """What one source address does in the log."""

    kind: str  # the scenario, as the tables name it
    variant: str  # what distinguishes it from others of its kind
    malicious: bool
    address: str = ""
    lines: list[tuple[float, str]] = field(default_factory=list)  # (seconds, text after the host)


def accepted(rng: random.Random, user: str, source: str) -> str:
    pid, port = rng.randint(1000, 99999), rng.randint(1024, 65535)
    return f"sshd[{pid}]: Accepted password for {user} from {source} port {port} ssh2"


def invalid(rng: random.Random, user: str, source: str) -> str:
    pid, port = rng.randint(1000, 99999), rng.randint(1024, 65535)
    return f"sshd[{pid}]: Invalid user {user} from {source} port {port}"


def paced(rng: random.Random, count: int, gap: float, jitter: float = 0.04) -> Iterator[float]:
    """*count* moments, *gap* seconds apart give or take a little."""
    now = 0.0
    for _ in range(count):
        yield now
        now += gap * rng.uniform(1 - jitter, 1 + jitter)


Script = Callable[[random.Random, str], list[tuple[float, str]]]


def brute_force(attempts: int, gap: float) -> Script:
    def script(rng: random.Random, source: str) -> list[tuple[float, str]]:
        user = rng.choice(USERS)
        return [(moment, failed(rng, user, source)) for moment in paced(rng, attempts, gap)]

    return script


def fast_brute_force(rng: random.Random, source: str) -> list[tuple[float, str]]:
    return brute_force(rng.randint(20, 150), rng.uniform(0.2, 2.0))(rng, source)


def name_sweep(with_password: bool) -> Script:
    """Thirty account names that do not exist, one try each."""

    def script(rng: random.Random, source: str) -> list[tuple[float, str]]:
        lines = []
        for number, moment in enumerate(paced(rng, 30, 3.0, jitter=0.4)):
            user = f"{rng.choice(USERS)}{number}"
            lines.append((moment, invalid(rng, user, source)))
            if with_password:
                lines.append((moment + 1, failed(rng, f"invalid user {user}", source)))
        return lines

    return script


def guessed_login(failures: int) -> Script:
    """Some wrong passwords, then the right one."""

    def script(rng: random.Random, source: str) -> list[tuple[float, str]]:
        user = rng.choice(STAFF)
        moments = list(paced(rng, failures + 1, 5.0, jitter=0.4))
        lines = [(moment, failed(rng, user, source)) for moment in moments[:-1]]
        return [*lines, (moments[-1], accepted(rng, user, source))]

    return script


def shared_exit(people: int) -> Script:
    """An office behind one address: at nine, several people mistype once and then log in."""

    def script(rng: random.Random, source: str) -> list[tuple[float, str]]:
        lines = []
        for user in rng.sample(STAFF, people):
            arrives = rng.uniform(0, 40)
            lines.append((arrives, failed(rng, user, source)))
            lines.append((arrives + rng.uniform(4, 9), accepted(rng, user, source)))
        return sorted(lines)

    return script


def port_scan(ports: int, gap: float) -> Script:
    def script(rng: random.Random, source: str) -> list[tuple[float, str]]:
        targets = rng.sample(range(1, 10000), ports)
        return [
            (moment, packet(rng, "BLOCK", source, port))
            for moment, port in zip(paced(rng, ports, gap), targets, strict=True)
        ]

    return script


PROBED = (22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443) + (
    9090,
    9100,
    9200,
    11211,
    15672,
    27017,
)


def probe_rounds(ports: int) -> Script:
    """A monitoring machine: the same ports, all within seconds, every ten minutes for a day."""

    def script(rng: random.Random, source: str) -> list[tuple[float, str]]:
        targets = rng.sample(PROBED, ports)
        lines = []
        for round_number in range(144):
            for number, port in enumerate(targets):
                verdict = "ALLOW" if port in (22, 80, 443) else "BLOCK"
                moment = round_number * 600 + number * 0.2
                lines.append((moment, packet(rng, verdict, source, port)))
        return lines

    return script


def open_desktop(rng: random.Random, source: str) -> list[tuple[float, str]]:
    """Connections the firewall lets through to a remote desktop port left open."""
    return [
        (moment, packet(rng, "ALLOW", source, 3389)) for moment in paced(rng, rng.randint(1, 3), 20)
    ]


def stray_attempts(rng: random.Random, source: str) -> list[tuple[float, str]]:
    """The internet's background: a try or two, hours apart."""
    return [
        (moment, failed(rng, rng.choice(USERS), source))
        for moment in paced(rng, rng.randint(1, 3), 7200, jitter=0.5)
    ]


def visitor(rng: random.Random, source: str) -> list[tuple[float, str]]:
    return [
        (moment, packet(rng, "ALLOW", source, rng.choice((80, 443))))
        for moment in paced(rng, rng.randint(1, 4), 900, jitter=0.5)
    ]


# (kind, variant, malicious, how many addresses, what they do)
CAST: list[tuple[str, str, bool, int, Script]] = [
    ("Hızlı kaba kuvvet", "0,2-2 sn arayla 20-150 deneme", True, 40, fast_brute_force),
    *[
        ("Aralıklı kaba kuvvet", f"{gap} sn arayla 40 deneme", True, 10, brute_force(40, gap))
        for gap in (5, 10, 14, 16, 30, 120, 1500)
    ],
    ("Kullanıcı adı taraması", "her adla bir parola denemesi", True, 15, name_sweep(True)),
    ("Kullanıcı adı taraması", "parola denemeden bağlantıyı kesiyor", True, 15, name_sweep(False)),
    *[
        (
            "Tahmin edilen parola",
            f"{failures} başarısız denemeden sonra giriş",
            True,
            8,
            guessed_login(failures),
        )
        for failures in (1, 3, 4, 5, 8, 25)
    ],  # fmt: skip
    *[
        ("Port taraması", f"{ports} port, {gap:g} sn arayla", True, 4, port_scan(ports, gap))
        for ports in (5, 10, 14, 15, 30, 100)
        for gap in (0.3, 3, 5, 30)
    ],
    ("Açık kalmış RDP portuna bağlantı", "1-3 bağlantı", True, 10, open_desktop),
    *[
        (
            "Parolasını yanlış yazan kullanıcı",
            f"{failures} yanlış, sonra doğru",
            False,
            10,
            guessed_login(failures),
        )
        for failures in (1, 2, 4, 5, 7)
    ],  # fmt: skip
    *[
        (
            "Tek adresten çıkan ofis",
            f"{people} kişi birer kez yanlış yazıyor",
            False,
            5,
            shared_exit(people),
        )
        for people in (3, 4, 5, 8)
    ],  # fmt: skip
    ("İzleme sunucusu", "10 dakikada bir 8 port", False, 5, probe_rounds(8)),
    ("İzleme sunucusu", "10 dakikada bir 20 port", False, 5, probe_rounds(20)),
    ("İnternet gürültüsü", "saatler arayla 1-3 deneme", False, 400, stray_attempts),
    ("Site ziyaretçisi", "80 ve 443'e birkaç bağlantı", False, 400, visitor),
]


def cast(seed: int) -> list[Part]:
    """Every part with an address of its own, placed somewhere in the week."""
    rng = random.Random(seed)
    parts = []
    for kind, variant, malicious, count, script in CAST:
        for _ in range(count):
            number = len(parts) + 1
            address = f"198.18.{number // 250}.{number % 250 + 1}"
            begins = rng.uniform(0, DAYS * 86400 - 90000)
            lines = [(begins + moment, text) for moment, text in script(rng, address)]
            parts.append(Part(kind, variant, malicious, address, lines))
    return parts


def log_lines(parts: list[Part]) -> list[str]:
    """All parts in one log, in time order, as syslog writes it."""
    everything = sorted(line for part in parts for line in part.lines)
    lines = []
    for seconds, text in everything:
        moment = START + timedelta(seconds=seconds)
        lines.append(f"{MONTHS[moment.month - 1]} {moment.day:2d} {moment:%H:%M:%S} {HOST} {text}")
    return lines


def alerts_by_address(lines: list[str]) -> tuple[dict[str, set[str]], Counter[str]]:
    """Run the shipped rules over *lines*: the rules that alerted, per address, and per rule."""
    engine = make_engine("sqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    rules = load_rules(get_settings().rules_dir)
    found: dict[str, set[str]] = defaultdict(set)
    with Session(engine, expire_on_commit=False) as session:
        ingest_lines(
            session,
            enumerate(lines, start=1),
            source_file="measure.log",
            parser=create_parser("auto", year=START.year),
        )
        evaluate(session, rules.enabled)
        per_rule = Counter[str]()
        for rule_id, group_key in session.execute(select(Alert.rule_id, Alert.group_key)):
            found[group_key].add(rule_id)
            per_rule[rule_id] += 1
    engine.dispose()
    return found, per_rule


def percent(part: int, whole: int) -> str:
    return f"%{100 * part / whole:.0f}" if whole else "-"


def report(seed: int) -> None:
    parts = cast(seed)
    lines = log_lines(parts)
    found, per_rule = alerts_by_address(lines)
    addresses = {part.address for part in parts}
    elsewhere = sorted(key for key in found if key not in addresses)

    attacks = [part for part in parts if part.malicious]
    harmless = [part for part in parts if not part.malicious]
    caught = sum(part.address in found for part in attacks)
    flagged = sum(part.address in found for part in harmless)

    print(
        f"{dots(len(lines))} satır, {dots(len(parts))} kaynak adres, {DAYS} gün. Tohum: {seed}.\n"
    )
    print("| | Adres | Uyarı aldı | Almadı |")
    print("|---|---|---|---|")
    print(
        f"| Saldırı | {len(attacks)} | {caught} (yakalandı) | {len(attacks) - caught} (kaçırıldı) |"
    )
    print(
        f"| Zararsız | {len(harmless)} | {flagged} (yanlış alarm) | "
        f"{len(harmless) - flagged} (doğru) |"
    )
    print()
    print(
        f"Yakalama oranı (recall): {percent(caught, len(attacks))}. "
        f"Uyarı alan adreslerin saldırgan olma oranı (precision): "
        f"{percent(caught, caught + flagged)}."
    )
    if elsewhere:
        print(f"\nHiçbir adrese ait olmayan uyarılar: {', '.join(elsewhere)}")

    for title, chosen in (("Saldırılar", attacks), ("Zararsız davranışlar", harmless)):
        print(f"\n### {title}\n")
        print("| Davranış | Ayrıntı | Adres | Uyarı alan | Uyaran kurallar |")
        print("|---|---|---|---|---|")
        groups: dict[tuple[str, str], list[Part]] = defaultdict(list)
        for part in chosen:
            groups[part.kind, part.variant].append(part)
        for (kind, variant), members in groups.items():
            alerted = [part for part in members if part.address in found]
            rules = sorted({rule for part in alerted for rule in found[part.address]})
            print(
                f"| {kind} | {variant} | {len(members)} | {len(alerted)} | "
                f"{', '.join(rules) or '-'} |"
            )

    print("\n### Kural başına uyarı sayısı\n")
    print("| Kural | Uyarı |")
    print("|---|---|")
    for rule_id, count in sorted(per_rule.items()):
        print(f"| {rule_id} | {count} |")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seed", type=int, default=1)
    report(parser.parse_args().seed)


if __name__ == "__main__":
    main()
