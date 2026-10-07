#!/usr/bin/env python3
"""Measure how the backend copes with a large log: loading, rules, and the API.

Writes a synthetic log of the wanted size (a busy month on one server: SSH
logins and failures, cron, the firewall's packet log, with brute-force bursts
and port scans mixed in), loads it into a fresh SQLite file through the same
code an upload runs, lets the rules run, and times the API calls the web
interface makes. The result is printed as Markdown tables.

Source addresses come from 198.18.0.0/15, the range RFC 2544 reserves for
benchmarks: a hundred thousand addresses that belong to nobody.

Usage (in the backend's virtual environment)::

    python samples/benchmark.py                     # one million lines
    python samples/benchmark.py --lines 100000      # a quicker look
    python samples/benchmark.py --keep /tmp/bench   # keep the log and the database
"""

import argparse
import random
import resource
import statistics
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import Base, get_session, make_engine
from app.ingest import Ingestor, ingest_lines, open_log, read_lines
from app.main import app
from app.models import Alert, Event
from app.parsers import create_parser
from app.rules import AlertKeeper, evaluate, latest_event_id, load_rules

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
START = datetime(2026, 6, 1)
DAYS = 30
HOST = "web-01"
SERVER = "192.0.2.5"
USERS = ("root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "deploy", "pi", "user")
STAFF = (("alice", "192.0.2.10"), ("bob", "192.0.2.11"), ("deploy", "192.0.2.50"))
PORTS = (21, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443)
MAC = "52:54:00:12:34:56:52:54:00:65:43:21:08:00"


def stranger(rng: random.Random) -> str:
    """An address out of 198.18.0.0/15."""
    return f"198.{rng.choice((18, 19))}.{rng.randrange(256)}.{rng.randrange(1, 255)}"


def packet(rng: random.Random, verdict: str, source: str, port: int) -> str:
    return (
        f"kernel: [{rng.uniform(1000, 900000):.6f}] [UFW {verdict}] IN=eth0 OUT= MAC={MAC} "
        f"SRC={source} DST={SERVER} LEN=44 TOS=0x00 PREC=0x00 TTL={rng.randint(40, 250)} "
        f"ID={rng.randint(1, 65535)} PROTO=TCP SPT={rng.randint(1024, 65535)} DPT={port} "
        "WINDOW=1024 RES=0x00 SYN URGP=0"
    )


def failed(rng: random.Random, user: str, source: str) -> str:
    pid, port = rng.randint(1000, 99999), rng.randint(1024, 65535)
    return f"sshd[{pid}]: Failed password for {user} from {source} port {port} ssh2"


def ordinary(rng: random.Random) -> str:
    """One line of a server's everyday log."""
    kind = rng.random()
    pid, port = rng.randint(1000, 99999), rng.randint(1024, 65535)
    if kind < 0.30:
        return failed(rng, rng.choice(USERS), stranger(rng))
    if kind < 0.40:
        user = f"{rng.choice(USERS)}{rng.randint(1, 99)}"
        return f"sshd[{pid}]: Invalid user {user} from {stranger(rng)} port {port}"
    if kind < 0.50:
        return (
            f"sshd[{pid}]: Connection closed by authenticating user root "
            f"{stranger(rng)} port {port} [preauth]"
        )
    if kind < 0.55:
        user, source = rng.choice(STAFF)
        return (
            f"sshd[{pid}]: Accepted publickey for {user} from {source} port {port} "
            "ssh2: ED25519 SHA256:benchmark"
        )
    if kind < 0.60:
        user, _ = rng.choice(STAFF)
        return (
            f"sudo:    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
            "COMMAND=/usr/bin/systemctl status nginx"
        )
    if kind < 0.70:
        return f"CRON[{pid}]: pam_unix(cron:session): session opened for user root(uid=0)"
    if kind < 0.88:
        return packet(rng, "BLOCK", stranger(rng), rng.choice(PORTS))
    return packet(rng, "ALLOW", stranger(rng), rng.choice((22, 80, 443)))


def synthetic_lines(count: int, seed: int = 1, start: datetime = START) -> Iterator[str]:
    """*count* log lines in time order, spread over DAYS days from *start*."""
    rng = random.Random(seed)
    step = DAYS * 86400 / count  # average seconds between two lines
    now = 0.0
    burst: list[str] = []  # lines of an attack in progress

    def stamp() -> str:
        moment = start + timedelta(seconds=now)
        return f"{MONTHS[moment.month - 1]} {moment.day:2d} {moment:%H:%M:%S} {HOST} "

    produced = 0
    while produced < count:
        if burst:
            now += rng.uniform(0.0, 0.8)
            yield stamp() + burst.pop()
            produced += 1
            continue
        now += rng.expovariate(1 / step)
        kind = rng.random()
        if kind < 0.0004:  # a brute-force burst against one account
            source, user = stranger(rng), rng.choice(USERS)
            burst = [failed(rng, user, source) for _ in range(rng.randint(20, 150))]
            if rng.random() < 0.05:  # now and then one gets in
                burst.insert(
                    0, f"sshd[4242]: Accepted password for {user} from {source} port 40000 ssh2"
                )
        elif kind < 0.0006:  # a port scan
            source = stranger(rng)
            burst = [packet(rng, "BLOCK", source, port) for port in rng.sample(range(1, 10000), 80)]
        else:
            yield stamp() + ordinary(rng)
            produced += 1


def later_lines(count: int, after: datetime, seed: int = 2) -> list[str]:
    """*count* more ordinary lines, a second apart, as a followed file would grow."""
    rng = random.Random(seed)
    lines = []
    for number in range(1, count + 1):
        moment = after + timedelta(seconds=number)
        stamp = f"{MONTHS[moment.month - 1]} {moment.day:2d} {moment:%H:%M:%S} {HOST} "
        lines.append(stamp + ordinary(rng))
    return lines


def timed(action: Callable[[], Any]) -> tuple[float, Any]:
    started = time.perf_counter()
    result = action()
    return time.perf_counter() - started, result


def dots(number: float) -> str:
    """1234567 -> 1.234.567, the way the rest of the documentation writes numbers."""
    return f"{number:,.0f}".replace(",", ".")


def measure_api(client: TestClient, path: str, params: dict[str, Any], repeat: int) -> str:
    durations = []
    size = 0
    for _ in range(repeat):
        started = time.perf_counter()
        response = client.get(path, params=params)
        durations.append((time.perf_counter() - started) * 1000)
        response.raise_for_status()
        size = len(response.content)
    return f"{statistics.median(durations):.0f} ms | {max(durations):.0f} ms | {size / 1024:.0f} kB"


def load(session: Session, log: Path) -> tuple[float, Any]:
    with log.open("rb") as stream:
        return timed(
            lambda: ingest_lines(
                session,
                read_lines(open_log(stream)),
                source_file=log.name,
                parser=create_parser("auto", year=START.year),
            )
        )


def run(lines: int, folder: Path, repeat: int) -> None:
    log = folder / "bench.log"
    database = folder / "bench.db"
    database.unlink(missing_ok=True)

    seconds, _ = timed(
        lambda: log.write_text("".join(f"{line}\n" for line in synthetic_lines(lines)))
    )
    megabytes = log.stat().st_size / 1e6
    print(f"## {dots(lines)} satır\n")
    print(f"Log dosyası: {megabytes:.0f} MB, {seconds:.1f} sn içinde üretildi.\n")

    engine = make_engine(f"sqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)
    rules = load_rules(get_settings().rules_dir)
    keeper = AlertKeeper()

    with Session(engine, expire_on_commit=False) as session:
        load_seconds, result = load(session, log)
        assert result.lines == lines and result.conflicts == result.duplicates == 0
        rule_seconds, evaluation = timed(lambda: keeper.refresh(session, rules, since=None))
        # Keyword rules share one pass over the lines, so they are timed together.
        per_rule = []
        keyword = [rule for rule in rules.enabled if rule.type == "keyword"]
        if keyword:
            together, outcome = timed(lambda: evaluate(session, keyword))
            label = f"{len(keyword)} anahtar kelime kuralı, tek geçişte"
            per_rule.append((label, together, outcome.total))
        for rule in rules.enabled:
            if rule.type != "keyword":
                one, outcome = timed(lambda rule=rule: evaluate(session, [rule]))
                per_rule.append((f"{rule.id} ({rule.type})", one, outcome.total))
        evaluate(session, rules.enabled)  # back to the full set of alerts
        again_seconds, again = load(session, log)
        assert again.duplicates == lines

        sources = session.scalar(select(func.count(func.distinct(Event.src_ip))))
        first, last = session.execute(select(func.min(Event.ts), func.max(Event.ts))).one()

        # What following costs: a hundred more lines arrive, the rules run on them.
        before = latest_event_id(session)
        fresh = later_lines(100, after=last.replace(tzinfo=None))
        ingestor = Ingestor(
            session,
            name=log.name,
            parser=create_parser("auto", year=START.year),
            resume=True,
        )
        append_seconds, _ = timed(
            lambda: (ingestor.feed(enumerate(fresh, start=lines + 1)), ingestor.flush())
        )
        step_seconds, step = timed(lambda: keeper.refresh(session, rules, since=before))

        alerts = session.scalar(select(func.count()).select_from(Alert))
        busiest = session.execute(
            select(Event.src_ip)
            .where(Event.src_ip.is_not(None))
            .group_by(Event.src_ip)
            .order_by(func.count().desc())
            .limit(1)
        ).scalar_one()
        rare = session.execute(
            select(Event.src_ip)
            .where(Event.src_ip.is_not(None))
            .group_by(Event.src_ip)
            .having(func.count() == 2)
            .limit(1)
        ).scalar_one()
        scanner = session.execute(
            select(Alert.group_key).where(Alert.rule_id == "NET-001").limit(1)
        ).scalar_one_or_none()
        big = session.execute(
            select(Alert.id, Alert.first_seen, Alert.last_seen)
            .order_by(Alert.count.desc())
            .limit(1)
        ).one()

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    megabytes = database.stat().st_size / 1e6
    print("| Adım | Süre | Not |")
    print("|---|---|---|")
    print(
        f"| Yükleme (ayrıştırma + yazma) | {load_seconds:.1f} sn | "
        f"{dots(lines / load_seconds)} satır/sn; {dots(result.parsed)} ayrıştırıldı, "
        f"{dots(result.unparsed)} tanınmadı |"
    )
    print(f"| Aynı dosyayı yeniden yükleme | {again_seconds:.1f} sn | hepsi kopya, atlandı |")
    print(
        f"| Kuralların tümü ({len(rules.enabled)}), baştan | {rule_seconds:.1f} sn | "
        f"{dots(evaluation.total)} uyarı |"
    )
    for label, one, total in per_rule:
        print(f"| &nbsp;&nbsp;{label} | {one:.1f} sn | {dots(total)} uyarı |")
    print(
        f"| Canlı takip adımı: 100 yeni satır | {(append_seconds + step_seconds) * 1000:.0f} ms | "
        f"yazma {append_seconds * 1000:.0f} ms, kurallar {step_seconds * 1000:.0f} ms; "
        f"{dots(step.total)} uyarı |"
    )
    print(f"| Veritabanı dosyası | {megabytes:.0f} MB | {dots(sources)} farklı kaynak adres |")
    print(f"| En yüksek bellek kullanımı | {peak:.0f} MB | ölçüm betiğinin tamamı |")
    print()

    def session_for_api() -> Iterator[Session]:
        with Session(engine, expire_on_commit=False) as database_session:
            yield database_session

    whole = {"start": first.isoformat(), "end": (last + timedelta(seconds=1)).isoformat()}
    middle = first + (last - first) / 2
    hour = {"start": middle.isoformat(), "end": (middle + timedelta(hours=1)).isoformat()}
    day = {"start": middle.isoformat(), "end": (middle + timedelta(days=1)).isoformat()}
    around = {
        "start": (big.first_seen - timedelta(minutes=1)).isoformat(),
        "end": (big.last_seen + timedelta(minutes=1)).isoformat(),
    }
    app.dependency_overrides[get_session] = session_for_api
    try:
        with TestClient(app) as client:
            page = client.get("/events", params={"limit": 200, "start": middle.isoformat()})
            cursor = page.json()["next_cursor"]
            hourly, events = {"bucket": "1h", **whole}, {"limit": 200}
            questions: list[tuple[str, str, dict[str, Any]]] = [
                ("Özet sayıları", "/stats", {}),
                ("Uyarı listesi (500)", "/alerts", {"limit": 500}),
                ("Zaman çizelgesi, tüm dönem, saatlik", "/timeline", hourly),
                ("Zaman çizelgesi, tüm dönem, günlük", "/timeline", {"bucket": "1d", **whole}),
                ("Zaman çizelgesi, bir gün, 5 dakikalık", "/timeline", {"bucket": "5m", **day}),
                ("Zaman çizelgesi, bir saat, 1 dakikalık", "/timeline", {"bucket": "1m", **hour}),
                ("Zaman çizelgesi, tüm dönem, tek adres", "/timeline", {**hourly, "ip": busiest}),
                (
                    "Zaman çizelgesi, tüm dönem, yalnızca şüpheli",
                    "/timeline",
                    {**hourly, "level": "warning"},
                ),
                ("Olaylar, ilk sayfa", "/events", {**events, **whole}),
                (
                    "Olaylar, dönemin ortasından sayfa",
                    "/events",
                    {**events, **whole, "cursor": cursor},
                ),
                ("Olaylar, en yeni 200", "/events", {**events, "order": "desc"}),
                ("Olaylar, çok görülen adres", "/events", {**events, "ip": busiest}),
                ("Olaylar, iki kez görülen adres", "/events", {**events, "ip": rare}),
                ("Olaylar, bir uyarının çevresi", "/events", {**events, **around}),
                ("Olaylar, bir uyarının kanıtları", "/events", {**events, "alert_id": big.id}),
                ("Olaylar, bir kuralın tüm kanıtları", "/events", {**events, "rule_id": "SSH-001"}),
                ("Olaylar, program süzgeci", "/events", {**events, **whole, "service": "sudo"}),
            ]
            if scanner:
                questions.append(("Port görünümü, tarama yapan adres", "/ports", {"ip": scanner}))

            print("| İstek | Ortanca | En kötü | Yanıt |")
            print("|---|---|---|---|")
            for label, path, params in questions:
                print(f"| {label} (`{path}`) | {measure_api(client, path, params, repeat)} |")
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
    print(f"\nHer istek {repeat} kez yapıldı. {dots(alerts)} uyarı, {dots(sources)} kaynak adres.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lines", type=int, default=1_000_000)
    parser.add_argument("--repeat", type=int, default=15, help="how often each API call is made")
    parser.add_argument("--keep", type=Path, help="folder to keep the log and the database in")
    arguments = parser.parse_args()

    if arguments.keep:
        arguments.keep.mkdir(parents=True, exist_ok=True)
        run(arguments.lines, arguments.keep, arguments.repeat)
    else:
        with tempfile.TemporaryDirectory() as folder:
            run(arguments.lines, Path(folder), arguments.repeat)


if __name__ == "__main__":
    main()
