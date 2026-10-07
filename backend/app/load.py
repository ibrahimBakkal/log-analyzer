"""Load log files from the command line: ``python -m app.load FILE [FILE ...]``.

Does what ``POST /ingest`` does (the same parsing, the same care not to store a
line twice, the rules run afterwards) without a server in between: for a large
file that is already on the machine, and for filling a new database with the
sample logs, which is what the Docker image does on its first start.

Meant for when the server is not running. If it is, the lines are stored all
the same, but pages that are open in a browser are not told to refresh.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from zoneinfo import ZoneInfoNotFoundError

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import session_factory
from app.ingest import DamagedFileError, NoTimestampsError, ingest_lines, open_log, read_lines
from app.parsers import create_parser, parser_names
from app.rules import AlertKeeper, latest_event_id, load_rules
from app.rules.loader import RuleSet


def load_files(
    session: Session,
    paths: Sequence[Path],
    *,
    rules: RuleSet,
    parser: str = "auto",
    year: int | None = None,
    tz: str = "UTC",
) -> bool:
    """Store the lines of *paths* and bring the alerts up to date.

    Says on standard output what became of each file. Returns whether every
    file could be loaded; one that could not does not stop the others.
    """
    before = latest_event_id(session)
    complete = True
    for path in paths:
        try:
            with path.open("rb") as stream:
                result = ingest_lines(
                    session,
                    read_lines(open_log(stream)),
                    source_file=path.name,
                    # A parser keeps track of where in the year its file is: one each.
                    parser=create_parser(parser, year=year, tz=tz),
                )
        except OSError as error:
            print(f"{path}: {error.strerror or error}", file=sys.stderr)
            complete = False
        except (NoTimestampsError, DamagedFileError) as error:
            # Of a damaged file, the lines before the damage are stored.
            print(f"{path}: {error}", file=sys.stderr)
            complete = False
        else:
            name = result.source_file
            stored_as = "" if name == path.name else f" (stored as {name})"
            print(
                f"{path}{stored_as}: {result.lines} lines, {result.parsed} parsed, "
                f"{result.unparsed} unparsed, {result.duplicates} duplicates, "
                f"{result.conflicts} conflicts"
            )

    outcome = AlertKeeper().refresh(session, rules, since=before)
    print(f"{outcome.total} alerts, {outcome.created} of them new")
    return complete


def main(arguments: Sequence[str] | None = None) -> int:
    options = argparse.ArgumentParser(
        prog="python -m app.load",
        description="Load log files into the database and run the rules.",
    )
    options.add_argument(
        "files", nargs="+", type=Path, help="log files; gzip, bzip2 and xz are unpacked"
    )
    options.add_argument(
        "--parser",
        default="auto",
        choices=parser_names(),
        help="what to look for in the files (default: auto, every known format)",
    )
    options.add_argument(
        "--year",
        type=int,
        help="year of the first line; syslog timestamps have none "
        "(default: the most recent year in which that line is not in the future)",
    )
    options.add_argument(
        "--tz", default="UTC", help="time zone of the machine that wrote the logs (default: UTC)"
    )
    chosen = options.parse_args(arguments)

    try:
        create_parser(chosen.parser, year=chosen.year, tz=chosen.tz)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        options.error(f"unknown time zone {chosen.tz!r}")

    settings = get_settings()
    rules = load_rules(settings.rules_dir)
    for error in rules.errors:
        print(f"rule file {error.file} was not loaded: {error.message}", file=sys.stderr)

    try:
        with session_factory()() as session:
            complete = load_files(
                session,
                chosen.files,
                rules=rules,
                parser=chosen.parser,
                year=chosen.year,
                tz=chosen.tz,
            )
    except SQLAlchemyError as error:
        # Most likely a database without tables.
        print(f"database not ready: {str(error).splitlines()[0]}", file=sys.stderr)
        print("have the migrations run? `alembic upgrade head`", file=sys.stderr)
        return 1
    return 0 if complete else 1


if __name__ == "__main__":
    sys.exit(main())
