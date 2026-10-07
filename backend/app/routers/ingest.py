"""POST /ingest: upload a log file."""

from dataclasses import asdict
from pathlib import PurePosixPath
from typing import Annotated
from zoneinfo import ZoneInfoNotFoundError

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from sqlalchemy import func, select

from app.ingest import DamagedFileError, NoTimestampsError, ingest_lines, open_log, read_lines
from app.models import Alert
from app.parsers import UnknownParserError, create_parser
from app.routers import SessionDep
from app.routers.live import HubDep
from app.routers.rules import AlertKeeperDep, RulesDep
from app.rules import latest_event_id
from app.schemas import IngestReport

router = APIRouter(tags=["ingest"])


def _source_name(name: str | None) -> str:
    """The bare file name: browsers may send a full path, and the name is user input."""
    base = PurePosixPath((name or "").replace("\\", "/")).name.strip()
    return base[:255] or "upload"


@router.post("/ingest")
def ingest_file(
    session: SessionDep,
    rules: RulesDep,
    keeper: AlertKeeperDep,
    hub: HubDep,
    file: Annotated[UploadFile, File(description="The log file to load.")],
    parser: Annotated[
        str,
        Form(
            description="What to look for in the file: `auto` recognizes the lines of every "
            "known format, `auth` only sshd and sudo, `ufw` only the firewall's packet log."
        ),
    ] = "auto",
    year: Annotated[
        int | None,
        Form(
            ge=1970,
            le=9999,
            description="Year of the first line; syslog timestamps have none. "
            "Default: the most recent year in which that line is not in the future.",
        ),
    ] = None,
    tz: Annotated[
        str,
        Form(description="Time zone of the machine that wrote the log, e.g. Europe/Istanbul."),
    ] = "UTC",
    source: Annotated[
        str | None,
        Form(description="Name to store a new file under. Default: the uploaded file's name."),
    ] = None,
) -> IngestReport:
    """Parse a log file, store every line as an event and re-run the rules.

    The file may be compressed (gzip, bzip2 or xz). Of a compressed file that is
    damaged, the lines up to the damage are stored and the request fails with 422.

    A file is known by its first line and each of its lines by its number, so
    uploading the same file again adds nothing (`duplicates`), uploading a file
    that has grown adds only the new lines, and a rotated copy (`auth.log.1`,
    `auth.log.2.gz`) is recognized as the file it used to be. `source_file` in
    the answer is the name the lines are stored under: the name the file was
    first seen with, or, if another file already has that name, the name with
    the date of the first line added.

    `conflicts` counts lines whose number is already stored with different text
    (a file that was edited); the stored lines are kept.
    """
    try:
        log_parser = create_parser(parser, year=year, tz=tz)
    except UnknownParserError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise HTTPException(status_code=422, detail=f"unknown time zone {tz!r}") from None

    before = latest_event_id(session)
    try:
        result = ingest_lines(
            session,
            read_lines(open_log(file.file)),
            source_file=_source_name(source or file.filename),
            parser=log_parser,
        )
    except NoTimestampsError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    except DamagedFileError as error:
        keeper.refresh(session, rules, since=before)
        detail = f"{error}. The lines before that were stored."
        raise HTTPException(status_code=422, detail=detail) from None

    if result.added:  # new events: the alerts of the groups they belong to may have changed
        keeper.refresh(session, rules, since=before)
    alerts = session.scalar(select(func.count()).select_from(Alert)) or 0
    if result.added:
        hub.publish("update", {"reason": "ingest", "added": result.added, "alerts": alerts})
    return IngestReport(**asdict(result), alerts=alerts)
