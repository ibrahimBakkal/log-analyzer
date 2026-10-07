"""POST /ingest: upload a log file."""

from dataclasses import asdict
from pathlib import PurePosixPath
from typing import Annotated
from zoneinfo import ZoneInfoNotFoundError

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from sqlalchemy import func, select

from app.ingest import NoTimestampsError, ingest_lines, read_lines
from app.models import Alert
from app.parsers import UnknownParserError, create_parser
from app.routers import SessionDep
from app.routers.rules import RulesDep
from app.rules import evaluate
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
        Form(description="Name to store the lines under. Default: the uploaded file's name."),
    ] = None,
) -> IngestReport:
    """Parse a log file, store every line as an event and re-run the rules.

    Lines are identified by file name and line number, so uploading the same
    file again adds nothing (`duplicates`), and uploading a file that has grown
    adds only the new lines. If a line number is already stored with different
    text (`conflicts`) the stored line is kept: upload a rotated file under
    another `source` name.
    """
    try:
        log_parser = create_parser(parser, year=year, tz=tz)
    except UnknownParserError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise HTTPException(status_code=422, detail=f"unknown time zone {tz!r}") from None

    try:
        result = ingest_lines(
            session,
            read_lines(file.file),
            source_file=_source_name(source or file.filename),
            parser=log_parser,
        )
    except NoTimestampsError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None

    if result.parsed or result.unparsed:  # new events: the alerts may have changed
        evaluate(session, rules.enabled)
    alerts = session.scalar(select(func.count()).select_from(Alert))
    return IngestReport(**asdict(result), alerts=alerts or 0)
