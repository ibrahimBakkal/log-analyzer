"""POST /ingest: upload a log file."""

from pathlib import PurePosixPath
from typing import Annotated
from zoneinfo import ZoneInfoNotFoundError

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.ingest import IngestResult, NoTimestampsError, ingest_lines, read_lines
from app.parsers import UnknownParserError, create_parser
from app.routers import SessionDep

router = APIRouter(tags=["ingest"])


def _source_name(name: str | None) -> str:
    """The bare file name: browsers may send a full path, and the name is user input."""
    base = PurePosixPath((name or "").replace("\\", "/")).name.strip()
    return base[:255] or "upload"


@router.post("/ingest")
def ingest_file(
    session: SessionDep,
    file: Annotated[UploadFile, File(description="The log file to load.")],
    parser: Annotated[str, Form(description="Format of the file.")] = "auth",
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
) -> IngestResult:
    """Parse a log file and store every line as an event.

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
        return ingest_lines(
            session,
            read_lines(file.file),
            source_file=_source_name(source or file.filename),
            parser=log_parser,
        )
    except NoTimestampsError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
