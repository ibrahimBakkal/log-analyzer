"""Shapes of the JSON the API returns."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.enums import Action, Level


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime = Field(description="When the line was logged, in UTC.")
    host: str | None
    service: str | None = Field(description="The program that wrote the line.")
    level: Level
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    user: str | None
    action: Action | None = Field(description="Null when no pattern recognized the line.")
    message: str = Field(description="The line without timestamp, host and program.")
    raw: str = Field(description="The line exactly as it was read.")
    source_file: str
    line_no: int
    parsed: bool


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None = Field(
        description="Pass as `cursor` to get the next page. Null on the last page."
    )
