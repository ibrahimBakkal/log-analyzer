"""Database tables."""

from datetime import datetime

from sqlalchemy import Index, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, UTCDateTime


class Event(Base):
    """One log line, whether a parser recognized it or not."""

    __tablename__ = "events"
    __table_args__ = (
        # A line of a file is stored once, however often the file is uploaded.
        UniqueConstraint("source_file", "line_no"),
        Index(None, "src_ip", "ts"),
        Index(None, "action", "ts"),
        Index(None, "dst_port", "ts"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    host: Mapped[str | None]
    service: Mapped[str | None]  # the program that wrote the line: sshd, sudo, CRON, ...
    level: Mapped[str]  # app.enums.Level
    src_ip: Mapped[str | None]
    dst_ip: Mapped[str | None]
    src_port: Mapped[int | None]
    dst_port: Mapped[int | None]
    user: Mapped[str | None]
    action: Mapped[str | None]  # app.enums.Action; NULL when no pattern matched
    message: Mapped[str] = mapped_column(Text)  # the line without timestamp, host and program
    raw: Mapped[str] = mapped_column(Text)  # the line exactly as it was read
    source_file: Mapped[str]
    line_no: Mapped[int]
    parsed: Mapped[bool]  # False: stored as-is because no pattern matched
