"""Database tables."""

from datetime import datetime

from sqlalchemy import JSON, ForeignKey, Index, Text, UniqueConstraint
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
        # For the dashboard on a large table: these let /timeline and /stats count
        # from the index alone, without reading a single row.
        Index(None, "level", "ts"),
        Index(None, "action", "src_ip", "ts"),
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


class Source(Base):
    """A log file that has been loaded, known by its first line.

    A log file keeps its first line for as long as it lives: while it grows,
    and after rotation has renamed it to ``auth.log.1`` or packed it into
    ``auth.log.2.gz``. Whatever name a file arrives under, its lines are stored
    under the name it was first seen with, so no line is stored twice.
    """

    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)  # what events.source_file says
    fingerprint: Mapped[str] = mapped_column(unique=True)  # SHA-256 of the first non-blank line


class Alert(Base):
    """Something a rule found: one burst of related events."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Rule, group and first event: the same burst keeps its row across re-evaluations.
    key: Mapped[str] = mapped_column(unique=True)
    rule_id: Mapped[str] = mapped_column(index=True)
    rule_name: Mapped[str]
    severity: Mapped[str]  # app.enums.Severity
    group_by: Mapped[str]  # the event field the rule groups on, e.g. src_ip
    group_key: Mapped[str]  # that field's value for this alert, e.g. 203.0.113.45
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    count: Mapped[int]  # number of evidence events
    summary: Mapped[str] = mapped_column(Text)


class AlertEvent(Base):
    """Evidence: an event that belongs to an alert, and where in its message to look."""

    __tablename__ = "alert_events"

    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    # [[start, end], ...]: character ranges of the event's message to highlight.
    spans: Mapped[list[list[int]]] = mapped_column(JSON)
