"""create sources table

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-07 17:20:00.000000

"""

import hashlib
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    sources = op.create_table(
        "sources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sources")),
        sa.UniqueConstraint("name", name=op.f("uq_sources_name")),
        sa.UniqueConstraint("fingerprint", name=op.f("uq_sources_fingerprint")),
    )

    # Files loaded before this table existed: register each by its first stored line.
    # Of several files that start with the same line (one file loaded under two
    # names), only the first can own the fingerprint.
    events = sa.table("events", sa.column("source_file"), sa.column("line_no"), sa.column("raw"))
    first_lines = (
        sa.select(events.c.source_file, sa.func.min(events.c.line_no).label("line_no"))
        .group_by(events.c.source_file)
        .subquery()
    )
    rows = op.get_bind().execute(
        sa.select(events.c.source_file, events.c.raw)
        .join(
            first_lines,
            sa.and_(
                events.c.source_file == first_lines.c.source_file,
                events.c.line_no == first_lines.c.line_no,
            ),
        )
        .order_by(events.c.source_file)
    )
    known: set[str] = set()
    found = []
    for name, raw in rows:
        fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if fingerprint not in known:
            known.add(fingerprint)
            found.append({"name": name, "fingerprint": fingerprint})
    if found:
        op.bulk_insert(sources, found)


def downgrade() -> None:
    op.drop_table("sources")
