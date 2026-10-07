"""create events table

Revision ID: 0001
Revises:
Create Date: 2026-10-07 15:19:47.027481

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("host", sa.String(), nullable=True),
        sa.Column("service", sa.String(), nullable=True),
        sa.Column("level", sa.String(), nullable=False),
        sa.Column("src_ip", sa.String(), nullable=True),
        sa.Column("dst_ip", sa.String(), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("user", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("raw", sa.Text(), nullable=False),
        sa.Column("source_file", sa.String(), nullable=False),
        sa.Column("line_no", sa.Integer(), nullable=False),
        sa.Column("parsed", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_events")),
        sa.UniqueConstraint("source_file", "line_no", name=op.f("uq_events_source_file_line_no")),
    )
    op.create_index(op.f("ix_events_ts"), "events", ["ts"])
    op.create_index(op.f("ix_events_src_ip_ts"), "events", ["src_ip", "ts"])
    op.create_index(op.f("ix_events_action_ts"), "events", ["action", "ts"])
    op.create_index(op.f("ix_events_dst_port_ts"), "events", ["dst_port", "ts"])


def downgrade() -> None:
    op.drop_table("events")  # its indexes go with it
