"""add counting indexes

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-07 17:50:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # With a million events, the dashboard's counts took seconds because every
    # one of them read the whole table. These two indexes hold all they need.
    op.create_index(op.f("ix_events_level_ts"), "events", ["level", "ts"])
    op.create_index(op.f("ix_events_action_src_ip_ts"), "events", ["action", "src_ip", "ts"])


def downgrade() -> None:
    op.drop_index(op.f("ix_events_action_src_ip_ts"), table_name="events")
    op.drop_index(op.f("ix_events_level_ts"), table_name="events")
