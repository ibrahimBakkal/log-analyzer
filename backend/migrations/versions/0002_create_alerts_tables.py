"""create alerts tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-07 15:38:12.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("rule_name", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("group_by", sa.String(), nullable=False),
        sa.Column("group_key", sa.String(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
        sa.UniqueConstraint("key", name=op.f("uq_alerts_key")),
    )
    op.create_index(op.f("ix_alerts_rule_id"), "alerts", ["rule_id"])
    op.create_index(op.f("ix_alerts_first_seen"), "alerts", ["first_seen"])

    op.create_table(
        "alert_events",
        sa.Column("alert_id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("spans", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_alert_events_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["events.id"],
            name=op.f("fk_alert_events_event_id_events"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("alert_id", "event_id", name=op.f("pk_alert_events")),
    )
    op.create_index(op.f("ix_alert_events_event_id"), "alert_events", ["event_id"])


def downgrade() -> None:
    op.drop_table("alert_events")
    op.drop_table("alerts")
