# ruff: noqa: I001
"""Device schema updates: realm_id, network ranges, secrets, indexes.

Revision ID: 0001_device_schema_updates
Revises:
Create Date: 2025-12-06
"""

from __future__ import annotations

from typing import Any
import ipaddress

import sqlalchemy as sa
from alembic import op as alembic_op  # type: ignore[attr-defined]
from sqlalchemy import inspect

op: Any = alembic_op

# revision identifiers, used by Alembic.
revision = "0001_device_schema_updates"
down_revision = None
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    op: Any = alembic_op
    conn = op.get_bind()
    insp = inspect(conn)
    cols = {c["name"] for c in insp.get_columns(table)}
    return column in cols


def upgrade():
    op: Any = alembic_op
    conn = op.get_bind()
    insp = inspect(conn)
    tables = set(insp.get_table_names())

    if "device_groups" in tables:
        with op.batch_alter_table("device_groups", recreate="auto") as batch_op:
            if not _has_column("device_groups", "realm_id"):
                batch_op.add_column(sa.Column("realm_id", sa.Integer()))
            if not _has_column("device_groups", "proxy_network"):
                batch_op.add_column(sa.Column("proxy_network", sa.String()))

    if "devices" in tables:
        with op.batch_alter_table("devices", recreate="auto") as batch_op:
            if not _has_column("devices", "network_start_int"):
                batch_op.add_column(sa.Column("network_start_int", sa.Integer()))
            if not _has_column("devices", "network_end_int"):
                batch_op.add_column(sa.Column("network_end_int", sa.Integer()))
            if not _has_column("devices", "tacacs_secret"):
                batch_op.add_column(sa.Column("tacacs_secret", sa.String()))
            if not _has_column("devices", "radius_secret"):
                batch_op.add_column(sa.Column("radius_secret", sa.String()))
            batch_op.create_index(
                "idx_device_network_range",
                ["network_start_int", "network_end_int"],
                unique=False,
                if_not_exists=True,
            )

        devices_tbl = sa.table(
            "devices",
            sa.column("id", sa.Integer),
            sa.column("network", sa.String),
            sa.column("network_start_int", sa.Integer),
            sa.column("network_end_int", sa.Integer),
        )
        rows = conn.execute(sa.select(devices_tbl.c.id, devices_tbl.c.network)).all()
        for row in rows:
            try:
                net = ipaddress.ip_network(row.network, strict=False)
                conn.execute(
                    sa.update(devices_tbl)
                    .where(devices_tbl.c.id == row.id)
                    .values(
                        network_start_int=int(net.network_address),
                        network_end_int=int(net.broadcast_address),
                    )
                )
            except ValueError:
                continue

    if "accounting_logs" in tables:
        op.create_index(
            "idx_acct_timestamp",
            "accounting_logs",
            ["timestamp"],
            unique=False,
            if_not_exists=True,
        )
        op.create_index(
            "idx_acct_username",
            "accounting_logs",
            ["username"],
            unique=False,
            if_not_exists=True,
        )
        op.create_index(
            "idx_acct_session",
            "accounting_logs",
            ["session_id"],
            unique=False,
            if_not_exists=True,
        )
        op.create_index(
            "idx_acct_recent",
            "accounting_logs",
            ["is_recent", "timestamp"],
            unique=False,
            if_not_exists=True,
        )


def downgrade():
    op.drop_index("idx_acct_recent", table_name="accounting_logs")
    op.drop_index("idx_acct_session", table_name="accounting_logs")
    op.drop_index("idx_acct_username", table_name="accounting_logs")
    op.drop_index("idx_acct_timestamp", table_name="accounting_logs")

    op.drop_index("idx_device_network_range", table_name="devices")
    with op.batch_alter_table("devices", recreate="auto") as batch_op:
        if _has_column("devices", "radius_secret"):
            batch_op.drop_column("radius_secret")
        if _has_column("devices", "tacacs_secret"):
            batch_op.drop_column("tacacs_secret")
        if _has_column("devices", "network_end_int"):
            batch_op.drop_column("network_end_int")
        if _has_column("devices", "network_start_int"):
            batch_op.drop_column("network_start_int")

    if _has_column("device_groups", "realm_id"):
        with op.batch_alter_table("device_groups", recreate="auto") as batch_op:
            batch_op.drop_column("realm_id")
    if _has_column("device_groups", "proxy_network"):
        with op.batch_alter_table("device_groups", recreate="auto") as batch_op:
            batch_op.drop_column("proxy_network")
