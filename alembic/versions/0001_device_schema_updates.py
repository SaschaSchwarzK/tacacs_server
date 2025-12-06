"""Device schema updates: realm_id, network ranges.

Revision ID: 0001_device_schema_updates
Revises: 
Create Date: 2025-12-06
"""

from __future__ import annotations

import ipaddress

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "0001_device_schema_updates"
down_revision = None
branch_labels = None
depends_on = None


def _has_column(table: str, column: str) -> bool:
    conn = op.get_bind()
    insp = inspect(conn)
    cols = {c["name"] for c in insp.get_columns(table)}
    return column in cols


def upgrade():
    conn = op.get_bind()
    insp = inspect(conn)
    tables = set(insp.get_table_names())

    if "device_groups" in tables and not _has_column("device_groups", "realm_id"):
        with op.batch_alter_table("device_groups") as batch_op:
            batch_op.add_column(sa.Column("realm_id", sa.Integer()))

    if "devices" in tables:
        with op.batch_alter_table("devices") as batch_op:
            if not _has_column("devices", "network_start_int"):
                batch_op.add_column(sa.Column("network_start_int", sa.Integer()))
            if not _has_column("devices", "network_end_int"):
                batch_op.add_column(sa.Column("network_end_int", sa.Integer()))

        # Backfill numeric ranges for existing device networks
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
            except Exception:
                continue


def downgrade():
    if _has_column("device_groups", "realm_id"):
        with op.batch_alter_table("device_groups") as batch_op:
            batch_op.drop_column("realm_id")
    if _has_column("devices", "network_start_int"):
        with op.batch_alter_table("devices") as batch_op:
            batch_op.drop_column("network_start_int")
    if _has_column("devices", "network_end_int"):
        with op.batch_alter_table("devices") as batch_op:
            batch_op.drop_column("network_end_int")
