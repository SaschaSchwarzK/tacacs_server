"""SQLAlchemy models for local auth, accounting, backups, and shared Base."""
# ruff: noqa: I001

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, Index, Integer, String, Text

from tacacs_server.db.engine import Base

# Local auth models


class LocalUser(Base):
    __tablename__ = "local_users"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=True)
    password_hash = Column(String, nullable=True)
    privilege_level = Column(Integer, nullable=False, default=1)
    service = Column(String, nullable=False, default="exec")
    groups = Column(Text, nullable=False, default='["users"]')
    enabled = Column(Integer, nullable=False, default=1)
    description = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=True, default=lambda: datetime.now(UTC)
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=True, default=lambda: datetime.now(UTC)
    )


class LocalUserGroup(Base):
    __tablename__ = "local_user_groups"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)
    ldap_group = Column(String, nullable=True)
    okta_group = Column(String, nullable=True)
    radius_group = Column(String, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=True, default=lambda: datetime.now(UTC)
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=True, default=lambda: datetime.now(UTC)
    )


# Accounting models
class Accounting(Base):
    __tablename__ = "accounting"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, nullable=True)
    username = Column(String, nullable=True)
    acct_type = Column(String, nullable=True)
    start_time = Column(Integer, nullable=True)
    stop_time = Column(Integer, nullable=True)
    bytes_in = Column(Integer, nullable=True)
    bytes_out = Column(Integer, nullable=True)
    attributes = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=True, default=lambda: datetime.now(UTC)
    )


class ActiveSession(Base):
    __tablename__ = "active_sessions"
    __table_args__ = {"extend_existing": True}

    session_id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    client_ip = Column(String, nullable=True)
    start_time = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    last_update = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    service = Column(String, nullable=True)
    port = Column(String, nullable=True)
    privilege_level = Column(Integer, nullable=True, default=1)
    bytes_in = Column(Integer, nullable=True, default=0)
    bytes_out = Column(Integer, nullable=True, default=0)


class AccountingLog(Base):
    __tablename__ = "accounting_logs"
    __table_args__ = (
        Index("idx_acct_timestamp", "timestamp"),
        Index("idx_acct_username", "username"),
        Index("idx_acct_session", "session_id"),
        Index("idx_acct_recent", "is_recent", "timestamp"),
        {"extend_existing": True},
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    username = Column(String, nullable=False)
    session_id = Column(Integer, nullable=False)
    status = Column(String, nullable=False)
    service = Column(String, nullable=True)
    command = Column(Text, nullable=True)
    client_ip = Column(String, nullable=True)
    port = Column(String, nullable=True)
    start_time = Column(String, nullable=True)
    stop_time = Column(String, nullable=True)
    bytes_in = Column(Integer, default=0)
    bytes_out = Column(Integer, default=0)
    elapsed_time = Column(Integer, default=0)
    privilege_level = Column(Integer, default=1)
    authentication_method = Column(String, nullable=True)
    nas_port = Column(String, nullable=True)
    nas_port_type = Column(String, nullable=True)
    task_id = Column(String, nullable=True)
    timezone = Column(String, nullable=True)
    attributes = Column(Text, nullable=True)
    is_recent = Column(Integer, default=0)


# Backup models
class BackupExecution(Base):
    __tablename__ = "backup_executions"
    __table_args__ = {"extend_existing": True}

    id = Column(String, primary_key=True)
    destination_id = Column(String, nullable=True, index=True)
    backup_filename = Column(String, nullable=True)
    backup_path = Column(String, nullable=True)
    triggered_by = Column(String, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, nullable=False, index=True)
    size_bytes = Column(Integer, nullable=True)
    compressed_size_bytes = Column(Integer, nullable=True)
    files_included = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    manifest_json = Column(Text, nullable=True)


class BackupDestination(Base):
    __tablename__ = "backup_destinations"
    __table_args__ = {"extend_existing": True}

    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    type = Column(String, nullable=False)
    enabled = Column(Integer, nullable=False, default=1)
    config_json = Column(Text, nullable=False)
    retention_days = Column(Integer, nullable=False, default=30)
    retention_strategy = Column(String, nullable=True, default="simple")
    retention_config_json = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    created_by = Column(String, nullable=False)
    last_backup_at = Column(DateTime(timezone=True), nullable=True)
    last_backup_status = Column(String, nullable=True)


# Re-export device models from devices.models to avoid duplication
try:
    from tacacs_server.devices.models import (
        DeviceModel as Device,  # noqa: F401
        DeviceGroupModel as DeviceGroup,  # noqa: F401
        ProxyModel as Proxy,  # noqa: F401
    )  # noqa: F401
except Exception:
    # Device models may not be needed in contexts that only use local/backup/accounting
    pass
