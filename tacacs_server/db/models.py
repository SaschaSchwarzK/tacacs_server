"""SQLAlchemy models for local auth and accounting (SQLite)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text

from .engine import Base


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
    created_at = Column(DateTime, nullable=True, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow)


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
    created_at = Column(DateTime, nullable=True, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow)


# Accounting models (simplified to match existing schema)
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
    created_at = Column(DateTime, nullable=True, default=datetime.utcnow)


class ActiveSession(Base):
    __tablename__ = "active_sessions"
    __table_args__ = {"extend_existing": True}

    session_id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    client_ip = Column(String, nullable=True)
    start_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_update = Column(DateTime, nullable=False, default=datetime.utcnow)
    service = Column(String, nullable=True)
    port = Column(String, nullable=True)
    privilege_level = Column(Integer, nullable=True, default=1)
    bytes_in = Column(Integer, nullable=True, default=0)
    bytes_out = Column(Integer, nullable=True, default=0)


class AccountingLog(Base):
    __tablename__ = "accounting_logs"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
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
