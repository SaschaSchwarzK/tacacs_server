"""SQLAlchemy models for device inventory (devices, groups, proxies)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text

from tacacs_server.db.engine import Base


class DeviceGroupModel(Base):
    __tablename__ = "device_groups"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    realm_id = Column(Integer, nullable=True)
    proxy_network = Column(String, nullable=True)
    proxy_id = Column(Integer, nullable=True)
    proxy_id = Column(Integer, nullable=True)
    metadata_json = Column("metadata", Text, nullable=True)
    tacacs_profile = Column(Text, nullable=True)
    radius_profile = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class ProxyModel(Base):
    __tablename__ = "proxies"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    network = Column(String, nullable=False)
    metadata_json = Column("metadata", Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class DeviceModel(Base):
    __tablename__ = "devices"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    network = Column(String, nullable=False)
    network_start_int = Column(Integer, nullable=True)
    network_end_int = Column(Integer, nullable=True)
    tacacs_secret = Column(String, nullable=True)
    radius_secret = Column(String, nullable=True)
    metadata_json = Column("metadata", Text, nullable=True)
    group_id = Column(Integer, nullable=True)
    proxy_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class RealmModel(Base):
    __tablename__ = "realms"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
