"""SQLAlchemy models for device inventory (devices, groups, proxies)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text

from tacacs_server.db.engine import Base


class DeviceGroupModel(Base):
    """Group of devices sharing proxy/network metadata and shared secrets."""

    __tablename__ = "device_groups"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    realm_id = Column(
        Integer, ForeignKey("realms.id", ondelete="SET NULL"), nullable=True
    )
    proxy_network = Column(String, nullable=True)
    proxy_id = Column(
        Integer, ForeignKey("proxies.id", ondelete="SET NULL"), nullable=True
    )
    metadata_json = Column("metadata", Text, nullable=True)
    tacacs_profile = Column(Text, nullable=True)
    radius_profile = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return f"<DeviceGroup id={self.id} name={self.name!r} realm_id={self.realm_id}>"


class ProxyModel(Base):
    """Proxy network entry used for proxy-aware device resolution."""

    __tablename__ = "proxies"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    network = Column(String, nullable=False)
    metadata_json = Column("metadata", Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return f"<Proxy id={self.id} name={self.name!r} network={self.network!r}>"


class DeviceModel(Base):
    """Individual device or network prefix entry."""

    __tablename__ = "devices"
    __table_args__ = (
        Index("idx_device_network_range", "network_start_int", "network_end_int"),
        {"extend_existing": True},
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    network = Column(String, nullable=False)
    network_start_int = Column(Integer, nullable=True)
    network_end_int = Column(Integer, nullable=True)
    tacacs_secret = Column(String, nullable=True)
    radius_secret = Column(String, nullable=True)
    metadata_json = Column("metadata", Text, nullable=True)
    group_id = Column(
        Integer, ForeignKey("device_groups.id", ondelete="SET NULL"), nullable=True
    )
    proxy_id = Column(
        Integer, ForeignKey("proxies.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return (
            f"<Device id={self.id} name={self.name!r} network={self.network!r} "
            f"group_id={self.group_id} proxy_id={self.proxy_id}>"
        )


class RealmModel(Base):
    __tablename__ = "realms"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    def __repr__(self) -> str:
        return f"<Realm id={self.id} name={self.name!r}>"
