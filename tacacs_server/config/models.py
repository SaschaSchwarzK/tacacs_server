from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, Text, DateTime, UniqueConstraint, Index, func
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class ConfigOverride(Base):
    """Active configuration overrides."""
    __tablename__ = 'config_overrides'
    
    id = Column(Integer, primary_key=True)
    section = Column(String(255), nullable=False)
    key = Column(String(255), nullable=False)
    value = Column(Text, nullable=False)
    value_type = Column(String(50))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_by = Column(String(255), nullable=False)
    active = Column(Boolean, nullable=False, default=True, server_default='1')
    
    # Composite unique constraint on section, key when active
    # For SQLite, the partial index is created in ConfigStore._create_sqlite_indexes()
    __table_args__ = ()


class ConfigHistory(Base):
    """Audit history of configuration changes."""
    __tablename__ = 'config_history'
    
    id = Column(Integer, primary_key=True)
    section = Column(String(255), nullable=False)
    key = Column(String(255), nullable=False)
    old_value = Column(Text)
    new_value = Column(Text)
    value_type = Column(String(50))
    changed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    changed_by = Column(String(255), nullable=False)
    change_reason = Column(Text)
    source_ip = Column(String(45))  # IPv6 max length
    config_hash = Column(String(64), nullable=False)  # SHA-256 hex digest
    
    # Index for faster lookups
    __table_args__ = (
        Index('ix_config_history_changed_at', 'changed_at'),
    )


class ConfigVersion(Base):
    """Versioned snapshots of complete configurations."""
    __tablename__ = 'config_versions'
    
    id = Column(Integer, primary_key=True)
    version_number = Column(Integer, unique=True, nullable=False)
    config_json = Column(Text, nullable=False)
    config_hash = Column(String(64), nullable=False)  # SHA-256 hex digest
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_by = Column(String(255), nullable=False)
    description = Column(Text)
    is_baseline = Column(Boolean, nullable=False, default=False, server_default='0')


class SystemMetadata(Base):
    """Simple key/value store for system metadata."""
    __tablename__ = 'system_metadata'
    
    key = Column(String(255), primary_key=True)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False, 
                       server_default=func.now(), onupdate=func.now())
