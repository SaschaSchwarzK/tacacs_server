"""Configuration override and history store using SQLAlchemy.

Provides durable storage for runtime configuration changes, their audit
history, and versioned snapshots of complete configurations.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from typing import Optional, Dict, List

from sqlalchemy import create_engine, delete, func, select, update
import sqlite3
from sqlalchemy.orm import Session as DBSession
from sqlalchemy.orm import sessionmaker

from .models import Base, ConfigHistory, ConfigOverride, ConfigVersion, SystemMetadata


def _utc_now() -> datetime:
    """Get current UTC time."""
    return datetime.now(UTC)


def _utc_now_iso() -> str:
    """Get current UTC time as ISO format string."""
    return _utc_now().isoformat()


def compute_config_hash(config_json: str | bytes) -> str:
    """Compute SHA-256 hash of config JSON."""
    data = config_json.encode("utf-8") if isinstance(config_json, str) else config_json
    return hashlib.sha256(data).hexdigest()


class ConfigStore:
    """SQLAlchemy-based configuration override and history store."""
    
    def __init__(self, db_url: str | None = None) -> None:
        """
        Initialize the config store.
        
        Args:
            db_url: SQLAlchemy database URL. If None, uses SQLite at data/config_store.db
        """
        if db_url is None:
            # Default to SQLite in data directory
            db_path = "data/config_store.db"
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            db_url = f"sqlite:///{os.path.abspath(db_path)}"
        else:
            # Accept plain filesystem path as db_url
            if "://" not in db_url and db_url.endswith(".db"):
                os.makedirs(os.path.dirname(db_url) or ".", exist_ok=True)
                db_url = f"sqlite:///{os.path.abspath(db_url)}"
        self.engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {}
        )
        self.Session = sessionmaker(bind=self.engine)
        self._lock = threading.Lock()
        # Provide sqlite cursor compatibility for legacy code paths/tests
        self._conn = None
        if db_url.startswith("sqlite"):
            try:
                # Extract filesystem path after sqlite:///
                db_path = db_url.split("sqlite:///")[-1]
                self._conn = sqlite3.connect(db_path, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                with self._conn:
                    self._conn.execute("PRAGMA foreign_keys = ON")
            except Exception:
                self._conn = None
        
        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)
        
        # Create SQLite-specific indexes if using SQLite
        if db_url.startswith("sqlite"):
            self._create_sqlite_indexes()
    
    def _ensure_schema(self) -> None:
        """Create database tables if they don't exist."""
        Base.metadata.create_all(self.engine)
    
    def _create_sqlite_indexes(self) -> None:
        """Create SQLite-specific indexes that can't be expressed in the ORM."""
        from sqlalchemy import text
        
        # Create the index if it doesn't exist
        with self.engine.connect() as conn:
            # Create partial index for active overrides
            # With the table-level UniqueConstraint(section,key,active), the
            # partial unique index is not strictly required; keep for safety on
            # older DBs created before this change.
            conn.execute(text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS ux_config_overrides_active 
                ON config_overrides (section, key) 
                WHERE active = 1;
                """
            ))
            conn.commit()
    
    def close(self) -> None:
        """Close database connections."""
        try:
            self.engine.dispose()
        except Exception:  # noqa: BLE001
            pass  # Ignore errors during cleanup
    
    # --- Session Management ---
    def _get_session(self) -> DBSession:
        """Get a new database session."""
        return self.Session()  # type: ignore
    
    # --- Value Encoding/Decoding ---
    @staticmethod
    def _encode_value(value: Any, value_type: str) -> str:
        """Encode a Python value to string based on its type."""
        if value is None:
            return ""
            
        if value_type in ("string", "str"):
            return str(value)
        if value_type in ("integer", "int"):
            return str(int(value))
        if value_type in ("boolean", "bool"):
            return "1" if bool(value) else "0"
        # Default to JSON for complex types
        return json.dumps(value)
    
    @staticmethod
    def _decode_value(value_str: str, value_type: str) -> Any:
        """Decode a string value to Python object based on its type."""
        if not value_str:
            return None
            
        if value_type in ("string", "str"):
            return value_str
        if value_type in ("integer", "int"):
            try:
                return int(value_str)
            except (ValueError, TypeError):
                return 0
        if value_type in ("boolean", "bool"):
            return value_str.lower() in ("1", "true", "yes")
        
        try:
            return json.loads(value_str)
        except (json.JSONDecodeError, TypeError):
            return value_str
    
    # --- Override Management ---
    def set_override(
        self,
        section: str,
        key: str,
        value: Any,
        value_type: str,
        changed_by: str,
        reason: Optional[str] = None,
    ) -> None:
        """
        Set a configuration override.
        
        Args:
            section: Configuration section name
            key: Configuration key
            value: New value
            value_type: Type of the value ('string', 'int', 'bool', 'json')
            changed_by: Username or identifier of who made the change
            reason: Optional reason for the change
        """
        with self._lock:
            # Get old value for history
            old = self.get_override(section, key)
            
            # Encode the value
            value_str = self._encode_value(value, value_type)
            
            with self._get_session() as session:
                # Deactivate any existing override
                stmt = (
                    update(ConfigOverride)
                    .where(
                        ConfigOverride.section == section,
                        ConfigOverride.key == key,
                        ConfigOverride.active == True  # noqa: E712
                    )
                    .values(active=False)
                )
                session.execute(stmt)
                
                # Add new override
                override = ConfigOverride(
                    section=section,
                    key=key,
                    value=value_str,
                    value_type=value_type,
                    created_by=changed_by,
                    active=True
                )
                session.add(override)
                
                # Add to history
                self._add_history(
                    session=session,
                    section=section,
                    key=key,
                    old_value=old[0] if old else None,
                    new_value=value,
                    value_type=value_type,
                    changed_by=changed_by,
                    change_reason=reason
                )
                
                session.commit()
    
    def get_override(self, section: str, key: str) -> tuple[Any, str] | None:
        """
        Get an active override.
        
        Args:
            section: Configuration section
            key: Configuration key
            
        Returns:
            Tuple of (value, value_type) if found, else None
        """
        with self._get_session() as session:
            stmt = select(ConfigOverride).where(
                ConfigOverride.section == section,
                ConfigOverride.key == key,
                ConfigOverride.active == True  # noqa: E712
            )
            result = session.execute(stmt).scalar_one_or_none()
            
            if not result:
                return None
                
            return (
                self._decode_value(result.value, result.value_type or "json"),
                result.value_type or "json"
            )
    
    def list_overrides(self, section: str | None = None) -> list[dict[str, Any]]:
        """List all active configuration overrides."""
        with self._get_session() as session:
            stmt = select(ConfigOverride).where(ConfigOverride.active == True)  # noqa: E712
            results = session.execute(stmt).scalars().all()
            return [{
                'id': r.id,
                'section': r.section,
                'key': r.key,
                'value': self._decode_value(r.value, r.value_type or 'json'),
                'value_type': r.value_type or 'json',
                'created_at': r.created_at,
                'created_by': r.created_by
            } for r in results]

    def delete_override(self, section: str, key: str, changed_by: str) -> None:
        """
        Delete a configuration override.
        
        Args:
            section: Configuration section
            key: Configuration key
            changed_by: Username or identifier of who made the change
        """
        with self._lock, self._get_session() as session:
            # Get current value for history
            stmt = select(ConfigOverride).where(
                ConfigOverride.section == section,
                ConfigOverride.key == key,
                ConfigOverride.active == True  # noqa: E712
            )
            override = session.execute(stmt).scalar_one_or_none()
            
            if not override:
                return
                
            # Add to history before deleting
            self._add_history(
                session=session,
                section=section,
                key=key,
                old_value=self._decode_value(override.value, override.value_type or 'json'),
                new_value=None,
                value_type=override.value_type or 'json',
                changed_by=changed_by,
                change_reason="delete override"
            )
            
            # Mark as inactive (soft delete)
            stmt = (
                update(ConfigOverride)
                .where(ConfigOverride.id == override.id)
                .values(active=False)
            )
            session.execute(stmt)
            session.commit()
    
    def get_all_overrides(self) -> dict[str, dict[str, tuple[Any, str]]]:
        """
        Get all active overrides organized by section and key.
        
        Returns:
            Nested dictionary: {section: {key: (value, value_type)}}
        """
        result: dict[str, dict[str, tuple[Any, str]]] = {}
        with self._get_session() as session:
            stmt = select(ConfigOverride).where(ConfigOverride.active == True)  # noqa: E712
            overrides = session.execute(stmt).scalars().all()
            
            for override in overrides:
                section = override.section
                key = override.key
                value = self._decode_value(override.value, override.value_type or 'json')
                value_type = override.value_type or 'json'
                
                if section not in result:
                    result[section] = {}
                result[section][key] = (value, value_type)
                
        return result
    
    def clear_overrides(
        self, 
        section: Optional[str] = None, 
        changed_by: str = "system"
    ) -> None:
        """
        Clear all or section-specific overrides.
        
        Args:
            section: If provided, only clear overrides in this section
            changed_by: Username or identifier of who made the change
        """
        with self._lock:
            if section:
                # Get all keys in the section to add to history
                with self._get_session() as session:
                    stmt = select(ConfigOverride).where(
                        ConfigOverride.section == section,
                        ConfigOverride.active == True  # noqa: E712
                    )
                    overrides = session.execute(stmt).scalars().all()
                    
                    # Add to history and mark as inactive
                    for override in overrides:
                        self._add_history(
                            session=session,
                            section=section,
                            key=override.key,
                            old_value=self._decode_value(override.value, override.value_type or 'json'),
                            new_value=None,
                            value_type=override.value_type or 'json',
                            changed_by=changed_by,
                            change_reason="clear overrides"
                        )
                        
                        stmt = (
                            update(ConfigOverride)
                            .where(ConfigOverride.id == override.id)
                            .values(active=False)
                        )
                        session.execute(stmt)
                    
                    session.commit()
            else:
                # Clear all overrides
                with self._get_session() as session:
                    # Get all active overrides for history
                    stmt = select(ConfigOverride).where(ConfigOverride.active == True)  # noqa: E712
                    overrides = session.execute(stmt).scalars().all()
                    
                    for override in overrides:
                        self._add_history(
                            session=session,
                            section=override.section,
                            key=override.key,
                            old_value=self._decode_value(override.value, override.value_type or 'json'),
                            new_value=None,
                            value_type=override.value_type or 'json',
                            changed_by=changed_by,
                            change_reason="clear all overrides"
                        )
                    
                    # Mark all as inactive
                    stmt = (
                        update(ConfigOverride)
                        .where(ConfigOverride.active == True)  # noqa: E712
                        .values(active=False)
                    )
                    session.execute(stmt)
                    session.commit()
    
    # --- History Management ---
    def _add_history(
        self,
        session: DBSession,
        section: str,
        key: str,
        old_value: Any,
        new_value: Any,
        value_type: str,
        changed_by: str,
        change_reason: str | None = None,
        source_ip: str | None = None,
        full_config: dict[str, Any] | None = None
    ) -> ConfigHistory:
        """
        Add an entry to the change history.
        
        Args:
            session: Database session
            section: Configuration section
            key: Configuration key
            old_value: Previous value
            new_value: New value
            value_type: Type of the value
            changed_by: Username or identifier of who made the change
            change_reason: Optional reason for the change
            source_ip: Optional source IP address
            full_config: Optional full config for hash calculation
            
        Returns:
            The created history record
        """
        # Encode values for storage
        old_val_str = None if old_value is None else self._encode_value(old_value, value_type)
        new_val_str = None if new_value is None else self._encode_value(new_value, value_type)
        
        # Compute config hash if full config provided
        config_hash = compute_config_hash(json.dumps(full_config)) if full_config else ""
        
        history = ConfigHistory(
            section=section,
            key=key,
            old_value=old_val_str,
            new_value=new_val_str,
            value_type=value_type,
            changed_by=changed_by,
            change_reason=change_reason,
            source_ip=source_ip,
            config_hash=config_hash
        )
        
        session.add(history)
        return history
    
    def get_history(
        self, 
        section: Optional[str] = None, 
        key: Optional[str] = None, 
        limit: int = 100, 
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get configuration change history.
        
        Args:
            section: Optional section filter
            key: Optional key filter
            limit: Maximum number of results to return
            offset: Number of results to skip
            
        Returns:
            List of history records
        """
        with self._get_session() as session:
            stmt = select(ConfigHistory).order_by(ConfigHistory.id.desc())
            
            if section:
                stmt = stmt.where(ConfigHistory.section == section)
            if key:
                stmt = stmt.where(ConfigHistory.key == key)
                
            stmt = stmt.limit(limit).offset(offset)
            
            results = session.execute(stmt).scalars().all()
            
            return [{
                'id': r.id,
                'section': r.section,
                'key': r.key,
                'old_value': self._decode_value(r.old_value, r.value_type or 'json') if r.old_value is not None else None,
                'new_value': self._decode_value(r.new_value, r.value_type or 'json') if r.new_value is not None else None,
                'value_type': r.value_type or 'json',
                'changed_at': r.changed_at,
                'changed_by': r.changed_by,
                'change_reason': r.change_reason,
                'source_ip': r.source_ip,
                'config_hash': r.config_hash
            } for r in results]
    
    # --- Version Management ---
    def create_version(
        self,
        config_dict: Dict[str, Any],
        created_by: str,
        description: Optional[str] = None,
        is_baseline: bool = False
    ) -> Dict[str, Any]:
        """
        Create a new versioned snapshot of the configuration.
        
        Args:
            config_dict: Full configuration as a dictionary
            created_by: Username or identifier of who created the version
            description: Optional description of this version
            is_baseline: Whether this should be marked as a baseline version
            
        Returns:
            The created version information
        """
        config_json = json.dumps(config_dict, indent=2)
        config_hash = compute_config_hash(config_json)
        
        with self._get_session() as session:
            # Get next version number
            stmt = select(func.max(ConfigVersion.version_number))
            max_ver = session.execute(stmt).scalar() or 0
            version_number = max_ver + 1
            
            # Create version
            version = ConfigVersion(
                version_number=version_number,
                config_json=config_json,
                config_hash=config_hash,
                created_by=created_by,
                description=description,
                is_baseline=is_baseline
            )
            
            session.add(version)
            # Record history for version save
            try:
                self._add_history(
                    session=session,
                    section='*',
                    key='*',
                    old_value=None,
                    new_value=config_dict,
                    value_type='json',
                    changed_by=created_by,
                    change_reason=description or ("baseline" if is_baseline else "save version"),
                    full_config=config_dict,
                )
            except Exception:
                pass
            session.commit()
            
            return {
                'id': version.id,
                'version_number': version.version_number,
                'config_hash': version.config_hash,
                'created_at': version.created_at,
                'created_by': version.created_by,
                'description': version.description,
                'is_baseline': version.is_baseline
            }
    
    def get_version(self, version_number: int) -> Optional[Dict[str, Any]]:
        """
        Get a specific configuration version.
        
        Args:
            version_number: Version number to retrieve
            
        Returns:
            Version information and config, or None if not found
        """
        with self._get_session() as session:
            stmt = select(ConfigVersion).where(ConfigVersion.version_number == version_number)
            version = session.execute(stmt).scalar_one_or_none()
            
            if not version:
                return None
                
            return {
                'id': version.id,
                'version_number': version.version_number,
                'config_json': version.config_json,
                'config_hash': version.config_hash,
                'created_at': version.created_at,
                'created_by': version.created_by,
                'description': version.description,
                'is_baseline': version.is_baseline
            }
    
    def list_versions(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """
        List all configuration versions.
        
        Args:
            limit: Maximum number of versions to return
            offset: Number of versions to skip
            
        Returns:
            List of version information
        """
        with self._get_session() as session:
            stmt = (
                select(ConfigVersion)
                .order_by(ConfigVersion.version_number.desc())
                .limit(limit)
                .offset(offset)
            )
            
            versions = session.execute(stmt).scalars().all()
            
            return [{
                'id': v.id,
                'version_number': v.version_number,
                'version': v.version_number,
                'config_hash': v.config_hash,
                'created_at': v.created_at,
                'created_by': v.created_by,
                'description': v.description,
                'is_baseline': v.is_baseline
            } for v in versions]

    # --- Backwards-compatibility helpers expected by tests ---
    def save_version(self, config_dict: dict[str, dict[str, Any]], created_by: str, description: str | None = None, is_baseline: bool = False) -> int:
        """Compatibility alias for create_version."""
        return self.create_version(config_dict=config_dict, created_by=created_by, description=description, is_baseline=is_baseline)

    def get_active_config(self) -> dict[str, dict[str, Any]]:
        """
        Return effective config: latest saved version merged with active overrides,
        then environment variable precedence (e.g., TACACS_SERVER_DEBUG=true).
        """
        # Seed with minimal sensible defaults to allow merging in absence of a saved version
        base: dict[str, dict[str, Any]] = {
            "server": {
                "host": "0.0.0.0",
                "port": 49,
                "debug": False,
            }
        }
        latest = self.get_latest_version()
        if latest and latest.get('config_json'):
            try:
                base = json.loads(latest['config_json'])  # type: ignore[arg-type]
            except Exception:
                base = {}
        # Apply overrides
        overrides = self.get_all_overrides()
        for section, items in overrides.items():
            base.setdefault(section, {})
            for key, (val, _typ) in items.items():
                base[section][key] = val
        # Apply env precedence
        def _env_key(sec: str, key: str) -> str:
            return f"TACACS_{sec.upper()}_{key.upper()}"
        for sec, kv in list(base.items()):
            for k in list(kv.keys()):
                env = os.getenv(_env_key(sec, k))
                if env is not None:
                    # Coerce booleans/ints where reasonable
                    lv = env.lower()
                    if lv in ("true", "false", "1", "0", "yes", "no"):
                        kv[k] = lv in ("true", "1", "yes")
                    else:
                        try:
                            kv[k] = int(env)
                        except Exception:
                            kv[k] = env
        return base

    # Back-compat: accept optional reason param
    def restore_version(self, version_number: int, restored_by: str, reason: str | None = None) -> bool:
        return super().restore_version(version_number=version_number, restored_by=restored_by)  # type: ignore[misc]
    
    def restore_version(self, version_number: int, restored_by: str, reason: str | None = None) -> bool:
        """
        Restore a specific configuration version.
        
        Args:
            version_number: Version number to restore
            restored_by: Username or identifier of who performed the restore
            
        Returns:
            True if successful, False if version not found
        """
        with self._lock, self._get_session() as session:
            # Get the version to restore
            stmt = select(ConfigVersion).where(ConfigVersion.version_number == version_number)
            version = session.execute(stmt).scalar_one_or_none()
            
            if not version:
                return False
            
            # Parse the config
            try:
                config = json.loads(version.config_json)
            except json.JSONDecodeError:
                return False
            
            # Clear existing overrides
            stmt = (
                update(ConfigOverride)
                .where(ConfigOverride.active == True)  # noqa: E712
                .values(active=False)
            )
            session.execute(stmt)
            
            # Do not create overrides from the version; base config is tracked
            # in config_versions. Keeping overrides empty reflects the version state.
            
            # Add to history
            self._add_history(
                session=session,
                section='*',
                key='*',
                old_value=None,
                new_value=version.config_json,
                value_type='json',
                changed_by=restored_by,
                change_reason=f"Restored from version {version_number}"
            )
            
            session.commit()
            return True
    
    def get_latest_version(self) -> Optional[Dict[str, Any]]:
        """
        Get the most recent configuration version.
        
        Returns:
            Latest version information, or None if no versions exist
        """
        with self._get_session() as session:
            stmt = (
                select(ConfigVersion)
                .order_by(ConfigVersion.version_number.desc())
                .limit(1)
            )
            
            version = session.execute(stmt).scalar_one_or_none()
            
            if not version:
                return None
                
            return {
                'id': version.id,
                'version_number': version.version_number,
                'config_hash': version.config_hash,
                'created_at': version.created_at,
                'created_by': version.created_by,
                'description': version.description,
                'is_baseline': version.is_baseline
            }
    
    # --- System Metadata ---
    def set_metadata(self, key: str, value: str) -> None:
        """
        Set a metadata value.
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        with self._get_session() as session:
            # Try to update existing
            stmt = (
                update(SystemMetadata)
                .where(SystemMetadata.key == key)
                .values(value=value, updated_at=func.now())
            )
            result = session.execute(stmt)
            
            # If no rows were updated, insert new
            if result.rowcount == 0:
                metadata = SystemMetadata(key=key, value=value)
                session.add(metadata)
            
            session.commit()
    
    def get_metadata(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a metadata value.
        
        Args:
            key: Metadata key
            default: Default value if key not found
            
        Returns:
            Metadata value or default if not found
        """
        with self._get_session() as session:
            stmt = select(SystemMetadata).where(SystemMetadata.key == key)
            result = session.execute(stmt).scalar_one_or_none()
            return result.value if result else default
    
    # --- Instance Management ---
    def ensure_instance_id(self) -> str:
        """
        Ensure an instance ID exists, creating one if needed.
        
        Returns:
            The instance ID
        """
        instance_id = self.get_metadata("instance_id")
        if not instance_id:
            instance_id = f"instance_{uuid.uuid4().hex[:8]}"
            self.set_metadata("instance_id", instance_id)
        return instance_id
    
    def get_instance_name(self) -> str:
        """
        Get the instance name, defaulting to instance ID if not set.
        
        Returns:
            Instance name or ID
        """
        return self.get_metadata("instance_name") or self.ensure_instance_id()
    
    def set_instance_name(self, name: str) -> None:
        """
        Set the instance name.
        
        Args:
            
        Returns:
            Number of versions deleted
        """
        with self._get_session() as session:
            # Find the version number to keep (Nth most recent)
            stmt = (
                select(ConfigVersion.version_number)
                .order_by(ConfigVersion.version_number.desc())
                .offset(10 - 1)
                .limit(1)
            )
            result = session.execute(stmt).scalar_one_or_none()
            
            if not result:
                return 0
                
            # Delete versions older than the one we found
            stmt = delete(ConfigVersion).where(ConfigVersion.version_number < result)
            result = session.execute(stmt)
            session.commit()
            
            return result.rowcount or 0

    def cleanup_old_versions(self, keep_versions: int = 10) -> list[int]:
        """
        Delete old versions.
        
        Args:
            keep_versions: Number of versions to keep
            
        Returns:
            List of deleted version numbers
        """
        with self._get_session() as session:
            # Find the version number to keep (Nth most recent)
            stmt = (
                select(ConfigVersion.version_number)
                .order_by(ConfigVersion.version_number.desc())
                .offset(keep_versions - 1)
                .limit(1)
            )
            result = session.execute(stmt).scalar_one_or_none()
            
            if not result:
                return []
                
            # Delete versions older than the one we found
            stmt = delete(ConfigVersion).where(ConfigVersion.version_number < result)
            session.execute(stmt)
            session.commit()
            
            # Return the deleted version numbers
            stmt = select(ConfigVersion.version_number).where(ConfigVersion.version_number < result)
            return [v[0] for v in session.execute(stmt).all()]

    

    def get_latest_version(self) -> dict[str, Any] | None:
        cur = self._conn.execute(
            "SELECT id, version_number, config_json, config_hash, created_at, created_by, description, is_baseline FROM config_versions ORDER BY version_number DESC LIMIT 1"
        )
        row = cur.fetchone()
        return dict(row) if row else None

    # --- System metadata ---
    def set_metadata(self, key: str, value: str) -> None:
        ts = _utc_now_iso()
        with self._conn:
            self._conn.execute(
                "INSERT INTO system_metadata(key, value, updated_at) VALUES(?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, value, ts),
            )

    def get_metadata(self, key: str) -> str | None:
        cur = self._conn.execute("SELECT value FROM system_metadata WHERE key=?", (key,))
        row = cur.fetchone()
        return str(row[0]) if row else None

    def ensure_instance_id(self) -> str:
        iid = self.get_metadata("instance_id")
        if iid:
            return iid
        iid = str(uuid.uuid4())
        self.set_metadata("instance_id", iid)
        return iid

    def get_instance_name(self) -> str:
        name = self.get_metadata("instance_name")
        return name or "tacacs-server"

    def set_instance_name(self, name: str) -> None:
        self.set_metadata("instance_name", name)

    # --- Utilities ---
    def execute(self, sql: str, params: Iterable[Any] | None = None) -> None:
        with self._conn:
            self._conn.execute(sql, tuple(params or ()))
