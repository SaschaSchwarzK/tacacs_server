"""SQLite-backed persistence for local users and groups."""

from __future__ import annotations

import json
import logging
import tempfile
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, select

from tacacs_server.db.engine import Base, get_session_factory, session_scope
from tacacs_server.db.models import LocalUser, LocalUserGroup

from .local_models import LocalUserGroupRecord, LocalUserRecord

logger = logging.getLogger(__name__)

UNSET = object()


class LocalAuthStore:
    """Persistent storage helper for local authentication data."""

    def __init__(self, db_path: Path | str = "data/local_auth.db") -> None:
        # Resolve and validate path to prevent path traversal
        self.db_path = Path(db_path).resolve()
        # Ensure path is within expected directory structure (allow pytest temp dirs)
        cwd = str(Path.cwd().resolve())
        db_str = str(self.db_path)
        # Allow paths within:
        # - Current working directory tree
        # - Pytest temp directories
        # - System temporary directory (handles macOS /private prefix)
        sys_tmp = tempfile.gettempdir()
        sys_tmp_private = (
            "/private" + sys_tmp if not sys_tmp.startswith("/private") else sys_tmp
        )
        allowed_prefixes = (cwd, sys_tmp, sys_tmp_private)
        if not (db_str.startswith(allowed_prefixes) or "/pytest-" in db_str):
            raise ValueError(f"Database path outside allowed directory: {self.db_path}")
        if not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._session_factory = self._create_session_factory()

        # Register with maintenance mode manager
        try:
            from tacacs_server.utils.maintenance import get_db_manager

            get_db_manager().register(self)
        except Exception as exc:
            logger.warning(
                "Failed to register local auth store for maintenance: %s", exc
            )

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------
    def _create_session_factory(self):
        factory = get_session_factory(str(self.db_path))
        engine = getattr(factory, "bind", None) or getattr(factory, "engine", None)
        if engine is None:
            raise RuntimeError("SQLAlchemy engine not initialized for local auth store")
        Base.metadata.create_all(engine)
        return factory

    def close(self) -> None:
        """Dispose the underlying SQLAlchemy engine."""
        with self._lock:
            engine = self._session_factory.kw.get("bind")
            if engine:
                try:
                    engine.dispose()
                except Exception as exc:
                    logger.warning("Failed to dispose local auth engine: %s", exc)

    def reload(self) -> None:
        """Recreate the session factory and ensure schema."""
        with self._lock:
            try:
                engine = self._session_factory.kw.get("bind")
                if engine:
                    engine.dispose()
            except Exception:
                logger.warning("Failed to dispose local auth engine before reload")
            self._session_factory = self._create_session_factory()

    # ------------------------------------------------------------------
    # JSON helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _dump_list(values: Iterable[str] | None) -> str:
        return json.dumps(list(values) if values is not None else [])

    @staticmethod
    def _load_list(payload: str | None) -> list[str]:
        if not payload:
            return []
        try:
            data = json.loads(payload)
            if isinstance(data, list):
                return [str(item) for item in data if isinstance(item, str)]
        except json.JSONDecodeError as exc:
            logger.debug("Failed to decode list payload for local store: %s", exc)
        return []

    @staticmethod
    def _dump_dict(payload) -> str:
        if not payload:
            return "{}"
        return json.dumps(payload)

    @staticmethod
    def _load_dict(payload: str | None):
        if not payload:
            return {}
        try:
            data = json.loads(payload)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError as exc:
            logger.debug("Failed to decode dict payload for local store: %s", exc)
        return {}

    @staticmethod
    @staticmethod
    def _now() -> datetime:
        return datetime.now(UTC).replace(microsecond=0)

    @staticmethod
    def _parse_datetime(value) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return None
        return None

    # ------------------------------------------------------------------
    # User operations
    # ------------------------------------------------------------------
    def list_users(self) -> list[LocalUserRecord]:
        with self._lock, session_scope(self._session_factory) as session:
            users = session.execute(
                select(LocalUser).order_by(LocalUser.username)
            ).scalars()
            return [self._row_to_user(user) for user in users]

    def get_user(self, username: str) -> LocalUserRecord | None:
        with self._lock, session_scope(self._session_factory) as session:
            user = session.execute(
                select(LocalUser).where(LocalUser.username == username)
            ).scalar_one_or_none()
            return self._row_to_user(user) if user else None

    def insert_user(self, record: LocalUserRecord) -> LocalUserRecord:
        with self._lock, session_scope(self._session_factory) as session:
            now_ts = self._now()
            user = LocalUser(
                username=record.username,
                password=record.password,
                password_hash=record.password_hash,
                privilege_level=int(record.privilege_level),
                service=record.service,
                groups=self._dump_list(record.groups),
                enabled=1 if record.enabled else 0,
                description=record.description,
                created_at=now_ts,
                updated_at=now_ts,
            )
            session.add(user)
        result = self.get_user(record.username)
        if result is None:
            raise RuntimeError(f"Failed to retrieve user after insert: {record.username}")
        return result

    def update_user(
        self,
        username: str,
        *,
        privilege_level: int | None = None,
        service: str | None = None,
        groups: Iterable[str] | None = None,
        enabled: bool | None = None,
        description: str | None = None,
    ) -> LocalUserRecord | None:
        with self._lock, session_scope(self._session_factory) as session:
            user: LocalUser | None = session.execute(
                select(LocalUser).where(LocalUser.username == username)
            ).scalar_one_or_none()
            if user is None:
                return None
            if privilege_level is not None:
                user.privilege_level = int(privilege_level)
            if service is not None:
                user.service = service
            if groups is not None:
                user.groups = self._dump_list(groups)
            if enabled is not None:
                user.enabled = 1 if enabled else 0
            if description is not None:
                user.description = description
            user.updated_at = self._now()
        return self.get_user(username)

    def set_user_password(
        self,
        username: str,
        *,
        password: str | None,
        password_hash: str | None,
    ) -> LocalUserRecord | None:
        with self._lock, session_scope(self._session_factory) as session:
            user: LocalUser | None = session.execute(
                select(LocalUser).where(LocalUser.username == username)
            ).scalar_one_or_none()
            if user is None:
                return None
            user.password = password
            user.password_hash = password_hash
            user.updated_at = self._now()
        return self.get_user(username)

    def delete_user(self, username: str) -> bool:
        with self._lock, session_scope(self._session_factory) as session:
            result = session.execute(
                delete(LocalUser).where(LocalUser.username == username)
            )
            return result.rowcount > 0

    # ------------------------------------------------------------------
    # Group operations
    # ------------------------------------------------------------------
    def list_groups(self) -> list[LocalUserGroupRecord]:
        with self._lock, session_scope(self._session_factory) as session:
            groups = session.execute(
                select(LocalUserGroup).order_by(LocalUserGroup.name)
            ).scalars()
            return [self._row_to_group(group) for group in groups]

    def get_group(self, name: str) -> LocalUserGroupRecord | None:
        with self._lock, session_scope(self._session_factory) as session:
            group = session.execute(
                select(LocalUserGroup).where(LocalUserGroup.name == name)
            ).scalar_one_or_none()
            return self._row_to_group(group) if group else None

    def insert_group(self, record: LocalUserGroupRecord) -> LocalUserGroupRecord:
        metadata_payload = dict(record.metadata or {})
        # Persist privilege_level in metadata; radius_group is stored in its
        # own column.
        metadata_payload["privilege_level"] = int(record.privilege_level)
        with self._lock, session_scope(self._session_factory) as session:
            now_ts = self._now()
            group = LocalUserGroup(
                name=record.name,
                description=record.description,
            metadata_json=self._dump_dict(metadata_payload),
            ldap_group=record.ldap_group,
            okta_group=record.okta_group,
            radius_group=record.radius_group,
                created_at=now_ts,
                updated_at=now_ts,
            )
            session.add(group)
        result = self.get_group(record.name)
        if result is None:
            raise RuntimeError(f"Failed to retrieve group after insert: {record.name}")
        return result

    def update_group(
        self,
        name: str,
        *,
        description: str | None = None,
        metadata: dict | None = None,
        ldap_group: str | None | object = UNSET,
        okta_group: str | None | object = UNSET,
        radius_group: str | None | object = UNSET,
    ) -> LocalUserGroupRecord | None:
        with self._lock, session_scope(self._session_factory) as session:
            group: LocalUserGroup | None = session.execute(
                select(LocalUserGroup).where(LocalUserGroup.name == name)
            ).scalar_one_or_none()
            if group is None:
                return None
            if description is not None:
                group.description = description
            existing_privilege = None
            if metadata is not None and "privilege_level" not in metadata:
                current = self._row_to_group(group)
                existing_privilege = current.privilege_level if current else None
            if metadata is not None:
                metadata_payload = dict(metadata)
                if "privilege_level" not in metadata_payload:
                    metadata_payload["privilege_level"] = (
                        existing_privilege if existing_privilege is not None else 1
                    )
                group.metadata_json = self._dump_dict(metadata_payload)
            if ldap_group is not UNSET:
                group.ldap_group = ldap_group
            if okta_group is not UNSET:
                group.okta_group = okta_group
            if radius_group is not UNSET:
                group.radius_group = radius_group
            group.updated_at = self._now()
        return self.get_group(name)

    def delete_group(self, name: str) -> bool:
        with self._lock, session_scope(self._session_factory) as session:
            result = session.execute(
                delete(LocalUserGroup).where(LocalUserGroup.name == name)
            )
            return result.rowcount > 0

    # ------------------------------------------------------------------
    # Row conversion helpers
    # ------------------------------------------------------------------
    def _row_to_user(self, row: LocalUser) -> LocalUserRecord:
        return LocalUserRecord(
            username=row.username,
            privilege_level=int(row.privilege_level),
            service=row.service,
            groups=self._load_list(row.groups),
            enabled=bool(row.enabled),
            description=row.description,
            password=row.password,
            password_hash=row.password_hash,
            id=row.id,
            created_at=self._parse_datetime(row.created_at),
            updated_at=self._parse_datetime(row.updated_at),
        )

    def _row_to_group(self, row: LocalUserGroup) -> LocalUserGroupRecord:
        metadata = self._load_dict(row.metadata_json)
        privilege = metadata.pop("privilege_level", 1)
        try:
            privilege = int(privilege)
        except (TypeError, ValueError):
            privilege = 1
        return LocalUserGroupRecord(
            name=row.name,
            description=row.description,
            metadata=metadata,
            ldap_group=row.ldap_group,
            okta_group=row.okta_group,
            radius_group=row.radius_group,
            privilege_level=privilege,
            id=row.id,
            created_at=self._parse_datetime(row.created_at),
            updated_at=self._parse_datetime(row.updated_at),
        )
