"""SQLite-backed persistence for local users and groups."""
from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from .local_models import LocalUserGroupRecord, LocalUserRecord

UNSET = object()


class LocalAuthStore:
    """Persistent storage helper for local authentication data."""

    def __init__(self, db_path: Path | str = "data/local_auth.db") -> None:
        # Resolve and validate path to prevent path traversal
        self.db_path = Path(db_path).resolve()
        # Ensure path is within expected directory structure (allow pytest temp dirs)
        cwd = str(Path.cwd().resolve())
        db_str = str(self.db_path)
        if not (db_str.startswith(cwd) or "/pytest-" in db_str):
            raise ValueError(f"Database path outside allowed directory: {self.db_path}")
        if not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = self._open_connection()
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------
    def _open_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def reload(self) -> None:
        """Re-open the underlying SQLite connection."""
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = self._open_connection()
            self._ensure_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _ensure_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS local_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT,
                    password_hash TEXT,
                    privilege_level INTEGER NOT NULL DEFAULT 1,
                    service TEXT NOT NULL DEFAULT 'exec',
                    shell_command TEXT NOT NULL DEFAULT '[]',
                    groups TEXT NOT NULL DEFAULT '["users"]',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    description TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS local_user_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    metadata TEXT,
                    ldap_group TEXT,
                    okta_group TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            self._conn.commit()

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
        except json.JSONDecodeError:
            pass
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
        except json.JSONDecodeError:
            pass
        return {}

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).replace(microsecond=0).isoformat()

    # ------------------------------------------------------------------
    # User operations
    # ------------------------------------------------------------------
    def list_users(self) -> list[LocalUserRecord]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM local_users ORDER BY username")
            return [self._row_to_user(row) for row in cur.fetchall()]

    def get_user(self, username: str) -> LocalUserRecord | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM local_users WHERE username = ?",
                (username,),
            )
            row = cur.fetchone()
            return self._row_to_user(row) if row else None

    def insert_user(self, record: LocalUserRecord) -> LocalUserRecord:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO local_users (
                    username, password, password_hash, privilege_level,
                    service, shell_command, groups, enabled, description,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.username,
                    record.password,
                    record.password_hash,
                    record.privilege_level,
                    record.service,
                    self._dump_list(record.shell_command),
                    self._dump_list(record.groups),
                    1 if record.enabled else 0,
                    record.description,
                    self._now(),
                    self._now(),
                ),
            )
            self._conn.commit()
            return self.get_user(record.username)

    def update_user(
        self,
        username: str,
        *,
        privilege_level: int | None = None,
        service: str | None = None,
        shell_command: Iterable[str] | None = None,
        groups: Iterable[str] | None = None,
        enabled: bool | None = None,
        description: str | None = None,
    ) -> LocalUserRecord | None:
        assignments = []
        params: list = []
        if privilege_level is not None:
            assignments.append("privilege_level = ?")
            params.append(int(privilege_level))
        if service is not None:
            assignments.append("service = ?")
            params.append(service)
        if shell_command is not None:
            assignments.append("shell_command = ?")
            params.append(self._dump_list(shell_command))
        if groups is not None:
            assignments.append("groups = ?")
            params.append(self._dump_list(groups))
        if enabled is not None:
            assignments.append("enabled = ?")
            params.append(1 if enabled else 0)
        if description is not None:
            assignments.append("description = ?")
            params.append(description)

        if not assignments:
            return self.get_user(username)

        assignments.append("updated_at = ?")
        params.append(self._now())
        params.append(username)

        with self._lock:
            cur = self._conn.execute(
                f"UPDATE local_users SET {', '.join(assignments)} WHERE username = ?",
                params,
            )
            if cur.rowcount == 0:
                self._conn.rollback()
                return None
            self._conn.commit()
            return self.get_user(username)

    def set_user_password(
        self,
        username: str,
        *,
        password: str | None,
        password_hash: str | None,
    ) -> LocalUserRecord | None:
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE local_users
                   SET password = ?,
                       password_hash = ?,
                       updated_at = ?
                 WHERE username = ?
                """,
                (password, password_hash, self._now(), username),
            )
            if cur.rowcount == 0:
                self._conn.rollback()
                return None
            self._conn.commit()
            return self.get_user(username)

    def delete_user(self, username: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM local_users WHERE username = ?",
                (username,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Group operations
    # ------------------------------------------------------------------
    def list_groups(self) -> list[LocalUserGroupRecord]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM local_user_groups ORDER BY lower(name)"
            )
            return [self._row_to_group(row) for row in cur.fetchall()]

    def get_group(self, name: str) -> LocalUserGroupRecord | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM local_user_groups WHERE name = ?",
                (name,),
            )
            row = cur.fetchone()
            return self._row_to_group(row) if row else None

    def insert_group(self, record: LocalUserGroupRecord) -> LocalUserGroupRecord:
        metadata_payload = dict(record.metadata or {})
        metadata_payload["privilege_level"] = int(record.privilege_level)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO local_user_groups (
                    name, description, metadata, ldap_group, okta_group,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.name,
                    record.description,
                    self._dump_dict(metadata_payload),
                    record.ldap_group,
                    record.okta_group,
                    self._now(),
                    self._now(),
                ),
            )
            self._conn.commit()
            return self.get_group(record.name)

    def update_group(
        self,
        name: str,
        *,
        description: str | None = None,
        metadata: dict | None = None,
        ldap_group: str | None | object = UNSET,
        okta_group: str | None | object = UNSET,
    ) -> LocalUserGroupRecord | None:
        assignments = []
        params: list = []
        if description is not None:
            assignments.append("description = ?")
            params.append(description)
        existing_privilege = None
        if metadata is not None and "privilege_level" not in metadata:
            existing = self.get_group(name)
            if existing:
                existing_privilege = existing.privilege_level
        if metadata is not None:
            metadata_payload = dict(metadata)
            if "privilege_level" not in metadata_payload:
                metadata_payload["privilege_level"] = (
                    existing_privilege if existing_privilege is not None else 1
                )
            assignments.append("metadata = ?")
            params.append(self._dump_dict(metadata_payload))
        if ldap_group is not UNSET:
            assignments.append("ldap_group = ?")
            params.append(ldap_group)
        if okta_group is not UNSET:
            assignments.append("okta_group = ?")
            params.append(okta_group)

        if not assignments:
            return self.get_group(name)

        assignments.append("updated_at = ?")
        params.append(self._now())
        params.append(name)

        with self._lock:
            cur = self._conn.execute(
                f"UPDATE local_user_groups SET {', '.join(assignments)} WHERE name = ?",
                params,
            )
            if cur.rowcount == 0:
                self._conn.rollback()
                return None
            self._conn.commit()
            return self.get_group(name)

    def delete_group(self, name: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM local_user_groups WHERE name = ?",
                (name,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Row conversion helpers
    # ------------------------------------------------------------------
    def _row_to_user(self, row: sqlite3.Row) -> LocalUserRecord:
        return LocalUserRecord(
            username=row["username"],
            privilege_level=int(row["privilege_level"]),
            service=row["service"],
            shell_command=self._load_list(row["shell_command"]),
            groups=self._load_list(row["groups"]),
            enabled=bool(row["enabled"]),
            description=row["description"],
            password=row["password"],
            password_hash=row["password_hash"],
        )

    def _row_to_group(self, row: sqlite3.Row) -> LocalUserGroupRecord:
        metadata = self._load_dict(row["metadata"])
        privilege = metadata.pop("privilege_level", 1)
        try:
            privilege = int(privilege)
        except (TypeError, ValueError):
            privilege = 1
        return LocalUserGroupRecord(
            name=row["name"],
            description=row["description"],
            metadata=metadata,
            ldap_group=row["ldap_group"],
            okta_group=row["okta_group"],
            privilege_level=privilege,
        )
