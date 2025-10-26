"""Configuration override and history store using SQLite.

Provides durable storage for runtime configuration changes, their audit
history, and versioned snapshots of complete configurations.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
import threading
import uuid
from pathlib import Path
from typing import Any, Iterable


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def compute_config_hash(config_json: str | bytes) -> str:
    data = config_json.encode("utf-8") if isinstance(config_json, str) else config_json
    return hashlib.sha256(data).hexdigest()


class ConfigStore:
    """SQLite-backed configuration override and history store."""

    def __init__(self, db_path: str = "data/config_store.db") -> None:
        self.db_path = db_path
        Path(os.path.dirname(self.db_path) or ".").mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA foreign_keys = ON")
        self._ensure_schema()
        self._lock = threading.RLock()

    # --- schema management ---
    def _ensure_schema(self) -> None:
        with self._conn:
            # config_overrides: active overrides with unique(section,key) while active
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS config_overrides (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    section TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    value_type TEXT,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            # Unique index while active (partial unique index)
            self._conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS ux_config_overrides_active
                ON config_overrides(section, key)
                WHERE active = 1
                """
            )

            # config_history: audit of changes
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS config_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    section TEXT NOT NULL,
                    key TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    value_type TEXT,
                    changed_at TEXT NOT NULL,
                    changed_by TEXT NOT NULL,
                    change_reason TEXT,
                    source_ip TEXT,
                    config_hash TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_config_history_changed_at
                ON config_history(changed_at)
                """
            )

            # config_versions: snapshots of full configurations
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS config_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_number INTEGER UNIQUE NOT NULL,
                    config_json TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    description TEXT,
                    is_baseline INTEGER NOT NULL DEFAULT 0
                )
                """
            )

            # system_metadata: simple key/value store
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS system_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    # --- basic helpers ---
    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    # --- value encoding/decoding helpers ---
    @staticmethod
    def _encode_value(value: Any, value_type: str) -> str:
        if value_type in ("string", "str"):
            return str(value)
        if value_type in ("integer", "int"):
            return str(int(value))
        if value_type in ("boolean", "bool"):
            return "1" if bool(value) else "0"
        # Default to JSON for complex types (json, list, dict, unknown)
        return json.dumps(value)

    @staticmethod
    def _decode_value(value_str: str, value_type: str) -> Any:
        if value_type in ("string", "str"):
            return value_str
        if value_type in ("integer", "int"):
            try:
                return int(value_str)
            except Exception:
                return 0
        if value_type in ("boolean", "bool"):
            return value_str in ("1", "true", "True", "yes")
        try:
            return json.loads(value_str)
        except Exception:
            return value_str

    # --- Overrides ---
    def upsert_override(
        self,
        *,
        section: str,
        key: str,
        value: Any,
        value_type: str,
        created_by: str = "system",
    ) -> int:
        """Insert or replace an active override. Returns row id."""
        val_str = json.dumps(value) if not isinstance(value, str) else value
        ts = _utc_now_iso()
        with self._conn:
            # Soft-delete existing active override (if any)
            self._conn.execute(
                "UPDATE config_overrides SET active=0 WHERE section=? AND key=? AND active=1",
                (section, key),
            )
            cur = self._conn.execute(
                """
                INSERT INTO config_overrides(section, key, value, value_type, created_at, created_by, active)
                VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (section, key, val_str, value_type, ts, created_by),
            )
            return int(cur.lastrowid)

    def list_overrides(self) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT id, section, key, value, value_type, created_at, created_by, active FROM config_overrides WHERE active=1"
        )
        return [dict(row) for row in cur.fetchall()]

    # High-level API similar to DeviceStore
    # Override management
    def set_override(
        self,
        section: str,
        key: str,
        value: Any,
        value_type: str,
        changed_by: str,
        reason: str | None = None,
    ) -> None:
        with self._lock:
            # Look up old value for history
            old = self.get_override(section, key)
            self.upsert_override(
                section=section,
                key=key,
                value=value if value_type not in ("json", "list") else value,
                value_type=value_type,
                created_by=changed_by,
            )
            self.record_change(
                section,
                key,
                old_value=old[0] if old else None,
                new_value=value,
                value_type=value_type,
                changed_by=changed_by,
                reason=reason,
            )

    def get_override(self, section: str, key: str) -> tuple[Any, str] | None:
        cur = self._conn.execute(
            "SELECT value, value_type FROM config_overrides WHERE section=? AND key=? AND active=1",
            (section, key),
        )
        row = cur.fetchone()
        if not row:
            return None
        vtype = str(row["value_type"]) if row["value_type"] is not None else "json"
        return self._decode_value(str(row["value"]), vtype), vtype

    def delete_override(self, section: str, key: str, changed_by: str) -> None:
        with self._lock, self._conn:
            # fetch for history
            cur = self._conn.execute(
                "SELECT value, value_type FROM config_overrides WHERE section=? AND key=? AND active=1",
                (section, key),
            )
            row = cur.fetchone()
            old_val: Any | None = None
            old_type = "json"
            if row:
                old_type = str(row["value_type"]) if row["value_type"] else "json"
                old_val = self._decode_value(str(row["value"]), old_type)
            self._conn.execute(
                "UPDATE config_overrides SET active=0 WHERE section=? AND key=? AND active=1",
                (section, key),
            )
        self.record_change(
            section,
            key,
            old_value=old_val,
            new_value=None,
            value_type=old_type,
            changed_by=changed_by,
            reason="delete override",
        )

    def get_all_overrides(self) -> dict[str, dict[str, tuple[Any, str]]]:
        cur = self._conn.execute(
            "SELECT section, key, value, value_type FROM config_overrides WHERE active=1"
        )
        result: dict[str, dict[str, tuple[Any, str]]] = {}
        for row in cur.fetchall():
            sec = str(row["section"]).strip()
            key = str(row["key"]).strip()
            vtype = str(row["value_type"]) if row["value_type"] else "json"
            val = self._decode_value(str(row["value"]), vtype)
            result.setdefault(sec, {})[key] = (val, vtype)
        return result

    def clear_overrides(self, section: str | None = None, changed_by: str = "system") -> None:
        with self._lock:
            if section is None:
                rows = self.list_overrides()
                for r in rows:
                    self.delete_override(str(r["section"]), str(r["key"]), changed_by)
            else:
                rows = self._conn.execute(
                    "SELECT key FROM config_overrides WHERE section=? AND active=1",
                    (section,),
                ).fetchall()
                for r in rows:
                    self.delete_override(section, str(r["key"]), changed_by)

    # --- History ---
    def add_history(
        self,
        *,
        section: str,
        key: str,
        old_value: Any,
        new_value: Any,
        value_type: str,
        changed_by: str,
        change_reason: str | None = None,
        source_ip: str | None = None,
        full_config_json: str | bytes = b"",
    ) -> int:
        ts = _utc_now_iso()
        old_s = json.dumps(old_value) if not isinstance(old_value, str) else old_value
        new_s = json.dumps(new_value) if not isinstance(new_value, str) else new_value
        cfg_hash = compute_config_hash(full_config_json)
        with self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO config_history(section, key, old_value, new_value, value_type, changed_at, changed_by, change_reason, source_ip, config_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    section,
                    key,
                    old_s,
                    new_s,
                    value_type,
                    ts,
                    changed_by,
                    change_reason,
                    source_ip,
                    cfg_hash,
                ),
            )
            return int(cur.lastrowid)

    # History wrapper for API parity
    def record_change(
        self,
        section: str,
        key: str,
        old_value: Any,
        new_value: Any,
        value_type: str,
        changed_by: str,
        reason: str | None = None,
        source_ip: str | None = None,
    ) -> None:
        self.add_history(
            section=section,
            key=key,
            old_value=old_value,
            new_value=new_value,
            value_type=value_type,
            changed_by=changed_by,
            change_reason=reason,
            source_ip=source_ip,
            full_config_json=b"",
        )

    def get_history(
        self, section: str | None = None, key: str | None = None, limit: int = 100, offset: int = 0
    ) -> list[dict]:
        sql = "SELECT * FROM config_history"
        params: list[Any] = []
        clauses: list[str] = []
        if section:
            clauses.append("section=?")
            params.append(section)
        if key:
            clauses.append("key=?")
            params.append(key)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY changed_at DESC LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])
        cur = self._conn.execute(sql, tuple(params))
        return [dict(row) for row in cur.fetchall()]

    def get_change_by_id(self, change_id: int) -> dict | None:
        cur = self._conn.execute(
            "SELECT * FROM config_history WHERE id=?", (int(change_id),)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    # --- Versions ---
    def add_version(
        self,
        *,
        version_number: int,
        config_json: str | bytes,
        created_by: str,
        description: str | None = None,
        is_baseline: bool = False,
    ) -> int:
        ts = _utc_now_iso()
        cfg_json_str = config_json if isinstance(config_json, str) else config_json.decode("utf-8")
        cfg_hash = compute_config_hash(cfg_json_str)
        with self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO config_versions(version_number, config_json, config_hash, created_at, created_by, description, is_baseline)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(version_number),
                    cfg_json_str,
                    cfg_hash,
                    ts,
                    created_by,
                    description,
                    1 if is_baseline else 0,
                ),
            )
            return int(cur.lastrowid)

    def create_version(
        self,
        config_dict: dict,
        created_by: str,
        description: str | None = None,
        is_baseline: bool = False,
    ) -> int:
        # Determine next version_number
        cur = self._conn.execute("SELECT COALESCE(MAX(version_number), 0) FROM config_versions")
        row = cur.fetchone()
        next_ver = int(row[0]) + 1 if row else 1
        cfg_json = json.dumps(config_dict, sort_keys=True)
        self.add_version(
            version_number=next_ver,
            config_json=cfg_json,
            created_by=created_by,
            description=description,
            is_baseline=is_baseline,
        )
        return next_ver

    def get_version(self, version_number: int) -> dict | None:
        cur = self._conn.execute(
            "SELECT * FROM config_versions WHERE version_number=?",
            (int(version_number),),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def list_versions(self, limit: int = 50) -> list[dict]:
        cur = self._conn.execute(
            """
            SELECT id, version_number, config_hash, created_at, created_by, description, is_baseline
            FROM config_versions ORDER BY version_number DESC LIMIT ?
            """,
            (int(limit),),
        )
        return [dict(row) for row in cur.fetchall()]

    def restore_version(self, version_number: int, restored_by: str) -> dict:
        row = self.get_version(version_number)
        if not row:
            raise ValueError(f"Version {version_number} not found")
        cfg_json = row.get("config_json")
        if not isinstance(cfg_json, str):
            raise ValueError("Invalid configuration payload for version")
        # Record a history entry noting a restore occurred
        self.add_history(
            section="system",
            key="restore_version",
            old_value=None,
            new_value=version_number,
            value_type="integer",
            changed_by=restored_by,
            change_reason="restore version",
            source_ip=None,
            full_config_json=cfg_json,
        )
        return json.loads(cfg_json)

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
