from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class BackupExecutionStore:
    """SQLite store for backup executions and destinations."""

    def __init__(self, db_path: str = "data/backup_executions.db") -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA foreign_keys = ON")
        self._ensure_schema()
        try:
            from tacacs_server.utils.maintenance import get_db_manager

            get_db_manager().register(self, self.close)
        except Exception as exc:
            logger.warning(
                "Failed to register execution store for maintenance",
                error=str(exc),
                db_path=self.db_path,
            )

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception as exc:
            logger.warning(
                "BackupExecutionStore close failed",
                error=str(exc),
                db_path=self.db_path,
            )

    def _ensure_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS backup_executions (
                    id TEXT PRIMARY KEY,
                    destination_id TEXT,
                    backup_filename TEXT,
                    backup_path TEXT,
                    triggered_by TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    size_bytes INTEGER,
                    compressed_size_bytes INTEGER,
                    files_included INTEGER,
                    error_message TEXT,
                    manifest_json TEXT
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_backup_exec_started_at ON backup_executions(started_at)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_backup_exec_status ON backup_executions(status)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS ix_backup_exec_dest ON backup_executions(destination_id)"
            )

            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS backup_destinations (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    type TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    config_json TEXT NOT NULL,
                    retention_days INTEGER NOT NULL DEFAULT 30,
                    retention_strategy TEXT DEFAULT 'simple',
                    retention_config_json TEXT,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    last_backup_at TEXT,
                    last_backup_status TEXT
                )
                """
            )
            # Backfill columns for existing installations (best-effort)
            try:
                self._conn.execute(
                    "ALTER TABLE backup_destinations ADD COLUMN retention_strategy TEXT DEFAULT 'simple'"
                )
            except Exception as exc:
                logger.debug(
                    "Retention strategy column already exists or failed to add",
                    error=str(exc),
                )
            try:
                self._conn.execute(
                    "ALTER TABLE backup_destinations ADD COLUMN retention_config_json TEXT"
                )
            except Exception as exc:
                logger.debug(
                    "Retention config column already exists or failed to add",
                    error=str(exc),
                )

    # --- executions ---
    def create_execution(
        self, execution_id: str, destination_id: str, triggered_by: str
    ) -> dict:
        row = {
            "id": execution_id,
            "destination_id": destination_id,
            "triggered_by": triggered_by,
            "started_at": _now_iso(),
            "status": "running",
        }
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO backup_executions(id, destination_id, triggered_by, started_at, status)
                VALUES(?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["destination_id"],
                    row["triggered_by"],
                    row["started_at"],
                    row["status"],
                ),
            )
        return row

    def update_execution(self, execution_id: str, **updates) -> None:
        if not updates:
            return
        keys = []
        params = []
        for k, v in updates.items():
            keys.append(f"{k}=?")
            if isinstance(v, (dict, list)) and k == "manifest_json":
                params.append(json.dumps(v))
            else:
                params.append(v)
        params.append(execution_id)
        with self._conn:
            self._conn.execute(
                f"UPDATE backup_executions SET {', '.join(keys)} WHERE id=?",
                tuple(params),
            )

    def get_execution(self, execution_id: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT * FROM backup_executions WHERE id=?", (execution_id,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def list_executions(
        self, limit: int = 100, offset: int = 0, status: str | None = None
    ) -> list[dict]:
        sql = "SELECT * FROM backup_executions"
        params: list[Any] = []
        if status:
            sql += " WHERE status=?"
            params.append(status)
        sql += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])
        cur = self._conn.execute(sql, tuple(params))
        return [dict(r) for r in cur.fetchall()]

    def list_backups_for_destination(
        self, destination_id: str, limit: int = 5
    ) -> list[dict]:
        cur = self._conn.execute(
            """
            SELECT
                backup_filename,
                backup_path,
                size_bytes,
                compressed_size_bytes,
                completed_at,
                started_at
            FROM backup_executions
            WHERE destination_id=? AND status='completed' AND backup_path IS NOT NULL
            ORDER BY completed_at DESC, started_at DESC
            LIMIT ?
            """,
            (destination_id, int(limit)),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_recent_executions(self, hours: int = 24) -> list[dict]:
        cutoff = (datetime.now(UTC) - timedelta(hours=int(hours))).isoformat()
        cur = self._conn.execute(
            "SELECT * FROM backup_executions WHERE started_at >= ? ORDER BY started_at DESC",
            (cutoff,),
        )
        return [dict(r) for r in cur.fetchall()]

    def delete_old_executions(self, days: int = 90) -> int:
        cutoff = (datetime.now(UTC) - timedelta(days=int(days))).isoformat()
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM backup_executions WHERE started_at < ?", (cutoff,)
            )
            return int(cur.rowcount or 0)

    # --- destinations ---
    def create_destination(
        self,
        name: str,
        dest_type: str,
        config: dict,
        created_by: str,
        *,
        retention_days: int = 30,
        retention_strategy: str = "simple",
        retention_config: dict | None = None,
        **kwargs,
    ) -> str:
        dest_id = str(uuid.uuid4())
        created_at = _now_iso()
        cfg_json = json.dumps(config or {})
        enabled = int(bool(kwargs.get("enabled", 1)))
        retention_days = int(retention_days)
        retention_strategy = str(retention_strategy or "simple").lower()
        if retention_config is None:
            retention_config = {"keep_days": retention_days}
        retention_cfg_json = json.dumps(retention_config)
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO backup_destinations(
                    id, name, type, enabled, config_json, retention_days, retention_strategy, retention_config_json, created_at, created_by
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dest_id,
                    name,
                    dest_type,
                    enabled,
                    cfg_json,
                    retention_days,
                    retention_strategy,
                    retention_cfg_json,
                    created_at,
                    created_by,
                ),
            )
        return dest_id

    def update_destination(self, dest_id: str, **updates) -> None:
        if not updates:
            return
        keys = []
        params = []
        for k, v in updates.items():
            keys.append(f"{k}=?")
            if k in ("config_json", "retention_config_json") and not isinstance(v, str):
                params.append(json.dumps(v))
            else:
                params.append(v)
        params.append(dest_id)
        with self._conn:
            self._conn.execute(
                f"UPDATE backup_destinations SET {', '.join(keys)} WHERE id=?",
                tuple(params),
            )

    def get_destination(self, dest_id: str) -> dict | None:
        cur = self._conn.execute(
            "SELECT * FROM backup_destinations WHERE id=?", (dest_id,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def list_destinations(self, enabled_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM backup_destinations"
        params: list[Any] = []
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY created_at DESC"
        cur = self._conn.execute(sql, tuple(params))
        return [dict(r) for r in cur.fetchall()]

    def delete_destination(self, dest_id: str) -> bool:
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM backup_destinations WHERE id=?", (dest_id,)
            )
            return cur.rowcount > 0

    def set_last_backup(
        self, dest_id: str, status: str, timestamp: str | None = None
    ) -> None:
        ts = timestamp or _now_iso()
        with self._conn:
            self._conn.execute(
                "UPDATE backup_destinations SET last_backup_at=?, last_backup_status=? WHERE id=?",
                (ts, status, dest_id),
            )
