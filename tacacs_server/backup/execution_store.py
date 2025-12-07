from __future__ import annotations

# mypy: ignore-errors
import json
import os
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from alembic.config import Config
from sqlalchemy import select, update

from alembic import command
from tacacs_server.db.engine import Base, get_session_factory, session_scope
from tacacs_server.db.models import BackupDestination, BackupExecution
from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


def _now_dt() -> datetime:
    return datetime.now(UTC)


def _now_iso() -> str:
    return _now_dt().isoformat()


class BackupExecutionStore:
    """SQLAlchemy store for backup executions and destinations."""

    def __init__(self, db_path: str = "data/backup_executions.db") -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self._session_factory = get_session_factory(self.db_path)
        engine = getattr(self._session_factory, "bind", None) or getattr(
            self._session_factory, "engine", None
        )
        if engine is None:
            raise RuntimeError("Failed to initialize backup store engine")
        self._run_alembic_or_create(engine)
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
            engine = getattr(self._session_factory, "bind", None) or getattr(
                self._session_factory, "engine", None
            )
            if engine:
                engine.dispose()
        except Exception as exc:
            logger.warning(
                "BackupExecutionStore close failed",
                error=str(exc),
                db_path=self.db_path,
            )

    def _run_alembic_or_create(self, engine) -> None:
        """Run Alembic migrations if available; fallback to create_all."""
        from pathlib import Path

        project_root = Path(__file__).resolve().parents[2]
        ini_path = project_root / "alembic.ini"
        script_location = project_root / "alembic"
        if ini_path.exists() and script_location.exists():
            cfg = Config(str(ini_path))
            cfg.set_main_option("script_location", str(script_location))
            cfg.set_main_option("sqlalchemy.url", f"sqlite:///{self.db_path}")
            try:
                command.upgrade(cfg, "head")
            except Exception:
                logger.warning("Alembic migration failed; using create_all fallback")
        Base.metadata.create_all(engine)

    # --- executions ---
    def create_execution(
        self, execution_id: str, destination_id: str, triggered_by: str
    ) -> dict:
        with self._lock, session_scope(self._session_factory) as session:
            existing = session.get(BackupExecution, execution_id)
            if existing:
                session.execute(
                    update(BackupExecution)
                    .where(BackupExecution.id == execution_id)
                    .values(
                        destination_id=destination_id,
                        backup_filename=None,
                        backup_path=None,
                        triggered_by=triggered_by,
                        started_at=_now_dt(),
                        completed_at=None,
                        status="running",
                        size_bytes=None,
                        compressed_size_bytes=None,
                        files_included=None,
                        error_message=None,
                        manifest_json=None,
                    )
                )
                row = existing
            else:
                row = BackupExecution(
                    id=execution_id,
                    destination_id=destination_id,
                    triggered_by=triggered_by,
                    started_at=_now_dt(),
                    status="running",
                )
                session.add(row)
        return {
            "id": row.id,
            "destination_id": row.destination_id,
            "triggered_by": row.triggered_by,
            "started_at": row.started_at.isoformat(),
            "status": row.status,
        }

    @staticmethod
    def _coerce_dt(val: Any) -> Any:
        """Accept datetime or ISO8601 string; otherwise return as-is."""
        if isinstance(val, datetime):
            return val
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val)
            except Exception:
                return val
        return val

    def update_execution(self, execution_id: str, **updates) -> None:
        if not updates:
            return
        allowed_keys = {
            "status",
            "completed_at",
            "backup_filename",
            "backup_path",
            "size_bytes",
            "compressed_size_bytes",
            "files_included",
            "error_message",
            "manifest_json",
        }
        update_values: dict[str, Any] = {}
        for k, v in updates.items():
            if k not in allowed_keys:
                raise ValueError(f"Invalid field for update: {k}")
            if k == "manifest_json" and isinstance(v, (dict, list)):
                update_values[k] = json.dumps(v)
            elif k == "completed_at":
                update_values[k] = self._coerce_dt(v)
            else:
                update_values[k] = v
        with self._lock, session_scope(self._session_factory) as session:
            session.execute(
                update(BackupExecution)
                .where(BackupExecution.id == execution_id)
                .values(**update_values)
            )

    def get_execution(self, execution_id: str) -> dict | None:
        with self._lock, session_scope(self._session_factory) as session:
            row = session.get(BackupExecution, execution_id)
            return self._execution_to_dict(row) if row else None

    def list_executions(
        self, limit: int = 100, offset: int = 0, status: str | None = None
    ) -> list[dict]:
        with self._lock, session_scope(self._session_factory) as session:
            stmt = select(BackupExecution)
            if status:
                stmt = stmt.where(BackupExecution.status == status)
            stmt = (
                stmt.order_by(BackupExecution.started_at.desc())
                .limit(int(limit))
                .offset(int(offset))
            )
            rows = session.scalars(stmt).all()
            return [self._execution_to_dict(r) for r in rows]

    def list_backups_for_destination(
        self, destination_id: str, limit: int = 5
    ) -> list[dict]:
        with self._lock, session_scope(self._session_factory) as session:
            stmt = (
                select(BackupExecution)
                .where(
                    BackupExecution.destination_id == destination_id,
                    BackupExecution.status == "completed",
                    BackupExecution.backup_path.is_not(None),
                )
                .order_by(
                    BackupExecution.completed_at.desc(),
                    BackupExecution.started_at.desc(),
                )
                .limit(int(limit))
            )
            rows = session.scalars(stmt).all()
            return [
                {
                    "backup_filename": r.backup_filename,
                    "backup_path": r.backup_path,
                    "size_bytes": r.size_bytes,
                    "compressed_size_bytes": r.compressed_size_bytes,
                    "completed_at": r.completed_at,
                    "started_at": r.started_at,
                }
                for r in rows
            ]

    def get_recent_executions(self, hours: int = 24) -> list[dict]:
        cutoff = _now_dt() - timedelta(hours=int(hours))
        with self._lock, session_scope(self._session_factory) as session:
            stmt = (
                select(BackupExecution)
                .where(BackupExecution.started_at >= cutoff)
                .order_by(BackupExecution.started_at.desc())
            )
            rows = session.scalars(stmt).all()
            return [self._execution_to_dict(r) for r in rows]

    def delete_old_executions(self, days: int = 90) -> int:
        cutoff = _now_dt() - timedelta(days=int(days))
        with self._lock, session_scope(self._session_factory) as session:
            result = session.execute(
                BackupExecution.__table__.delete().where(
                    BackupExecution.started_at < cutoff
                )
            )
            return int(result.rowcount or 0)

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
        created_at = _now_dt()
        cfg_json = json.dumps(config or {})
        enabled = int(bool(kwargs.get("enabled", 1)))
        retention_days = int(retention_days)
        retention_strategy = str(retention_strategy or "simple").lower()
        if retention_config is None:
            retention_config = {"keep_days": retention_days}
        retention_cfg_json = json.dumps(retention_config)
        dest = BackupDestination(
            id=dest_id,
            name=name,
            type=dest_type,
            enabled=enabled,
            config_json=cfg_json,
            retention_days=retention_days,
            retention_strategy=retention_strategy,
            retention_config_json=retention_cfg_json,
            created_at=created_at,
            created_by=created_by,
        )
        with self._lock, session_scope(self._session_factory) as session:
            session.add(dest)
        return dest_id

    def update_destination(self, dest_id: str, **updates) -> None:
        if not updates:
            return
        allowed_keys = {
            "name",
            "type",
            "enabled",
            "config_json",
            "retention_days",
            "retention_strategy",
            "retention_config_json",
            "last_backup_at",
            "last_backup_status",
        }
        update_values: dict[str, Any] = {}
        for k, v in updates.items():
            if k not in allowed_keys:
                raise ValueError(f"Invalid field for update: {k}")
            if k in {"config_json", "retention_config_json"} and not isinstance(v, str):
                update_values[k] = json.dumps(v)
            elif k == "last_backup_at" and isinstance(v, str):
                try:
                    update_values[k] = datetime.fromisoformat(v)
                except ValueError:
                    update_values[k] = v
            else:
                update_values[k] = v
        with self._lock, session_scope(self._session_factory) as session:
            session.execute(
                update(BackupDestination)
                .where(BackupDestination.id == dest_id)
                .values(**update_values)
            )

    def get_destination(self, dest_id: str) -> dict | None:
        with self._lock, session_scope(self._session_factory) as session:
            row = session.get(BackupDestination, dest_id)
            return self._destination_to_dict(row) if row else None

    def list_destinations(self, enabled_only: bool = False) -> list[dict]:
        with self._lock, session_scope(self._session_factory) as session:
            stmt = select(BackupDestination)
            if enabled_only:
                stmt = stmt.where(BackupDestination.enabled == 1)
            stmt = stmt.order_by(BackupDestination.created_at.desc())
            rows = session.scalars(stmt).all()
            return [self._destination_to_dict(r) for r in rows]

    def delete_destination(self, dest_id: str) -> bool:
        with self._lock, session_scope(self._session_factory) as session:
            result = session.execute(
                BackupDestination.__table__.delete().where(
                    BackupDestination.id == dest_id
                )
            )
            return bool(result.rowcount)

    def set_last_backup(
        self, dest_id: str, status: str, timestamp: str | None = None
    ) -> None:
        ts = timestamp or _now_iso()
        with self._lock, session_scope(self._session_factory) as session:
            session.execute(
                update(BackupDestination)
                .where(BackupDestination.id == dest_id)
                .values(last_backup_at=self._coerce_dt(ts), last_backup_status=status)
            )

    def _execution_to_dict(self, row: BackupExecution | None) -> dict:
        if row is None:
            return {}

        def _ts(val):
            if isinstance(val, (datetime,)):
                return val.isoformat()
            return val

        return {
            "id": row.id,
            "destination_id": row.destination_id,
            "backup_filename": row.backup_filename,
            "backup_path": row.backup_path,
            "triggered_by": row.triggered_by,
            "started_at": _ts(row.started_at),
            "completed_at": _ts(row.completed_at),
            "status": row.status,
            "size_bytes": row.size_bytes,
            "compressed_size_bytes": row.compressed_size_bytes,
            "files_included": row.files_included,
            "error_message": row.error_message,
            "manifest_json": row.manifest_json,
        }

    def _destination_to_dict(self, row: BackupDestination | None) -> dict:
        if row is None:
            return {}

        def _ts(val):
            if isinstance(val, (datetime,)):
                return val.isoformat()
            return val

        return {
            "id": row.id,
            "name": row.name,
            "type": row.type,
            "enabled": bool(row.enabled),
            "config_json": row.config_json,
            "retention_days": row.retention_days,
            "retention_strategy": row.retention_strategy,
            "retention_config_json": row.retention_config_json,
            "created_at": _ts(row.created_at),
            "created_by": row.created_by,
            "last_backup_at": _ts(row.last_backup_at),
            "last_backup_status": row.last_backup_status,
        }
