"""
SQLAlchemy-backed accounting database logger for TACACS+.
"""
# mypy: ignore-errors

from __future__ import annotations

import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from logging.handlers import SysLogHandler
from pathlib import Path
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from tacacs_server.db.engine import Base, get_session_factory, session_scope
from tacacs_server.db.models import Accounting, AccountingLog, ActiveSession
from tacacs_server.utils.logger import bind_context, clear_context, get_logger
from tacacs_server.utils.maintenance import get_db_manager

logger = get_logger("tacacs_server.accounting.database", component="accounting")

# Track which database paths we have already announced as initialized
_ANNOUNCED_DB_PATHS: set[str] = set()


def _as_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=UTC)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            try:
                return datetime.fromtimestamp(float(value), tz=UTC)
            except (ValueError, TypeError):
                return None
    return None


class DatabaseLogger:
    RECENT_WINDOW_DAYS = 30
    STATS_CACHE_TTL_SECONDS = 60

    def __init__(
        self,
        db_path: str = "data/tacacs_accounting.db",
        maintain_mv: bool = True,
        *,
        pool_size: int | None = None,
    ):
        # pool_size retained for signature compatibility; SQLAlchemy manages pooling
        self.db_path = str(db_path)
        self.maintain_mv = maintain_mv
        self._stats_cache: dict[int, tuple[float, dict[str, Any]]] = {}
        self._session_factory = get_session_factory(self.db_path)
        self.engine: Engine | None = getattr(
            self._session_factory, "bind", None
        ) or getattr(self._session_factory, "engine", None)
        if self.engine is None:
            raise RuntimeError("Failed to initialize accounting engine")
        self._run_alembic_or_create(self.engine)

        # Register with maintenance manager
        try:
            get_db_manager().register(self, self.close)
        except Exception as exc:
            logger.warning(
                "Failed to register accounting DB with maintenance manager",
                event="accounting.db.register_failed",
                error=str(exc),
            )

        # Initialize syslog handler for audit trail (configurable via SYSLOG_ADDRESS)
        self._syslog: logging.Logger | None = None
        try:
            self._syslog = logging.getLogger("tacacs.accounting")
            if not any(isinstance(h, SysLogHandler) for h in self._syslog.handlers):
                addr_env = os.getenv("SYSLOG_ADDRESS", "")
                address: Any
                if addr_env:
                    if ":" in addr_env and not addr_env.startswith("/"):
                        host, port = addr_env.split(":", 1)
                        address = (host.strip(), int(port.strip()))
                    else:
                        address = addr_env
                elif os.path.exists("/dev/log"):
                    address = "/dev/log"
                else:
                    address = ("127.0.0.1", 514)
                handler = SysLogHandler(address=address)
                formatter = logging.Formatter("tacacs_accounting: %(message)s")
                handler.setFormatter(formatter)
                self._syslog.addHandler(handler)
                self._syslog.setLevel(logging.INFO)
        except Exception as exc:
            logger.warning(
                "Failed to configure accounting syslog",
                event="accounting.syslog.configure_failed",
                error=str(exc),
            )
            self._syslog = None

        # Emit the initialization log only once per resolved path
        resolved = str(Path(self.db_path).resolve())
        if resolved not in _ANNOUNCED_DB_PATHS:
            _ANNOUNCED_DB_PATHS.add(resolved)
            logger.info(
                "Accounting database initialized",
                event="accounting.db.initialized",
                db_path=self.db_path,
            )
        else:
            logger.debug(
                "Accounting database already initialized (suppressing duplicate)",
                event="accounting.db.initialized_duplicate",
                db_path=self.db_path,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _now_utc(self) -> datetime:
        return datetime.now(UTC)

    def _now_utc_iso(self) -> str:
        return self._now_utc().isoformat()

    def _compute_is_recent(self, timestamp_value: datetime | None) -> int:
        if timestamp_value is None:
            return 1
        if timestamp_value.tzinfo is None:
            timestamp_value = timestamp_value.replace(tzinfo=UTC)
        cutoff = datetime.now(UTC) - timedelta(days=self.RECENT_WINDOW_DAYS)
        return 1 if timestamp_value >= cutoff else 0

    def _invalidate_stats_cache(self):
        self._stats_cache.clear()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        try:
            if self.engine:
                self.engine.dispose()
        except Exception as exc:
            logger.warning(
                "Accounting DB close failed",
                event="accounting.db.close_failed",
                error=str(exc),
                db_path=str(self.db_path),
            )

    def reload(self) -> None:
        try:
            if self.engine:
                self.engine.dispose()
        except Exception:
            logger.warning(
                "Failed to dispose accounting engine before reload",
                event="accounting.db.reload_dispose_failed",
            )
        self._session_factory = get_session_factory(self.db_path)
        self.engine = getattr(self._session_factory, "bind", None) or getattr(
            self._session_factory, "engine", None
        )
        if self.engine is None:
            raise RuntimeError("Failed to reload accounting engine")
        self._run_alembic_or_create(self.engine)

    def __del__(self):
        self.close()

    def ping(self) -> bool:
        try:
            with session_scope(self._session_factory) as session:
                session.execute(select(func.count()).select_from(AccountingLog))
                return True
        except Exception:
            return False

    def _run_alembic_or_create(self, engine: Engine) -> None:
        """Run Alembic migrations if available; fall back to create_all."""
        try:
            from alembic import command  # type: ignore[attr-defined] # noqa: I001
            from alembic.config import Config
        except ImportError:
            Base.metadata.create_all(engine)
            return

        from pathlib import Path

        project_root = Path(__file__).resolve().parents[2]
        ini_path = project_root / "alembic.ini"
        script_location = project_root / "alembic"
        if not ini_path.exists() or not script_location.exists():
            Base.metadata.create_all(engine)
            return

        cfg = Config(str(ini_path))
        cfg.set_main_option("script_location", str(script_location))
        cfg.set_main_option("sqlalchemy.url", str(engine.url))
        try:
            command.upgrade(cfg, "head")
        except Exception:
            Base.metadata.create_all(engine)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    def log_accounting(self, record) -> bool:
        token = None
        try:
            try:
                base_data = record.to_dict()
            except Exception:
                token = bind_context(
                    session_id=getattr(record, "session_id", None),
                    username=getattr(record, "username", None),
                )
                logger.exception(
                    "Invalid accounting record payload",
                    event="accounting.record.invalid",
                )
                return False

            timestamp_value = (
                _as_datetime(base_data.get("timestamp")) or self._now_utc()
            )
            base_data["timestamp"] = timestamp_value
            is_recent = self._compute_is_recent(timestamp_value)

            status = base_data.get("status") or base_data.get("acct_type") or "UNKNOWN"
            token = bind_context(
                session_id=base_data.get("session_id"),
                username=base_data.get("username"),
                client_ip=base_data.get("client_ip"),
                service=base_data.get("service"),
                status=status,
            )

            start_int = _as_int(base_data.get("start_time"))
            stop_int = _as_int(base_data.get("stop_time"))
            attributes = base_data.get("attributes")
            if isinstance(attributes, dict):
                attributes = json.dumps(attributes)

            with session_scope(self._session_factory) as session:
                session.add(
                    Accounting(
                        session_id=base_data.get("session_id"),
                        username=base_data.get("username"),
                        acct_type=status,
                        start_time=start_int,
                        stop_time=stop_int,
                        bytes_in=_as_int(base_data.get("bytes_in")),
                        bytes_out=_as_int(base_data.get("bytes_out")),
                        attributes=attributes,
                        created_at=timestamp_value,
                    )
                )

                session.add(
                    AccountingLog(
                        timestamp=timestamp_value,
                        username=base_data.get("username", "unknown"),
                        session_id=base_data.get("session_id") or 0,
                        status=status,
                        service=base_data.get("service"),
                        command=base_data.get("command"),
                        client_ip=base_data.get("client_ip"),
                        port=base_data.get("port"),
                        start_time=str(base_data.get("start_time"))
                        if base_data.get("start_time") is not None
                        else None,
                        stop_time=str(base_data.get("stop_time"))
                        if base_data.get("stop_time") is not None
                        else None,
                        bytes_in=_as_int(base_data.get("bytes_in")) or 0,
                        bytes_out=_as_int(base_data.get("bytes_out")) or 0,
                        elapsed_time=_as_int(base_data.get("elapsed_time")) or 0,
                        privilege_level=_as_int(base_data.get("privilege_level")) or 1,
                        authentication_method=base_data.get("authentication_method"),
                        nas_port=base_data.get("nas_port"),
                        nas_port_type=base_data.get("nas_port_type"),
                        task_id=base_data.get("task_id"),
                        timezone=base_data.get("timezone"),
                        attributes=attributes,
                        is_recent=is_recent,
                    )
                )

                if status == "START":
                    self._start_session(session, base_data, timestamp_value)
                elif status == "STOP":
                    self._stop_session(session, base_data)
                elif status == "UPDATE":
                    self._update_session(session, base_data)

            logger.info(
                "Accounting record logged",
                event="accounting.record.logged",
                command=base_data.get("command"),
                client_ip=base_data.get("client_ip"),
                port=base_data.get("port"),
            )
            syslog = self._syslog
            if syslog is not None:
                syslog.info(
                    "event=accounting.record.syslog username=%s session=%s status=%s service=%s command=%s client_ip=%s bytes_in=%s bytes_out=%s",
                    base_data.get("username"),
                    base_data.get("session_id"),
                    status,
                    base_data.get("service", ""),
                    base_data.get("command", ""),
                    base_data.get("client_ip", ""),
                    int(base_data.get("bytes_in", 0) or 0),
                    int(base_data.get("bytes_out", 0) or 0),
                )
            self._invalidate_stats_cache()
            return True
        except Exception as exc:
            logger.error(
                "Failed to log accounting record",
                event="accounting.record.log_failed",
                error=str(exc),
                session_id=getattr(record, "session_id", None),
                username=getattr(record, "username", None),
                status=getattr(record, "status", None),
            )
            return False
        finally:
            if token is not None:
                clear_context(token)

    def _start_session(self, session: Session, payload: dict[str, Any], ts: datetime):
        start_dt = _as_datetime(payload.get("start_time")) or ts
        session.merge(
            ActiveSession(
                session_id=payload.get("session_id"),
                username=payload.get("username"),
                client_ip=payload.get("client_ip"),
                start_time=start_dt,
                last_update=self._now_utc(),
                service=payload.get("service"),
                port=payload.get("port"),
                privilege_level=_as_int(payload.get("privilege_level")) or 1,
                bytes_in=_as_int(payload.get("bytes_in")) or 0,
                bytes_out=_as_int(payload.get("bytes_out")) or 0,
            )
        )
        session.flush()

    def _update_session(self, session: Session, payload: dict[str, Any]):
        session_id = payload.get("session_id")
        existing = session.get(ActiveSession, session_id)
        if not existing:
            return
        existing.bytes_in = _as_int(payload.get("bytes_in")) or existing.bytes_in
        existing.bytes_out = _as_int(payload.get("bytes_out")) or existing.bytes_out
        existing.last_update = self._now_utc()
        session.flush()

    def _stop_session(self, session: Session, payload: dict[str, Any]):
        session_id = payload.get("session_id")
        if session_id is None:
            return
        obj = session.get(ActiveSession, session_id)
        if obj:
            session.delete(obj)
            session.flush()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def get_statistics(self, days: int = 30) -> dict[str, Any]:
        days = max(int(days), 0)
        cached = self._stats_cache.get(days)
        if cached:
            expires_at, payload = cached
            if time.monotonic() < expires_at:
                return dict(payload)
            self._stats_cache.pop(days, None)

        cutoff = datetime.now(UTC) - timedelta(days=days)
        with session_scope(self._session_factory) as session:
            total_records = session.scalar(
                select(func.count())
                .select_from(AccountingLog)
                .where(AccountingLog.timestamp > cutoff, AccountingLog.is_recent == 1)
            )
            unique_users = session.scalar(
                select(func.count(func.distinct(AccountingLog.username))).where(
                    AccountingLog.timestamp > cutoff, AccountingLog.is_recent == 1
                )
            )
        result = {
            "period_days": days,
            "total_records": int(total_records or 0),
            "unique_users": int(unique_users or 0),
        }
        self._stats_cache[days] = (
            time.monotonic() + self.STATS_CACHE_TTL_SECONDS,
            dict(result),
        )
        return result

    def get_recent_records(
        self, since: datetime, limit: int = 100
    ) -> list[dict[str, Any]]:
        limit = min(max(1, int(limit)), 10000)
        with session_scope(self._session_factory) as session:
            rows = (
                session.execute(
                    select(
                        AccountingLog.username,
                        AccountingLog.session_id,
                        AccountingLog.status,
                        AccountingLog.service,
                        AccountingLog.command,
                        AccountingLog.client_ip,
                        AccountingLog.timestamp,
                        AccountingLog.bytes_in,
                        AccountingLog.bytes_out,
                    )
                    .where(
                        AccountingLog.timestamp >= since,
                        AccountingLog.is_recent == 1,
                    )
                    .order_by(AccountingLog.timestamp.desc())
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            return [dict(row) for row in rows]

    def get_hourly_stats(self, hours: int = 24) -> list[dict[str, Any]]:
        hours = min(max(1, int(hours)), 168)
        cutoff = datetime.now(UTC) - timedelta(hours=hours)
        with session_scope(self._session_factory) as session:
            rows = (
                session.execute(
                    select(
                        func.strftime(
                            "%Y-%m-%d %H:00:00", AccountingLog.timestamp
                        ).label("hour"),
                        func.count().label("total"),
                        func.sum(
                            case((AccountingLog.status == "START", 1), else_=0)
                        ).label("starts"),
                        func.sum(
                            case((AccountingLog.status == "STOP", 1), else_=0)
                        ).label("stops"),
                    )
                    .where(
                        AccountingLog.timestamp >= cutoff,
                        AccountingLog.is_recent == 1,
                    )
                    .group_by("hour")
                    .order_by("hour")
                )
                .mappings()
                .all()
            )
            return [dict(row) for row in rows]

    def get_active_sessions(self) -> list[dict[str, Any]]:
        with session_scope(self._session_factory) as session:
            rows = session.execute(
                select(
                    Accounting.session_id,
                    Accounting.username,
                    Accounting.acct_type,
                    Accounting.start_time,
                    Accounting.attributes,
                    Accounting.created_at,
                ).where(
                    Accounting.stop_time.is_(None), Accounting.start_time.is_not(None)
                )
            ).all()

        sessions = []
        for row in rows:
            attributes = {}
            if row[4]:
                try:
                    attributes = json.loads(row[4])
                except (json.JSONDecodeError, TypeError):
                    attributes = {}
            sessions.append(
                {
                    "session_id": row[0],
                    "username": row[1],
                    "acct_type": row[2],
                    "start_time": row[3],
                    "duration_seconds": int(time.time() - row[3]) if row[3] else 0,
                    "device_ip": attributes.get("device_ip", "unknown"),
                    "created_at": row[5],
                }
            )
        return sessions

    def get_total_sessions(self, period_days: int = 30) -> int:
        cutoff_timestamp = int(time.time()) - (int(period_days) * 86400)
        with session_scope(self._session_factory) as session:
            result = session.scalar(
                select(func.count(func.distinct(Accounting.session_id))).where(
                    Accounting.start_time >= cutoff_timestamp
                )
            )
            return int(result or 0)

    def get_session_duration_stats(self, period_days: int = 30) -> dict[str, float]:
        cutoff_timestamp = int(time.time()) - (int(period_days) * 86400)
        with session_scope(self._session_factory) as session:
            row = session.execute(
                select(
                    func.avg(Accounting.stop_time - Accounting.start_time),
                    func.min(Accounting.stop_time - Accounting.start_time),
                    func.max(Accounting.stop_time - Accounting.start_time),
                    func.count(),
                ).where(
                    Accounting.start_time >= cutoff_timestamp,
                    Accounting.start_time.is_not(None),
                    Accounting.stop_time.is_not(None),
                    Accounting.stop_time > Accounting.start_time,
                )
            ).first()
        if row and row[0] is not None:
            return {
                "avg_duration_seconds": float(row[0]),
                "min_duration_seconds": float(row[1]),
                "max_duration_seconds": float(row[2]),
                "completed_sessions": int(row[3]),
            }
        return {
            "avg_duration_seconds": 0.0,
            "min_duration_seconds": 0.0,
            "max_duration_seconds": 0.0,
            "completed_sessions": 0,
        }

    def get_session_by_id(self, session_id: int) -> dict[str, Any] | None:
        with session_scope(self._session_factory) as session:
            row = session.execute(
                select(
                    Accounting.session_id,
                    Accounting.username,
                    Accounting.acct_type,
                    Accounting.start_time,
                    Accounting.stop_time,
                    Accounting.bytes_in,
                    Accounting.bytes_out,
                    Accounting.attributes,
                    Accounting.created_at,
                ).where(Accounting.session_id == session_id)
            ).first()
        if not row:
            return None
        attributes = {}
        if row[7]:
            try:
                attributes = json.loads(row[7])
            except (json.JSONDecodeError, TypeError):
                attributes = {}
        duration = None
        if row[3] and row[4]:
            duration = row[4] - row[3]
        elif row[3]:
            duration = int(time.time()) - row[3]
        return {
            "session_id": row[0],
            "username": row[1],
            "acct_type": row[2],
            "start_time": row[3],
            "stop_time": row[4],
            "duration_seconds": duration,
            "bytes_in": row[5],
            "bytes_out": row[6],
            "attributes": attributes,
            "created_at": row[8],
            "is_active": row[4] is None,
        }

    def get_user_session_history(
        self, username: str, limit: int = 10
    ) -> list[dict[str, Any]]:
        with session_scope(self._session_factory) as session:
            rows = session.execute(
                select(
                    Accounting.session_id,
                    Accounting.username,
                    Accounting.acct_type,
                    Accounting.start_time,
                    Accounting.stop_time,
                    Accounting.bytes_in,
                    Accounting.bytes_out,
                    Accounting.attributes,
                    Accounting.created_at,
                )
                .where(Accounting.username == username)
                .order_by(Accounting.start_time.desc())
                .limit(limit)
            ).all()

        sessions = []
        for row in rows:
            attributes = {}
            if row[7]:
                try:
                    attributes = json.loads(row[7])
                except (json.JSONDecodeError, TypeError):
                    attributes = {}
            if row[3] and row[4]:
                duration = row[4] - row[3]
            elif row[3]:
                duration = int(time.time()) - row[3]
            else:
                duration = None
            sessions.append(
                {
                    "session_id": row[0],
                    "username": row[1],
                    "acct_type": row[2],
                    "start_time": row[3],
                    "stop_time": row[4],
                    "duration_seconds": duration,
                    "bytes_in": row[5],
                    "bytes_out": row[6],
                    "device_ip": attributes.get("device_ip", "unknown"),
                    "created_at": row[8],
                    "is_active": row[4] is None,
                }
            )
        return sessions
