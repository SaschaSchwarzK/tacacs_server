"""
Maintenance utilities: database connection pool manager and service restarts.

Provides a lightweight, process-local manager that components can register
with so that a restore procedure can signal all DB connections to close and
temporarily block new DB work. Also provides a helper to restart services
after a restore.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class _DBConnectionManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Store (object, close_fn, reload_fn)
        self._registrations: list[tuple[Any, Callable[[], None], Callable[[], None] | None]] = []
        self._in_maintenance: bool = False

    def register(self, obj: Any, close_fn: Callable[[], None] | None = None) -> None:
        """Register an object with a close() method to be closed on maintenance.

        If close_fn is None, the manager attempts to call obj.close.
        """
        with self._lock:
            if close_fn is None:
                close_fn = getattr(obj, "close", None)
            reload_fn = getattr(obj, "reload", None)
            if not callable(close_fn):
                return
            # Avoid duplicates
            for existing_obj, _, _ in self._registrations:
                if existing_obj is obj:
                    return
            self._registrations.append((obj, close_fn, reload_fn if callable(reload_fn) else None))

    def unregister(self, obj: Any) -> None:
        with self._lock:
            self._registrations = [
                (o, cfn, rfn) for (o, cfn, rfn) in self._registrations if o is not obj
            ]

    def enter_maintenance(self) -> None:
        """Enter maintenance mode and close all registered connections."""
        with self._lock:
            self._in_maintenance = True
        regs = list(self._registrations)
        # Close outside the lock to avoid deadlocks on client internal locks
        for _, close_fn, _ in regs:
            try:
                close_fn()
            except Exception as exc:  # pragma: no cover - best-effort
                try:
                    logger.debug("Close during maintenance failed: %s", exc)
                except Exception:
                    pass

    def exit_maintenance(self) -> None:
        # Flip flag first
        with self._lock:
            self._in_maintenance = False
            regs = list(self._registrations)
        # Attempt to reload any registered connections that expose reload()
        for _, _, reload_fn in regs:
            if reload_fn is None:
                continue
            try:
                reload_fn()
            except Exception as exc:  # pragma: no cover - best-effort
                try:
                    logger.debug("Reload after maintenance failed: %s", exc)
                except Exception:
                    pass

    def is_in_maintenance(self) -> bool:
        with self._lock:
            return self._in_maintenance


_DB_MANAGER = _DBConnectionManager()


def get_db_manager() -> _DBConnectionManager:
    return _DB_MANAGER


if TYPE_CHECKING:  # pragma: no cover
    from tacacs_server.backup.scheduler import BackupScheduler as _BackupScheduler


def restart_services() -> None:  # pragma: no cover - orchestration/hard to unit test
    """Best-effort restart of in-process services after restore.

    - TACACS server (stop/start)
    - RADIUS server (stop/start) if present
    - Backup scheduler (start) if present
    """
    try:
        # TACACS
        try:
            from tacacs_server.web.web import get_tacacs_server

            srv = get_tacacs_server()
            if srv is not None:
                try:
                    srv.stop()
                except Exception:
                    pass
                try:
                    srv.start()
                except Exception:
                    pass
        except Exception:
            pass

        # RADIUS
        try:
            from tacacs_server.web.web import get_radius_server

            r = get_radius_server()
            if r is not None:
                try:
                    r.stop()
                except Exception:
                    pass
                try:
                    r.start()
                except Exception:
                    pass
        except Exception:
            pass

        # Backup scheduler
        try:
            from tacacs_server.backup.service import get_backup_service

            svc = get_backup_service()
            sch = getattr(svc, "scheduler", None)
            if sch is not None:
                try:
                    cast("_BackupScheduler", sch).start()
                except Exception:
                    pass
        except Exception:
            pass

        # Refresh web app service stores (reopen DB connections) if available
        try:
            from tacacs_server.web.web import (
                get_device_service as _get_dev_svc,
                get_local_user_service as _get_user_svc,
                get_local_user_group_service as _get_group_svc,
            )

            ds = _get_dev_svc()
            if ds and hasattr(ds, "store") and hasattr(ds.store, "reload"):
                try:
                    ds.store.reload()  # type: ignore[attr-defined]
                except Exception:
                    pass
            us = _get_user_svc()
            if us and hasattr(us, "store") and hasattr(us.store, "reload"):
                try:
                    us.store.reload()  # type: ignore[attr-defined]
                except Exception:
                    pass
            gs = _get_group_svc()
            if gs and hasattr(gs, "store") and hasattr(gs.store, "reload"):
                try:
                    gs.store.reload()  # type: ignore[attr-defined]
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        # Entire restart is best-effort
        pass
