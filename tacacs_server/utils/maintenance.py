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
from typing import Any

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class _DBConnectionManager:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._registrations: list[
            tuple[Any, Callable[[], None], Callable[[], None] | None]
        ] = []
        self._in_maintenance: bool = False

    def register(self, obj: Any, close_fn: Callable[[], None] | None = None) -> None:
        with self._lock:
            if close_fn is None:
                close_fn = getattr(obj, "close", None)
            reload_fn = getattr(obj, "reload", None)
            if not callable(close_fn):
                return
            for existing_obj, _, _ in self._registrations:
                if existing_obj is obj:
                    return
            self._registrations.append(
                (obj, close_fn, reload_fn if callable(reload_fn) else None)
            )

    def unregister(self, obj: Any) -> None:
        with self._lock:
            self._registrations = [
                (o, cfn, rfn) for (o, cfn, rfn) in self._registrations if o is not obj
            ]

    def enter_maintenance(self) -> None:
        with self._lock:
            self._in_maintenance = True
        regs = list(self._registrations)
        for _, close_fn, _ in regs:
            try:
                close_fn()
            except Exception as exc:
                logger.debug("Close during maintenance failed: %s", exc)

    def exit_maintenance(self) -> None:
        with self._lock:
            self._in_maintenance = False
            regs = list(self._registrations)
        for _, _, reload_fn in regs:
            if reload_fn is None:
                continue
            try:
                reload_fn()
            except Exception as exc:
                logger.debug("Reload after maintenance failed: %s", exc)

    def is_in_maintenance(self) -> bool:
        with self._lock:
            return self._in_maintenance


_DB_MANAGER = _DBConnectionManager()


def get_db_manager() -> _DBConnectionManager:
    return _DB_MANAGER


def restart_services() -> None:
    try:
        try:
            from tacacs_server.web.web import get_tacacs_server

            srv = get_tacacs_server()
            if srv is not None:
                try:
                    srv.stop()
                except Exception as exc:
                    logger.warning("TACACS stop failed during maintenance: %s", exc)
                try:
                    srv.start()
                except Exception as exc:
                    logger.warning("TACACS restart failed during maintenance: %s", exc)
        except Exception as exc:
            logger.warning("Failed to rotate TACACS server during maintenance: %s", exc)

        try:
            from tacacs_server.web.web import get_radius_server

            r = get_radius_server()
            if r is not None:
                try:
                    r.stop()
                except Exception as exc:
                    logger.warning("RADIUS stop failed during maintenance: %s", exc)
                try:
                    r.start()
                except Exception as exc:
                    logger.warning("RADIUS restart failed during maintenance: %s", exc)
        except Exception as exc:
            logger.warning("Failed to rotate RADIUS server during maintenance: %s", exc)

        try:
            from tacacs_server.backup.service import get_backup_service

            svc = get_backup_service()
            sch = getattr(svc, "scheduler", None)
            if sch is not None:
                try:
                    sch.start()
                except Exception as exc:
                    logger.warning("Backup scheduler restart failed: %s", exc)
        except Exception as exc:
            logger.warning("Failed to restart backup scheduler: %s", exc)

        try:
            from tacacs_server.web.web import (
                get_device_service as _get_dev_svc,
            )
            from tacacs_server.web.web import (
                get_local_user_group_service as _get_group_svc,
            )
            from tacacs_server.web.web import (
                get_local_user_service as _get_user_svc,
            )

            ds = _get_dev_svc()
            if ds and hasattr(ds, "store") and hasattr(ds.store, "reload"):
                try:
                    ds.store.reload()
                except Exception as exc:
                    logger.warning("Device store reload failed: %s", exc)
            us = _get_user_svc()
            if us and hasattr(us, "store") and hasattr(us.store, "reload"):
                try:
                    us.store.reload()
                except Exception as exc:
                    logger.warning("User store reload failed: %s", exc)
            gs = _get_group_svc()
            if gs and hasattr(gs, "store") and hasattr(gs.store, "reload"):
                try:
                    gs.store.reload()
                except Exception as exc:
                    logger.warning("Group store reload failed: %s", exc)
        except Exception as exc:
            logger.warning(
                "Failed to refresh service stores after maintenance: %s", exc
            )
    except Exception as exc:
        logger.warning("Maintenance restart hook failed: %s", exc)
