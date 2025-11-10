"""Compatibility shim for legacy monitoring imports.

Re-exports minimal interfaces expected by existing code:
- PrometheusIntegration: static record_* methods used by handlers and RADIUS server
- get_command_engine / get_command_authorizer: delegate to web_api or other modules if available
"""

from __future__ import annotations

import time
from typing import Any

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.metrics_history import get_metrics_history

logger = get_logger(__name__)

# Simple in-process aggregator that periodically writes snapshots
_metrics: dict[str, float] = {
    "auth_requests": 0,
    "auth_success": 0,
    "auth_failures": 0,
    "author_requests": 0,
    "author_success": 0,
    "author_failures": 0,
    "acct_requests": 0,
    "acct_success": 0,
    "acct_failures": 0,
    "connections_active": 0,
    "connections_total": 0,
}
_flush_state = {"last_flush_ts": 0.0}
_flush_interval_sec: float = 5.0


def _maybe_flush_snapshot() -> None:  # pragma: no cover
    state = _flush_state
    now = time.time()
    if (now - state["last_flush_ts"]) < _flush_interval_sec:
        return
    try:
        # Build snapshot with optional system metrics (CPU/mem)
        snapshot = dict(_metrics)
        try:
            import psutil

            vm = psutil.virtual_memory()
            snapshot["memory_usage_mb"] = round(
                (getattr(vm, "used", 0) or 0) / (1024 * 1024), 2
            )
            # Non-blocking CPU percent (use last value if no interval)
            cpu = psutil.cpu_percent(interval=0.0)
            snapshot["cpu_percent"] = float(cpu or 0)
        except Exception as exc:
            logger.debug("Optional psutil metrics unavailable: %s", exc)
        get_metrics_history().record_snapshot(snapshot)
    except Exception as exc:
        logger.warning("Failed to record metrics snapshot: %s", exc)
    state["last_flush_ts"] = now


def get_tacacs_server() -> Any | None:
    """Return the TACACS server instance when available.

    Imports lazily to avoid import cycles and provides a consistent signature
    regardless of import success.
    """
    try:  # pragma: no cover
        from .web import get_tacacs_server as _get

        return _get()
    except Exception:
        return None


class PrometheusIntegration:
    @staticmethod
    def record_auth_request(
        status: str, backend: str, duration: float, reason: str = ""
    ) -> None:  # pragma: no cover
        # Update in-memory counters for DB rollup
        try:
            _metrics["auth_requests"] += 1
            if str(status).lower().startswith("success") or status in ("ok", "accept"):
                _metrics["auth_success"] += 1
            else:
                _metrics["auth_failures"] += 1
            _maybe_flush_snapshot()
        except Exception as exc:
            logger.warning("Failed to update auth metrics: %s", exc)

    @staticmethod
    def record_accounting_record(status: str) -> None:  # pragma: no cover
        try:
            _metrics["acct_requests"] += 1
            if str(status).lower().startswith("success"):
                _metrics["acct_success"] += 1
            else:
                _metrics["acct_failures"] += 1
            _maybe_flush_snapshot()
        except Exception as exc:
            logger.warning("Failed to record accounting metrics: %s", exc)

    @staticmethod
    def record_radius_auth(status: str) -> None:  # pragma: no cover
        try:
            # Treat as auth metrics as well for unified graphs
            _metrics["auth_requests"] += 1
            if str(status).lower().startswith("accept") or status in ("ok", "success"):
                _metrics["auth_success"] += 1
            else:
                _metrics["auth_failures"] += 1
            _maybe_flush_snapshot()
        except Exception as exc:
            logger.warning("Failed to record radius auth metrics: %s", exc)

    @staticmethod
    def update_active_connections(count: int) -> None:  # pragma: no cover
        try:
            _metrics["connections_active"] = int(count) if count is not None else 0
            # Track max total as a rough counter when active increases
            _metrics["connections_total"] = max(
                _metrics.get("connections_total", 0),
                _metrics.get("connections_active", 0),
            )
            _maybe_flush_snapshot()
        except Exception as exc:
            logger.warning("Failed to update active connections: %s", exc)


def get_command_engine():  # pragma: no cover
    try:
        srv = get_tacacs_server()
        if srv and getattr(srv, "command_engine", None) is not None:
            return srv.command_engine
    except Exception as exc:
        logger.warning("Failed to get command engine from monitoring shim: %s", exc)
    return None


def get_command_authorizer():  # pragma: no cover
    try:
        srv = get_tacacs_server()
        if srv and getattr(srv, "command_authorizer", None) is not None:
            return srv.command_authorizer
    except Exception as exc:
        logger.warning("Failed to get command authorizer from monitoring shim: %s", exc)
    return None
