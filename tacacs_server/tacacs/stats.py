"""Statistics and metrics tracking"""

import threading
import time
from collections.abc import Callable
from typing import Any

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class StatsManager:
    """Manages server statistics and metrics"""

    def __init__(self):
        self._stats_lock = threading.RLock()
        self.stats = {
            "connections_total": 0,
            "connections_active": 0,
            "connections_proxied": 0,
            "connections_direct": 0,
            "proxy_headers_parsed": 0,
            "proxy_header_errors": 0,
            "proxy_rejected_unknown": 0,
            "auth_requests": 0,
            "auth_success": 0,
            "auth_failures": 0,
            "author_requests": 0,
            "author_success": 0,
            "author_failures": 0,
            "acct_requests": 0,
            "acct_success": 0,
            "acct_failures": 0,
        }
        self.start_time = time.time()
        self._prom_update_active: Callable[[int], None] | None = None
        self._init_prometheus()

    def _init_prometheus(self):
        """Initialize Prometheus integration if available"""
        try:
            from tacacs_server.web.web import PrometheusIntegration as _PM

            self._prom_update_active = getattr(_PM, "update_active_connections", None)
        except Exception:
            self._prom_update_active = None

    def increment(self, key: str, value: int = 1):
        """Increment a stat counter"""
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + value

    def update_active_connections(self, delta: int) -> None:
        """Update active connections count and Prometheus gauge"""
        with self._stats_lock:
            current = self.stats.get("connections_active", 0)
            new_val = max(0, current + delta)
            self.stats["connections_active"] = new_val
            push = self._prom_update_active

        try:
            if push is not None:
                push(new_val)
        except Exception as e:
            logger.debug("Failed to update Prometheus active connections: %s", e)

    def get_active_connections(self) -> int:
        """Get current active connections count"""
        with self._stats_lock:
            return int(self.stats.get("connections_active", 0))

    def record_connection_type(self, is_proxied: bool):
        """Record whether connection is proxied or direct"""
        with self._stats_lock:
            if is_proxied:
                self.stats["connections_proxied"] = (
                    self.stats.get("connections_proxied", 0) + 1
                )
            else:
                self.stats["connections_direct"] = (
                    self.stats.get("connections_direct", 0) + 1
                )

    def get_all(self) -> dict[str, Any]:
        """Get all statistics"""
        with self._stats_lock:
            return dict(self.stats)

    def reset(self):
        """Reset all statistics except active connections"""
        with self._stats_lock:
            active = self.stats["connections_active"]
            self.stats = {
                "connections_total": 0,
                "connections_active": active,
                "connections_proxied": 0,
                "connections_direct": 0,
                "proxy_headers_parsed": 0,
                "proxy_header_errors": 0,
                "proxy_rejected_unknown": 0,
                "auth_requests": 0,
                "auth_success": 0,
                "auth_failures": 0,
                "author_requests": 0,
                "author_success": 0,
                "author_failures": 0,
                "acct_requests": 0,
                "acct_success": 0,
                "acct_failures": 0,
            }
        logger.info("Server statistics reset")
