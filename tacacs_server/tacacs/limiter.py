"""Connection rate limiting and abuse control"""

import threading

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class ConnectionLimiter:
    """Manages per-IP connection limits"""

    def __init__(self, max_per_ip: int = 20):
        self._ip_conn_lock = threading.RLock()
        self._ip_connections: dict[str, int] = {}
        self.max_per_ip = max_per_ip

    def acquire(self, ip: str) -> bool:
        """Try to acquire connection slot for IP"""
        with self._ip_conn_lock:
            current = self._ip_connections.get(ip, 0)
            if current >= self.max_per_ip:
                logger.warning(
                    "Per-IP connection cap exceeded for %s (count=%s)", ip, current + 1
                )
                return False
            self._ip_connections[ip] = current + 1
            return True

    def release(self, ip: str):
        """Release connection slot for IP"""
        with self._ip_conn_lock:
            current = max(0, self._ip_connections.get(ip, 1) - 1)
            if current == 0:
                self._ip_connections.pop(ip, None)
            else:
                self._ip_connections[ip] = current
