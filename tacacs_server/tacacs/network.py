"""Network handling utilities for TACACS+ server"""

import socket

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class NetworkHandler:
    """Handles low-level network operations"""

    @staticmethod
    def recv_exact(sock: socket.socket, length: int) -> bytes | None:
        """Receive exactly the specified number of bytes"""
        data = b""
        while len(data) < length:
            try:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            except OSError:
                return None
        return data

    @staticmethod
    def safe_close_socket(sock: socket.socket) -> None:
        """Safely close socket with proper error handling"""
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError) as shut_exc:
            logger.debug("Failed to shutdown socket: %s", shut_exc)
        try:
            sock.close()
        except (OSError, AttributeError) as close_exc:
            logger.debug("Failed to close socket: %s", close_exc)

    @staticmethod
    def enable_tcp_keepalive(
        sock: socket.socket, idle: int, interval: int, count: int
    ) -> None:
        """Enable TCP keepalive with platform-specific options"""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
            if hasattr(socket, "TCP_KEEPALIVE"):
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, idle)
                except OSError as e:
                    logger.debug("Failed to set TCP_KEEPALIVE: %s", e)
        except OSError as e:
            logger.debug("Failed to enable TCP keepalive: %s", e)
