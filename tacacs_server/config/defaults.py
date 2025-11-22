"""Centralized default configuration values for TACACS server setup."""

from __future__ import annotations

from typing import Any

from .constants import DEFAULTS

DEFAULT_SERVER_HOST = "localhost"
DEFAULT_TACACS_PORT = 49
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_SHARED_SECRET = "tacacs123"
DEFAULT_CONFIG_REFRESH_SECONDS = 300
DEFAULT_CONFIG_REFRESH_MIN_SLEEP = 30
DEFAULT_TCP_KEEPALIVE_IDLE = 60
DEFAULT_LISTEN_BACKLOG = 128
DEFAULT_THREAD_POOL_MAX = 100
DEFAULT_CLIENT_TIMEOUT = 15.0
DEFAULT_MAX_PACKET_LENGTH = 4096
DEFAULT_TCP_KEEPINTVL = 10
DEFAULT_TCP_KEEPCNT = 5
DEFAULT_USE_THREAD_POOL = True
DEFAULT_PROXY_ENABLED = False
DEFAULT_PROXY_VALIDATE = True
DEFAULT_PROXY_REJECT = True
DEFAULT_PER_IP_CAP = 20
DEFAULT_ENCRYPTION_REQUIRED = True
DEFAULT_ADMIN_SESSION_TIMEOUT_MINUTES = 60
DEFAULT_MONITORING_HOST = "127.0.0.1"
DEFAULT_MONITORING_PORT = 8080
DEFAULT_RADIUS_WORKERS = 8
DEFAULT_RADIUS_SOCKET_TIMEOUT = 1.0
DEFAULT_RADIUS_RCVBUF = 1_048_576
MIN_RADIUS_RCVBUF = 262_144
DEFAULT_COMMAND_RESPONSE_MODE = "pass_add"
DEFAULT_PRIVILEGE_ORDER = "before"


def populate_defaults(parser: Any) -> None:
    """Populate a ConfigParser with default sections/options."""

    for section, values in DEFAULTS.items():
        if not parser.has_section(section):
            parser.add_section(section)
        for key, val in values.items():
            if not parser.has_option(section, key):
                parser.set(section, key, str(val))
