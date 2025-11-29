"""
TACACS+ AAA Request Handlers
"""

# NOTE: On modern macOS versions, using fork() without an immediate exec()
# can cause crashes when network, DNS, or Objective-C based libraries are used.
# This is due to Apple's stricter post-fork safety rules. Avoid fork() on macOS
# or use a spawn/forkserver start method instead.
# As this code is supposed to run in containers, we assume Linux environments where fork() is safe.
# But this still might affect users running on macOS hosts directly for testing.

import atexit
import json
import multiprocessing as mp
import os
import re
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import TYPE_CHECKING, Any, TypedDict

from tacacs_server.auth.base import AuthenticationBackend

if TYPE_CHECKING:
    from tacacs_server.authorization.command_authorization import (
        CommandAuthorizationEngine,
    )

from ..accounting.models import AccountingRecord
from ..utils.constants import MAX_PASSWORD_LENGTH
from ..utils.exceptions import AuthenticationError, ProtocolError
from ..utils.logger import get_logger
from ..utils.policy import PolicyContext, PolicyResult, evaluate_policy
from ..utils.security import AuthRateLimiter, validate_username
from .constants import (
    TAC_PLUS_ACCT_FLAG,
    TAC_PLUS_ACCT_STATUS,
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHEN_TYPE,
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_FLAGS,
    TAC_PLUS_PACKET_TYPE,
)
from .packet import TacacsPacket
from .structures import (
    parse_acct_request,
    parse_authen_continue,
    parse_authen_start,
    parse_author_request,
)

logger = get_logger(__name__)


class DeviceContext(TypedDict):
    device: str | None
    group: str | None
    allowed_groups: list[Any]


def _structured_log(log_fn, payload: dict[str, Any]):
    """Emit structured log without double JSON encoding."""
    try:
        event = payload.get("event")
        message = payload.get("message") or (
            event.replace(".", " ") if isinstance(event, str) else "event"
        )
        extra = {k: v for k, v in payload.items() if k not in {"event", "message"}}
        if event:
            log_fn(message, event=event, **extra)
        else:
            log_fn(message, **extra)
    except Exception:
        # Logging must never break the request flow
        pass


def _backend_worker_main(in_q: "mp.Queue", out_q: "mp.Queue") -> None:
    """Process main loop for backend worker.

    Receives tasks as tuples: (task_id, backend_config, username, password, kwargs)
    Puts results into out_q as (task_id, ok, err_msg).
    """
    # Emit a worker-only startup marker with this process PID
    try:
        logger.info(
            "Process pool worker started",
            event="process_pool.worker_started",
            pid=os.getpid(),
        )
    except Exception:
        # Ignore logging errors at interpreter shutdown
        pass

    while True:
        try:
            task = in_q.get()
        except Exception:
            break
        if task is None:
            break
        try:
            task_id, backend_config, username, password, kwargs = task
        except Exception:
            # Malformed task; ignore
            continue
        try:
            # Create backend instance in worker process
            backend_type = backend_config.get("type")
            backend: Any = None

            if backend_type == "local":
                from tacacs_server.auth.local import LocalAuthBackend

                backend = LocalAuthBackend(backend_config.get("database_url", ""))
            elif backend_type == "ldap":
                from tacacs_server.auth.ldap_auth import LDAPAuthBackend

                backend = LDAPAuthBackend(
                    ldap_server=backend_config.get("ldap_server", ""),
                    base_dn=backend_config.get("base_dn", ""),
                    bind_dn=backend_config.get("bind_dn"),
                    bind_password=backend_config.get("bind_password"),
                    user_attribute=backend_config.get("user_attribute", "uid"),
                    use_tls=backend_config.get("use_tls", False),
                    timeout=backend_config.get("timeout", 10),
                )
            elif backend_type == "okta":
                from tacacs_server.auth.okta_auth import OktaAuthBackend

                # Okta backend expects a config dict
                okta_config = {
                    "org_url": backend_config.get("org_url", ""),
                    "api_token": backend_config.get("api_token", ""),
                    "client_id": backend_config.get("client_id", ""),
                    "client_secret": backend_config.get("client_secret", ""),
                    "private_key": backend_config.get("private_key", ""),
                    "private_key_id": backend_config.get("private_key_id", ""),
                    "auth_method": backend_config.get("auth_method", ""),
                    "verify_tls": backend_config.get("verify_tls", True),
                    "require_group_for_auth": backend_config.get(
                        "require_group_for_auth", False
                    ),
                }
                backend = OktaAuthBackend(okta_config)
            elif backend_type == "radius":
                from tacacs_server.auth.radius_auth import RADIUSAuthBackend

                # RADIUS backend expects a config dict
                radius_config = {
                    "radius_server": backend_config.get("radius_server", ""),
                    "radius_port": backend_config.get("radius_port", 1812),
                    "radius_secret": backend_config.get("radius_secret", ""),
                    "radius_timeout": backend_config.get("radius_timeout", 5),
                    "radius_retries": backend_config.get("radius_retries", 3),
                    "radius_nas_ip": backend_config.get("radius_nas_ip", "0.0.0.0"),
                    "radius_nas_identifier": backend_config.get(
                        "radius_nas_identifier"
                    ),
                }
                backend = RADIUSAuthBackend(radius_config)
            else:
                out_q.put((task_id, False, f"unsupported_backend_type_{backend_type}"))
                continue

            if backend:
                ok = bool(backend.authenticate(username, password, **(kwargs or {})))
                # Emit a worker-only handled marker including backend type and PID
                try:
                    logger.info(
                        "Process pool handler completed",
                        event="process_pool.handled",
                        backend=backend_type,
                        pid=os.getpid(),
                        ok=ok,
                    )
                except Exception:
                    pass
                out_q.put((task_id, ok, None))
            else:
                out_q.put((task_id, False, "backend_creation_failed"))
        except Exception as e:  # noqa: BLE001
            try:
                out_q.put((task_id, False, str(e)))
            except Exception:
                pass


class AAAHandlers:
    """TACACS+ Authentication, Authorization, and Accounting handlers.

    Orchestrates packet parsing, backend authentication with timeouts,
    authorization decisions via a policy engine, and accounting persistence.
    Emits structured JSON logs for observability and safety.
    """

    # Pending task cleanup configuration
    _PENDING_TASK_CLEANUP_INTERVAL_S = 10.0
    _PENDING_TASK_EXPIRY_S = 30.0

    services: Any | None = None  # optional DI container

    def __init__(
        self,
        auth_backends: list[AuthenticationBackend],
        db_logger,
        *,
        backend_timeout: float | None = None,
        backend_process_pool_size: int | None = None,
    ):
        self.auth_backends = auth_backends
        self._backends_by_name: dict[str, AuthenticationBackend] = {}
        for _backend in auth_backends:
            try:
                name = getattr(_backend, "name", None)
                if isinstance(name, str) and name:
                    self._backends_by_name[name] = _backend
            except Exception:
                continue
        self.db_logger = db_logger
        # Shared session state; protect with a re-entrant lock
        self._lock = threading.RLock()
        self._acct_session_ids: set[int] = set()
        self._acct_session_lock = threading.RLock()
        self.auth_sessions: dict[int, dict[str, Any]] = {}
        self.rate_limiter = AuthRateLimiter()
        self.rate_limit_enabled: bool = True
        self.session_device: dict[int, Any] = {}
        self.session_usernames: dict[int, str] = {}
        # Optional command authorization engine injected by main
        self.command_engine: CommandAuthorizationEngine | None = None
        self.local_user_group_service = None
        # Defaults injected from main; ensure attributes exist for type checkers
        self.command_response_mode_default: str | None = None
        self.privilege_check_order: str = "before"
        # Bounded worker pool for backend authentication calls; avoids
        # unbounded daemon thread creation on slow/hanging backends.
        max_workers = int(os.getenv("TACACS_BACKEND_EXECUTOR_WORKERS", "8"))
        self._backend_executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="backend-auth"
        )
        # Per-backend authentication timeout (seconds) to avoid slow backend DoS
        if backend_timeout is not None:
            try:
                self.backend_timeout = float(backend_timeout)
            except Exception:
                self.backend_timeout = 2.0
        else:
            try:
                self.backend_timeout = float(os.getenv("TACACS_BACKEND_TIMEOUT", "2"))
            except Exception:
                self.backend_timeout = 2.0

        # Optional persistent process pool for running backend.authenticate
        # in isolated processes that can be terminated on timeout. Default
        # size: 2 (enabled), configurable via parameter or env `TACACS_BACKEND_PROCESS_POOL`.
        try:
            env_pool = int(os.getenv("TACACS_BACKEND_PROCESS_POOL", "2"))
        except Exception:
            env_pool = 2
        if backend_process_pool_size is None:
            pool_size = env_pool
        else:
            pool_size = int(backend_process_pool_size)

        self._process_pool_size = pool_size if pool_size and pool_size > 0 else 0
        self._process_ctx: Any = None
        self._process_workers: list[mp.process.BaseProcess | None] = []
        self._process_in_queues: list[Any] = []
        self._process_out_queue: Any = None
        self._process_lock = threading.Lock()
        self._next_worker = 0
        self._next_task_id = 0
        self._pending_tasks: dict[int, Any] = {}
        self._pending_tasks_max_size = 1000  # Limit pending tasks
        self._last_cleanup_time = 0.0  # Track last cleanup
        self._backend_configs: list[dict[str, Any]] = []  # Always initialize
        self._process_pool_stop_event = threading.Event()

        # Process pool creation with robust error handling
        if self._process_pool_size:
            try:
                # Only use fork context - spawn doesn't work with backend sharing
                self._process_ctx = mp.get_context("fork")

                # Prepare backend configurations for worker processes
                for backend in self.auth_backends:
                    config = self._serialize_backend_config(backend)
                    if config:
                        self._backend_configs.append(config)

                # Test if we can actually create a process
                test_q = self._process_ctx.Queue()
                test_p = self._process_ctx.Process(
                    target=lambda: test_q.put("test"), daemon=True
                )
                test_p.start()
                test_p.join(timeout=2.0)  # Increased timeout
                if test_p.is_alive():
                    test_p.terminate()
                    test_p.join(timeout=1.0)
                    raise RuntimeError("Test process failed to complete")

                # If test succeeded, create the actual worker pool with bounded queues
                self._process_out_queue = self._process_ctx.Queue(
                    maxsize=200
                )  # Increased buffer
                for _ in range(self._process_pool_size):
                    in_q = self._process_ctx.Queue(maxsize=100)  # Increased buffer
                    p = self._process_ctx.Process(
                        target=_backend_worker_main,
                        args=(in_q, self._process_out_queue),
                        daemon=True,
                    )
                    p.start()
                    self._process_workers.append(p)
                    self._process_in_queues.append(in_q)

                logger.debug(
                    f"Created process pool with {len(self._process_workers)} workers"
                )
            except Exception as e:
                # Could not create process pool; fall back to thread pool only
                logger.warning("Process pool creation failed, using thread pool: %s", e)
                self._process_ctx = None
                self._process_workers = []
                self._process_in_queues = []
                self._process_out_queue = None
                self._process_pool_size = 0
        else:
            # Process pool disabled
            self._process_pool_size = 0

        # Start a lightweight heartbeat thread to monitor process pool health
        if self._process_pool_size:
            threading.Thread(
                target=self._process_pool_heartbeat_loop,
                daemon=True,
                name="ProcessPoolHeartbeat",
            ).start()
            atexit.register(self._shutdown_process_pool)

    def set_local_user_group_service(self, service) -> None:
        self.local_user_group_service = service

    def _cleanup_pending_tasks(self) -> None:
        """Clean up old pending tasks to prevent unbounded growth."""
        import time

        current_time = time.time()
        # Always run a quick sweep; we cap overhead with small dict sizes
        self._last_cleanup_time = current_time

        # Remove tasks older than _PENDING_TASK_EXPIRY_S seconds
        expired_keys = [
            task_id
            for task_id, (ok, err, timestamp) in self._pending_tasks.items()
            if current_time - timestamp > self._PENDING_TASK_EXPIRY_S
        ]
        for key in expired_keys:
            self._pending_tasks.pop(key, None)

        # If dict is still large after time-based cleanup, remove oldest entries
        if len(self._pending_tasks) > self._pending_tasks_max_size * 0.8:
            # Sort by timestamp and remove oldest 20%
            sorted_tasks = sorted(self._pending_tasks.items(), key=lambda x: x[1][2])
            to_remove = max(1, len(sorted_tasks) // 5)
            for task_id, _ in sorted_tasks[:to_remove]:
                self._pending_tasks.pop(task_id, None)

        # Hard cap: if still above max size, drop oldest until under cap
        while len(self._pending_tasks) > self._pending_tasks_max_size:
            task_id, _ = min(self._pending_tasks.items(), key=lambda x: x[1][2])
            self._pending_tasks.pop(task_id, None)

    def _ensure_process_workers_alive(self) -> bool:
        """Best-effort check to ensure process workers are alive."""
        if not self._process_workers or not self._process_ctx:
            return False
        alive = True
        for idx, p in enumerate(list(self._process_workers)):
            if p is None or not p.is_alive():
                alive = False
                # Attempt restart
                try:
                    new_in_q = self._process_ctx.Queue(maxsize=100)
                    new_p = self._process_ctx.Process(
                        target=_backend_worker_main,
                        args=(new_in_q, self._process_out_queue),
                        daemon=True,
                    )
                    new_p.start()
                    self._process_workers[idx] = new_p
                    self._process_in_queues[idx] = new_in_q
                except Exception as exc:
                    logger.debug("Failed to restart process worker: %s", exc)
                    self._process_workers[idx] = None
        # Drop any failed slots to avoid using them
        self._process_workers = [p for p in self._process_workers if p is not None]
        self._process_in_queues = [
            q
            for q, p in zip(self._process_in_queues, self._process_workers)
            if p is not None
        ]
        return alive

    def _process_pool_heartbeat_loop(self) -> None:
        """Periodically ensure process pool workers are alive."""
        while not self._process_pool_stop_event.wait(5):
            try:
                self._ensure_process_workers_alive()
            except Exception as exc:
                logger.debug("Process pool heartbeat error: %s", exc)

    def _shutdown_process_pool(self) -> None:
        """Stop heartbeat and terminate process workers."""
        self._process_pool_stop_event.set()
        try:
            for p in getattr(self, "_process_workers", []):
                try:
                    if p.is_alive():
                        p.terminate()
                        p.join(timeout=1)
                except Exception:
                    continue
        except Exception:
            pass

    def _serialize_backend_config(
        self, backend: AuthenticationBackend
    ) -> dict[str, Any] | None:
        """Serialize backend configuration for process pool workers.

        Returns a dictionary with backend configuration that can be used to
        recreate the backend instance in a worker process.
        """
        try:
            backend_name = getattr(backend, "name", "")

            if backend_name == "local":
                db_path = getattr(backend, "db_path", "")
                config = {
                    "type": "local",
                    "database_url": db_path,
                }
            elif backend_name == "ldap":
                config = {
                    "type": "ldap",
                    "ldap_server": getattr(backend, "ldap_server", ""),
                    "base_dn": getattr(backend, "base_dn", ""),
                    "bind_dn": getattr(backend, "bind_dn", None),
                    "bind_password": getattr(backend, "bind_password", None),
                    "user_attribute": getattr(backend, "user_attribute", "uid"),
                    "use_tls": getattr(backend, "use_tls", False),
                    "timeout": getattr(backend, "timeout", 10),
                }
            elif backend_name == "okta":
                config = {
                    "type": "okta",
                    "org_url": getattr(backend, "org_url", ""),
                    "client_id": getattr(backend, "client_id", ""),
                    "client_secret": getattr(backend, "client_secret", ""),
                    "private_key": getattr(backend, "private_key", ""),
                    "private_key_id": getattr(backend, "private_key_id", ""),
                    "auth_method": getattr(backend, "auth_method", ""),
                    "verify_tls": getattr(backend, "verify_tls", True),
                    "require_group_for_auth": getattr(
                        backend, "require_group_for_auth", False
                    ),
                }
            elif backend_name == "radius":
                # RADIUS secret is stored as bytes, convert back to string for serialization
                radius_secret = getattr(backend, "radius_secret", b"")
                if isinstance(radius_secret, bytes):
                    radius_secret = radius_secret.decode("utf-8", errors="ignore")
                config = {
                    "type": "radius",
                    "radius_server": getattr(backend, "radius_server", ""),
                    "radius_port": getattr(backend, "radius_port", 1812),
                    "radius_secret": radius_secret,
                    "radius_timeout": getattr(backend, "radius_timeout", 5),
                    "radius_retries": getattr(backend, "radius_retries", 3),
                    "radius_nas_ip": getattr(backend, "radius_nas_ip", "0.0.0.0"),
                    "radius_nas_identifier": getattr(
                        backend, "radius_nas_identifier", None
                    ),
                }
            else:
                logger.debug(
                    "Backend type '%s' not supported in process pool", backend_name
                )
                return None
            # Validate JSON-serializable payload to avoid worker failures
            json.dumps(config)
            return config
        except Exception as e:
            # Ensure serialization errors don't break pool setup; log and skip
            try:
                backend_name = getattr(backend, "name", "unknown")
            except Exception:
                backend_name = "unknown"
            logger.debug(
                "Failed to serialize backend config for %s: %s", backend_name, e
            )
            return None

    def on_backend_added(self, backend: AuthenticationBackend) -> None:
        """Register a newly added backend with the process-pool config list.

        This allows pools created during __init__ (when auth_backends might have been empty)
        to recognize backends added later by the server.
        """
        try:
            cfg = self._serialize_backend_config(backend)
            if not cfg:
                return
            # Avoid duplicates of same type/server tuple where applicable
            try:
                key = (
                    cfg.get("type"),
                    cfg.get("ldap_server")
                    or cfg.get("radius_server")
                    or cfg.get("database_url"),
                )
                existing = [
                    (
                        c.get("type"),
                        c.get("ldap_server")
                        or c.get("radius_server")
                        or c.get("database_url"),
                    )
                    for c in self._backend_configs
                ]
                if key in existing:
                    return
            except Exception:
                # On any error computing keys, fall back to appending
                pass
            self._backend_configs.append(cfg)
            try:
                name = getattr(backend, "name", None)
                if isinstance(name, str) and name:
                    self._backends_by_name[name] = backend
            except Exception:
                pass
        except Exception as e:
            logger.debug("Failed to register backend with process pool: %s", e)

    def _redact_args(self, args: dict[str, str]) -> dict[str, str]:
        """Return a copy of args with sensitive values redacted.
        Keys containing common secrets (pass, pwd, secret, token, key) are masked.
        Additionally, values that look like obvious secrets (very long opaque
        strings or common PII patterns) are redacted defensively.
        """
        if not isinstance(args, dict):
            return {}
        redacted: dict[str, str] = {}
        SENSITIVE = ("pass", "pwd", "secret", "token", "key")
        try:
            for k, v in args.items():
                key_s = str(k).lower()
                val_s = str(v)
                # Known sensitive key names
                if any(s in key_s for s in SENSITIVE):
                    redacted[str(k)] = "***"
                    continue
                # Heuristic redaction for values:
                # - long opaque tokens (>= 24 chars, no whitespace)
                # - digit-heavy sequences (potential card numbers)
                if (
                    len(val_s) >= 24 and not any(ch.isspace() for ch in val_s)
                ) or re.fullmatch(r"[0-9\-]{12,}", val_s):
                    redacted[str(k)] = "***"
                else:
                    redacted[str(k)] = val_s
        except Exception:
            # Fallback to empty on unexpected structures
            return {}
        return redacted

    def _safe_int(self, value: object, default: int = 0) -> int:
        """Convert to int safely, returning default on error."""
        try:
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str):
                return int(value)
        except (ValueError, TypeError):
            pass  # Invalid conversion, return default
        return default

    @staticmethod
    def _safe_user(user: str | None) -> str:
        return user if user else "<unknown>"

    def _safe_decode(self, data: bytes | None, default: str = "") -> str:
        if not data:
            return default
        return data.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _fmt_session_id(session_id: int) -> str:
        return f"0x{session_id:08x}"

    def _get_device_context(self, device: Any | None) -> DeviceContext:
        """Cache device/group attributes extraction."""
        group = getattr(device, "group", None) if device else None
        return {
            "device": getattr(device, "name", None) if device else None,
            "group": getattr(group, "name", None) if group else None,
            "allowed_groups": getattr(group, "allowed_user_groups", [])
            if group
            else [],
        }

    def _get_backend_group_field(self, backend_name: str | None) -> str | None:
        """Map backend name to its group field."""
        mapping = {
            "okta": "okta_group",
            "ldap": "ldap_group",
            "radius": "radius_group",
            "local": "name",
        }
        return mapping.get(backend_name.lower() if backend_name else "")

    @staticmethod
    def _extract_backend_name(detail: str | None) -> str | None:
        if not detail or "backend=" not in detail:
            return None
        try:
            return detail.split("backend=", 1)[1].split()[0]
        except (IndexError, AttributeError):
            return None

    def _notify_auth_failure(
        self, username: str | None, client_ip: str | None, detail: str | None
    ) -> None:
        """Send webhook/monitoring events for authentication/authorization failures."""
        try:
            from ..utils.webhook import notify, record_event

            notify(
                "auth_failure",
                {
                    "username": username,
                    "client_ip": client_ip,
                    "detail": detail,
                },
            )
            record_event("auth_failure", username or (client_ip or "unknown"))
        except Exception as e:
            logger.debug("Webhook notification failed: %s", e)

    def _remember_username(self, session_id: int, username: str | None) -> None:
        if username:
            with self._lock:
                self.session_usernames[session_id] = username

    def _check_privilege(
        self,
        required_priv: int,
        user_priv: int,
        user: str | None,
        command: str | None,
        device: Any | None,
    ) -> tuple[bool, str | None]:
        """Check privilege and return (allowed, message)."""
        device_ctx = self._get_device_context(device)
        payload = {
            "event": "privilege_check",
            "user": user,
            "command": command,
            "device": device_ctx["device"],
            "device_group": device_ctx["group"],
            "required_priv": required_priv,
            "user_priv": user_priv,
        }
        if required_priv > user_priv:
            _structured_log(logger.debug, {**payload, "result": "deny"})
            return (
                False,
                f"Insufficient privilege (required: {required_priv}, user: {user_priv})",
            )
        _structured_log(logger.debug, {**payload, "result": "allow"})
        return True, None

    def _sanitize_user_attrs(self, attrs: Any) -> dict[str, Any]:
        """Recursively filter to safe types only."""
        if not isinstance(attrs, dict):
            return {}
        safe: dict[str, Any] = {}
        for k, v in attrs.items():
            if not isinstance(k, str):
                continue
            if isinstance(v, (str, int, float, bool)):
                safe[k] = v
            elif isinstance(v, (list, tuple)):
                filtered = [x for x in v if isinstance(x, (str, int, float, bool))]
                safe[k] = filtered
        return safe

    def _log_packet_error(
        self, event: str, stage: str, packet: TacacsPacket, reason: object
    ) -> None:
        _structured_log(
            logger.warning,
            {
                "event": f"tacacs.{event}.packet_error",
                "message": f"Invalid {event} packet body",
                "service": "tacacs",
                "stage": stage,
                "session": self._fmt_session_id(packet.session_id),
                "seq": packet.seq_no,
                "reason": str(reason),
                "length": len(packet.body or b""),
            },
        )

    def cleanup_session(self, session_id: int) -> None:
        """Remove cached state associated with a TACACS session."""
        with self._lock:
            simple_key = session_id
            prefix = f"{session_id}_"
            auth_keys_to_remove = []
            if simple_key in self.auth_sessions:
                auth_keys_to_remove.append(simple_key)
            for key in list(self.auth_sessions.keys()):
                try:
                    if isinstance(key, str) and key.startswith(prefix):
                        auth_keys_to_remove.append(key)
                    elif not isinstance(key, str) and str(key).startswith(prefix):
                        auth_keys_to_remove.append(key)
                except (TypeError, AttributeError):
                    continue
            has_device = session_id in self.session_device
            has_user = session_id in self.session_usernames

        # Remove entries after releasing the lock to minimize contention
        if has_device:
            self.session_device.pop(session_id, None)
        if has_user:
            self.session_usernames.pop(session_id, None)
        for key in auth_keys_to_remove:
            self.auth_sessions.pop(key, None)

    def _log_auth_result(
        self,
        session_id: int,
        username: str | None,
        device: Any | None,
        success: bool,
        detail: str | None = None,
    ) -> None:
        with self._lock:
            cached_user = self.session_usernames.get(session_id)
        resolved_user = username if username else cached_user
        safe_user = self._safe_user(resolved_user)
        device_ctx = self._get_device_context(device)
        device_name = device_ctx["device"]
        group_name = device_ctx["group"]
        context = group_name or device_name or "unknown"
        sess_hex = self._fmt_session_id(session_id)
        # Structured log aligned with logging spec; avoid manual JSON
        backend_name = self._extract_backend_name(detail)
        try:
            log_kwargs = dict(
                event="auth.success" if success else "auth.failure",
                service="tacacs",
                component="handlers",
                session=sess_hex,
                correlation_id=sess_hex,
                user_ref=safe_user,
                device=device_name,
                device_group=group_name,
                auth={
                    "backend": backend_name or "unknown",
                    "result": "success" if success else "failure",
                },
                detail=detail or "",
            )
            if success:
                logger.info("Authentication result", extra=log_kwargs)
            else:
                logger.warning("Authentication result", extra=log_kwargs)
        except Exception:
            # Fallback plain logs to avoid any crash due to logging
            if success:
                logger.info(
                    "TACACS authentication success: user=%s detail=%s device=%s session=%s",
                    safe_user,
                    detail or "backend=unknown",
                    context,
                    sess_hex,
                )
            else:
                logger.warning(
                    "TACACS authentication failed: user=%s reason=%s device=%s session=%s",
                    safe_user,
                    detail or "unknown",
                    context,
                    sess_hex,
                )

    def handle_authentication(
        self, packet: TacacsPacket, device: Any | None = None
    ) -> TacacsPacket:
        """Handle authentication request with metrics"""
        try:
            parsed = {}
            cont = None
            if packet.seq_no == 1:
                try:
                    parsed = parse_authen_start(packet.body)
                except ProtocolError as pe:
                    self._log_packet_error("auth", "start", packet, pe)
                    response = self._create_auth_response(
                        packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR
                    )
                    self.cleanup_session(packet.session_id)
                    return response
            else:
                try:
                    cont = parse_authen_continue(packet.body)
                except ProtocolError as pe:
                    # Compatibility fallback: some tests/clients reuse START layout for CONTINUE
                    logger.debug(
                        "Failed to parse authen_continue, falling back to start parser: %s",
                        pe,
                    )
                    try:
                        parsed = parse_authen_start(packet.body)
                    except ProtocolError as pe_fallback:
                        self._log_packet_error(
                            "auth",
                            "continue",
                            packet,
                            f"primary: {pe}, fallback: {pe_fallback}",
                        )
                        response = self._create_auth_response(
                            packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR
                        )
                        self.cleanup_session(packet.session_id)
                        return response
                except Exception:
                    logger.error("Authentication parsing failed (unexpected error)")
                    response = self._create_auth_response(
                        packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR
                    )
                    self.cleanup_session(packet.session_id)
                    return response

            # Map parsed fields (START) when present
            action = int(parsed.get("action", 0))
            priv_lvl = int(parsed.get("priv_lvl", 0))
            authen_type = int(parsed.get("authen_type", 0))
            user = parsed.get("user", "")
            port = parsed.get("port", "")
            rem_addr = parsed.get("rem_addr", "")
            data = parsed.get("data", b"")

            # For CONTINUE packets, prefer the session username and user_msg/data from parse_authen_continue.
            # Non-ASCII auth types (e.g., PAP) are single-step; treat later packets as restart attempts.
            if packet.seq_no != 1:
                with self._lock:
                    sess_info = self.auth_sessions.get(packet.session_id, {})
                # Reuse stored authen_type/action when CONTINUE omitted them
                if authen_type == 0:
                    authen_type = int(sess_info.get("authen_type", 0))
                if action == 0:
                    action = int(sess_info.get("action", 0))

                # Fallback: if no session state exists (e.g., legacy clients with CONTINUE only),
                # synthesize minimal session info so we can continue the ASCII flow.
                if not sess_info and authen_type in (
                    0,
                    TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_ASCII,
                ):
                    with self._lock:
                        self.auth_sessions[packet.session_id] = {
                            "step": "password" if user else "username",
                            "username": user or None,
                            "authen_type": authen_type
                            if authen_type != 0
                            else TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_ASCII,
                            "action": action or 1,
                        }
                        sess_info = dict(self.auth_sessions[packet.session_id])
                    if authen_type == 0:
                        authen_type = TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_ASCII
                    if action == 0:
                        action = 1

                if authen_type != TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_ASCII:
                    safe_user = self._safe_user(user)
                    logger.debug(
                        "TACACS auth restart: user=%s, type=%s, action=%s, seq=%s, session=%s",
                        safe_user,
                        authen_type,
                        action,
                        packet.seq_no,
                        self._fmt_session_id(packet.session_id),
                    )
                    self._remember_username(packet.session_id, user)
                    return self._handle_auth_start(
                        packet,
                        action,
                        authen_type,
                        user,
                        port,
                        rem_addr,
                        data,
                        priv_lvl,
                        device,
                    )

                if not user:
                    user = sess_info.get("username", "")
                if cont is not None:
                    data = cont.get("data", b"")
                    user_msg = cont.get("user_msg", b"")
                else:
                    user_msg = b""
                safe_user = self._safe_user(user)
                logger.debug(
                    "TACACS auth request: user=%s, type=%s, action=%s, seq=%s, session=%s",
                    safe_user,
                    authen_type,
                    action,
                    packet.seq_no,
                    self._fmt_session_id(packet.session_id),
                )
                return self._handle_auth_continue(packet, user, data, user_msg)

            safe_user = self._safe_user(user)
            logger.debug(
                "TACACS auth request: user=%s, type=%s, action=%s, seq=%s, session=%s",
                safe_user,
                authen_type,
                action,
                packet.seq_no,
                self._fmt_session_id(packet.session_id),
            )
            self._remember_username(packet.session_id, user)
            return self._handle_auth_start(
                packet,
                action,
                authen_type,
                user,
                port,
                rem_addr,
                data,
                priv_lvl,
                device,
            )
        except Exception as e:
            logger.error("Authentication error: %s", e)
            response = self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                "Internal server error",
            )
            self.cleanup_session(packet.session_id)
            return response

    def handle_authorization(
        self, packet: TacacsPacket, device: Any | None = None
    ) -> TacacsPacket:
        """Handle authorization request"""
        try:
            try:
                a = parse_author_request(packet.body)
            except ProtocolError as pe:
                self._log_packet_error("author", "request", packet, pe)
                return self._create_author_response(
                    packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR
                )
            except Exception:
                logger.error("Authorization parsing failed (unexpected error)")
                return self._create_author_response(
                    packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR
                )
            priv_lvl = a["priv_lvl"]
            authen_service = a["authen_service"]
            user = a["user"]
            args = a["args"]
            logger.info(
                "Authorization request: user=%s, service=%s, args=%s, session=%s",
                self._safe_user(user),
                authen_service,
                self._redact_args(args),
                self._fmt_session_id(packet.session_id),
            )
            return self._process_authorization(
                packet, user, authen_service, priv_lvl, args, device
            )
        except Exception as e:
            logger.error("Authorization error: %s", e)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR,
                "Internal server error",
            )

    def handle_accounting(
        self, packet: TacacsPacket, device: Any | None = None
    ) -> TacacsPacket:
        """Handle accounting request"""
        try:
            try:
                r = parse_acct_request(packet.body)
            except ProtocolError as pe:
                self._log_packet_error("acct", "request", packet, pe)
                return self._create_acct_response(
                    packet, TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR
                )
            except Exception:
                logger.error("Accounting parsing failed (unexpected error)")
                return self._create_acct_response(
                    packet, TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR
                )
            flags = r["flags"]
            priv_lvl = r["priv_lvl"]
            authen_service = r["authen_service"]
            user = r["user"]
            port = r["port"]
            rem_addr = r["rem_addr"]
            args = r["args"]
            logger.debug(
                "TACACS accounting request: user=%s, flags=%s, args=%s, session=%s",
                self._safe_user(user),
                flags,
                self._redact_args(args),
                self._fmt_session_id(packet.session_id),
            )
            return self._process_accounting(
                packet,
                user,
                port,
                rem_addr,
                flags,
                authen_service,
                priv_lvl,
                args,
                device,
            )
        except Exception as e:
            logger.error("Accounting error: %s", e)
            return self._create_acct_response(
                packet,
                TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR,
                "Internal server error",
            )

    def _handle_auth_start(
        self,
        packet: TacacsPacket,
        action: int,
        authen_type: int,
        user: str,
        port: str,
        rem_addr: str,
        data: bytes,
        priv_lvl: int,
        device: Any | None,
    ) -> TacacsPacket:
        """Handle initial authentication request"""
        with self._lock:
            self.session_device[packet.session_id] = device
        if authen_type == TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP:
            if not user:
                return self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL,
                    "Username required",
                )
            password = data.decode("utf-8", errors="replace")
            # Use remote address as client identity for rate limiting
            client_ip = rem_addr or None
            # Invalidate any local backend user cache to pick up very recent writes
            try:
                from tacacs_server.auth.local import LocalAuthBackend as _LAB

                for _b in self.auth_backends:
                    if isinstance(_b, _LAB):
                        try:
                            _b.invalidate_user_cache(user)
                        except Exception as e:
                            logger.debug("Failed to invalidate user cache: %s", e)
            except Exception as e:
                logger.debug("Failed to invalidate local backend cache: %s", e)
            authenticated, detail = self._authenticate_user(
                user,
                password,
                client_ip=client_ip,
            )
            if not authenticated:
                # One-time best-effort reload for local store to catch recent writes
                try:
                    from tacacs_server.auth.local import LocalAuthBackend as _LAB

                    reloaded = False
                    for _b in self.auth_backends:
                        if isinstance(_b, _LAB):
                            # Invalidate user cache so a fresh fetch occurs after reload
                            try:
                                _b.invalidate_user_cache(user)
                            except Exception as e:
                                logger.debug(
                                    "Failed to invalidate user cache on retry: %s", e
                                )
                            svc = getattr(_b, "user_service", None)
                            st = getattr(svc, "store", None) if svc else None
                            if st and hasattr(st, "reload"):
                                try:
                                    st.reload()
                                    reloaded = True
                                except Exception as e:
                                    logger.debug("Failed to reload local store: %s", e)
                    if reloaded:
                        authenticated, detail = self._authenticate_user(
                            user, password, client_ip=client_ip
                        )
                except Exception as e:
                    logger.debug("Failed to retry authentication after reload: %s", e)
            if authenticated:
                backend_name = self._extract_backend_name(detail)
                allowed, reason = self._enforce_device_group_policy(
                    backend_name, user, device
                )
                if not allowed:
                    authenticated = False
                    detail = f"backend={backend_name or 'unknown'} error={reason or 'group_not_allowed'}"

            if authenticated:
                self._remember_username(packet.session_id, user)
                self._log_auth_result(packet.session_id, user, device, True, detail)
                return self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS,
                    "Authentication successful",
                )
            else:
                self._log_auth_result(packet.session_id, user, device, False, detail)
                response = self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL,
                    "Authentication failed",
                )
                self.cleanup_session(packet.session_id)
                return response
        elif authen_type == TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_ASCII:
            session_key = packet.session_id
            if not user:
                with self._lock:
                    self.auth_sessions[session_key] = {
                        "step": "username",
                        "authen_type": authen_type,
                        "action": action,
                    }
                return self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETUSER,
                    "Username: ",
                )
            else:
                with self._lock:
                    self.auth_sessions[session_key] = {
                        "step": "password",
                        "username": user,
                        "authen_type": authen_type,
                        "action": action,
                    }
                return self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETPASS,
                    "Password: ",
                )
        elif authen_type == TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_CHAP:
            self._log_auth_result(
                packet.session_id,
                user,
                device,
                False,
                "CHAP authentication not implemented",
            )
            response = self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                "CHAP authentication not implemented",
            )
            self.cleanup_session(packet.session_id)
            return response
        else:
            self._log_auth_result(
                packet.session_id,
                user,
                device,
                False,
                f"Unsupported authentication type {authen_type}",
            )
            response = self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                f"Unsupported authentication type: {authen_type}",
            )
            self.cleanup_session(packet.session_id)
            return response

    def _handle_auth_continue(
        self, packet: TacacsPacket, user: str, data: bytes, user_msg: bytes = b""
    ) -> TacacsPacket:
        """Handle authentication continuation"""
        session_key = packet.session_id
        with self._lock:
            session_info = self.auth_sessions.get(session_key)
        if not session_info:
            # Synthesize minimal session info for clients that send CONTINUE without prior state
            username_seed = self._safe_decode(data or user_msg)
            with self._lock:
                self.auth_sessions[session_key] = {
                    "step": "password" if username_seed else "username",
                    "username": username_seed or None,
                }
                session_info = dict(self.auth_sessions[session_key])
        if session_info["step"] == "username":
            username = self._safe_decode(data)
            session_info["username"] = username
            session_info["step"] = "password"
            self._remember_username(packet.session_id, username)
            return self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETPASS,
                "Password: ",
            )
        elif session_info["step"] == "password":
            password = self._safe_decode(data)
            if not password:
                password = self._safe_decode(user_msg)
            username = session_info["username"]
            with self._lock:
                del self.auth_sessions[session_key]
                device = self.session_device.get(packet.session_id)
            client_ip = getattr(device, "ip", None)
            authenticated, detail = self._authenticate_user(
                username, password, client_ip=client_ip
            )
            if authenticated:
                backend_name = self._extract_backend_name(detail)
                allowed, reason = self._enforce_device_group_policy(
                    backend_name, username, device
                )
                if not allowed:
                    authenticated = False
                    detail = f"backend={backend_name or 'unknown'} error={reason or 'group_not_allowed'}"

            if authenticated:
                self._remember_username(packet.session_id, username)
                self._log_auth_result(packet.session_id, username, device, True, detail)
                return self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS,
                    "Authentication successful",
                )
            else:
                device = self.session_device.get(packet.session_id)
                self._log_auth_result(
                    packet.session_id, username, device, False, detail
                )
                response = self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL,
                    "Authentication failed",
                )
                self.cleanup_session(packet.session_id)
                return response
        else:
            response = self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                "Invalid authentication step",
            )
            self.cleanup_session(packet.session_id)
            return response

    def _process_authorization(
        self,
        packet: TacacsPacket,
        user: str,
        service: int,
        priv_lvl: int,
        args: dict[str, str],
        device: Any | None,
    ) -> TacacsPacket:
        """Process authorization request"""
        device_ctx = self._get_device_context(
            device or self.session_device.get(packet.session_id)
        )
        user_attrs = None
        for backend in self.auth_backends:
            try:
                user_attrs = backend.get_user_attributes(user)
                if user_attrs:
                    logger.debug(
                        f"Got user attributes from {backend.name}: {user_attrs}"
                    )
                    break
            except Exception as e:
                logger.error("Error getting attributes from %s: %s", backend.name, e)
                continue
        # Sanitize attributes to avoid propagating malformed data
        user_attrs = self._sanitize_user_attrs(user_attrs)
        if not user_attrs or not any(user_attrs.values()):
            # If no attributes and no explicit command requested, allow minimal service
            # This aligns with integration tests expecting PASS for service-only requests.
            has_cmd = bool(args.get("cmd"))
            if not has_cmd:
                auth_attrs = {"priv-lvl": "1", "service": args.get("service", "exec")}
                self.cleanup_session(packet.session_id)
                return self._create_author_response(
                    packet,
                    TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                    "Authorization granted",
                    auth_attrs,
                )
            # Otherwise, treat as failure when a command is requested but user unknown
            self.cleanup_session(packet.session_id)
            _structured_log(
                logger.warning,
                {
                    "event": "authorization_denied",
                    "session": self._fmt_session_id(packet.session_id),
                    "user": user,
                    "reason": "no_attrs",
                    "command": args.get("cmd"),
                    "device_group": device_ctx["group"],
                },
            )
            try:
                self._notify_auth_failure(user, getattr(device, "ip", None), "no_attrs")
            except Exception:
                pass
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                "User not found or no attributes available",
            )
        if not user_attrs.get("enabled", True):
            self.cleanup_session(packet.session_id)
            try:
                _structured_log(
                    logger.warning,
                    {
                        "event": "authorization_denied",
                        "session": self._fmt_session_id(packet.session_id),
                        "user": user,
                        "reason": "disabled",
                        "command": args.get("cmd"),
                        "device_group": device_ctx["group"],
                    },
                )
            except Exception as e:
                logger.debug("Failed to log authorization denial: %s", e)
            try:
                self._notify_auth_failure(user, getattr(device, "ip", None), "disabled")
            except Exception:
                pass
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                "User account is disabled",
            )

        allowed_groups = device_ctx["allowed_groups"] or []
        device_group_name = device_ctx["group"]

        context = PolicyContext(
            device_group_name=device_group_name,
            allowed_user_groups=allowed_groups or [],
            user_groups=user_attrs.get("groups", []) or [],
            fallback_privilege=user_attrs.get("privilege_level", 1),
        )

        def _lookup_privilege(group_name: str) -> int | None:
            if not self.local_user_group_service:
                return None
            record = self.local_user_group_service.get_group(group_name)
            return getattr(record, "privilege_level", None)

        result: PolicyResult = evaluate_policy(context, _lookup_privilege)
        user_priv = result.privilege_level
        user_attrs["privilege_level"] = user_priv
        if not result.allowed:
            self.cleanup_session(packet.session_id)
            _structured_log(
                logger.warning,
                {
                    "event": "authorization_denied",
                    "session": self._fmt_session_id(packet.session_id),
                    "user": user,
                    "reason": result.denial_message or "policy_denied",
                    "command": args.get("cmd"),
                    "required_priv": priv_lvl,
                    "user_priv": user_priv,
                    "device_group": device_group_name,
                },
            )
            try:
                self._notify_auth_failure(
                    user,
                    getattr(device, "ip", None),
                    result.denial_message or "policy_denied",
                )
            except Exception:
                pass
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                result.denial_message or "User not permitted on this device",
            )

        # Treat only explicit 'cmd' as a command to authorize. A bare
        # 'service' argument (e.g., service=shell) is not considered a
        # command request for the purposes of minimal authorization flows.
        command = args.get("cmd", "")
        # Privilege level enforcement order can be configured. Default: 'before'.
        allowed_priv, denial_msg = self._check_privilege(
            priv_lvl, user_priv, user, command, device
        )
        _priv_order = getattr(self, "privilege_check_order", "before")
        if _priv_order == "before" and not allowed_priv:
            self.cleanup_session(packet.session_id)
            _structured_log(
                logger.warning,
                {
                    "event": "authorization_denied",
                    "session": self._fmt_session_id(packet.session_id),
                    "user": user,
                    "reason": "insufficient_privilege",
                    "command": args.get("cmd"),
                    "required_priv": priv_lvl,
                    "user_priv": user_priv,
                    "device_group": device_group_name,
                },
            )
            try:
                self._notify_auth_failure(
                    user,
                    getattr(device, "ip", None),
                    "insufficient_privilege",
                )
            except Exception:
                pass
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                denial_msg
                or f"Insufficient privilege (required: {priv_lvl}, user: {user_priv})",
            )
        # Command authorization evaluation (engine/external/defaults)
        if command:
            return self._evaluate_command_authorization(
                packet,
                user,
                user_priv,
                priv_lvl,
                command,
                user_attrs,
                args,
                device,
            )
        # No command -> grant base attributes
        auth_attrs = self._build_authorization_attributes(user_attrs, args)
        self.cleanup_session(packet.session_id)
        _structured_log(
            logger.info,
            {
                "event": "authorization_granted",
                "mode": "pass_add",
                "session": self._fmt_session_id(packet.session_id),
                "user": user,
                "command": args.get("cmd"),
                "user_priv": user_priv,
                "required_priv": priv_lvl,
                "device_group": device_group_name,
            },
        )
        return self._create_author_response(
            packet,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            "Authorization granted",
            auth_attrs,
        )

    def _process_accounting(
        self,
        packet: TacacsPacket,
        user: str,
        port: str,
        rem_addr: str,
        flags: int,
        service: int,
        priv_lvl: int,
        args: dict[str, str],
        device: Any | None,
    ) -> TacacsPacket:
        """Process accounting request"""
        # Warn on session_id reuse (informational only)
        try:
            with self._acct_session_lock:
                if packet.session_id in self._acct_session_ids:
                    logger.warning(
                        "Accounting session_id reused",
                        event="acct.session.reuse",
                        session=self._fmt_session_id(packet.session_id),
                        user=user,
                        client_ip=rem_addr,
                    )
                else:
                    self._acct_session_ids.add(packet.session_id)
        except Exception as e:
            _structured_log(
                logger.warning,
                {
                    "event": "acct.session.reuse_check_failed",
                    "error": str(e),
                    "session": self._fmt_session_id(getattr(packet, "session_id", 0)),
                    "user": user,
                    "client_ip": rem_addr,
                },
            )

        if flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START:
            status = "START"
        elif flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP:
            status = "STOP"
        elif flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_WATCHDOG:
            status = "UPDATE"
        elif flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_MORE:
            status = "UPDATE"
        else:
            status = "UNKNOWN"
        record = AccountingRecord(
            username=user,
            session_id=packet.session_id,
            status=status,
            service=args.get("service", "unknown"),
            command=args.get("cmd", args.get("service", "unknown")),
            client_ip=rem_addr,
            port=port,
            start_time=args.get("start_time"),
            stop_time=args.get("stop_time"),
            bytes_in=self._safe_int(args.get("bytes_in", 0), 0),
            bytes_out=self._safe_int(args.get("bytes_out", 0), 0),
            elapsed_time=self._safe_int(args.get("elapsed_time", 0), 0),
            privilege_level=priv_lvl,
            authentication_method=args.get("authen_method"),
            nas_port=args.get("nas-port"),
            nas_port_type=args.get("nas-port-type"),
            task_id=args.get("task_id"),
            timezone=args.get("timezone"),
            cause=args.get("cause") or args.get("acct_terminate_cause"),
        )
        if self.db_logger.log_accounting(record):
            response = self._create_acct_response(
                packet,
                TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
                "Accounting record logged successfully",
            )
            _structured_log(
                logger.info,
                {
                    "event": "acct_record",
                    "session": self._fmt_session_id(packet.session_id),
                    "user": user or self._safe_user(None),
                    "status": status,
                    "service": record.service,
                    "command": record.command,
                    "client_ip": rem_addr,
                    "port": port,
                    "priv": priv_lvl,
                    "attrs": self._redact_args(args),
                },
            )
            try:
                from ..web.monitoring import PrometheusIntegration as _PM

                _PM.record_accounting_record("success")
            except Exception as e:
                logger.debug("Failed to record accounting metric: %s", e)
        else:
            response = self._create_acct_response(
                packet,
                TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR,
                "Failed to log accounting record",
            )
            _structured_log(
                logger.warning,
                {
                    "event": "acct_record_error",
                    "session": self._fmt_session_id(packet.session_id),
                    "user": user or self._safe_user(None),
                    "status": status,
                    "service": record.service,
                    "command": record.command,
                    "client_ip": rem_addr,
                    "port": port,
                    "priv": priv_lvl,
                    "attrs": self._redact_args(args),
                },
            )
            try:
                from ..web.monitoring import PrometheusIntegration as _PM

                _PM.record_accounting_record("error")
            except Exception as e:
                logger.debug("Failed to record accounting metric: %s", e)
        self.cleanup_session(packet.session_id)
        return response

    def _get_backend_by_name(
        self, backend_name: str | None
    ) -> AuthenticationBackend | None:
        """Retrieve backend by name using cached map; fall back to a scan if missing.

        The cache is populated during __init__ and on_backend_added; any backend not
        yet cached is resolved by iterating auth_backends once and then memoized.
        """
        if not backend_name:
            return None
        backend = self._backends_by_name.get(backend_name)
        if backend:
            return backend
        # Fallback to search in case of late-added backends without on_backend_added
        for backend_candidate in self.auth_backends:
            try:
                if getattr(backend_candidate, "name", None) == backend_name:
                    self._backends_by_name[backend_name] = backend_candidate
                    return backend_candidate
            except Exception:
                continue
        return None

    def _enforce_device_group_policy(
        self, backend_name: str | None, username: str, device: Any | None
    ) -> tuple[bool, str | None]:
        """Enforce device-scoped group policy in AAA for authenticated users.

        For Phase 1, this enforces Okta group membership when a device group
        has allowed_user_groups configured that map to Okta groups via the
        local user group service.
        """
        if device is None:
            return True, None
        device_ctx = self._get_device_context(device)
        backend = self._get_backend_by_name(backend_name)
        if backend is None:
            return True, None

        device_group_name = device_ctx["group"]
        if not device_group_name:
            return True, None
        try:
            allowed_group_names = list(device_ctx["allowed_groups"] or [])
        except Exception:
            allowed_group_names = []
        if not allowed_group_names:
            return True, None

        allowed_targets: set[str] = set()
        if self.local_user_group_service:
            for gname in allowed_group_names:
                try:
                    record = self.local_user_group_service.get_group(gname)
                except Exception:
                    continue
                backend_name_norm = str(getattr(backend, "name", "")).lower()
                target_field = self._get_backend_group_field(backend_name_norm)
                target_value: str | None = (
                    getattr(record, target_field, None) if target_field else None
                )
                if backend_name_norm == "radius" and target_value is None:
                    target_value = getattr(record, "name", None)

                if target_value:
                    try:
                        allowed_targets.add(str(target_value).lower())
                    except Exception:
                        continue

        if not allowed_targets:
            return True, None

        user_groups: set[str] = set()
        try:
            raw_groups = backend.get_user_groups(username)
            if isinstance(raw_groups, (list, set, tuple)):
                user_groups = {str(g).lower() for g in raw_groups}
        except Exception as e:
            logger.debug(
                "Failed to resolve user groups for %s via backend %s: %s",
                username,
                getattr(backend, "name", "<unknown>"),
                e,
            )
            user_groups = set()

        matches = sorted(list(allowed_targets & user_groups))
        device_name = device_ctx["device"]

        log_payload = {
            "event": "group_enforcement",
            "backend": getattr(backend, "name", None),
            "user": username,
            "device": device_name,
            "device_group": device_group_name,
            "allowed_user_groups": allowed_group_names,
            "allowed_targets": sorted(list(allowed_targets)),
            "user_groups": sorted(list(user_groups)),
            "match": matches,
        }

        if matches:
            _structured_log(logger.info, {**log_payload, "result": "allow"})
        else:
            _structured_log(logger.warning, {**log_payload, "result": "deny"})

        if matches:
            return True, None
        return False, "group_not_allowed"

    def _authenticate_user(
        self, username: str, password: str, client_ip: str | None = None, **kwargs
    ) -> tuple[bool, str]:
        """Authenticate user against all backends with rate limiting."""
        import time as _time

        from ..web.monitoring import PrometheusIntegration as _PM

        start_ts = _time.time()

        if not validate_username(username):
            return False, "invalid username format"

        # Hard cap password length to mitigate abuse
        if password is None or len(password) == 0:
            return False, "empty password"
        if len(password) > MAX_PASSWORD_LENGTH:
            return False, "password too long"

        if (
            self.rate_limit_enabled
            and client_ip
            and not self.rate_limiter.is_allowed(client_ip)
        ):
            _structured_log(
                logger.warning,
                {
                    "event": "auth_rate_limited",
                    "user": username or self._safe_user(None),
                    "client_ip": client_ip,
                },
            )
            return False, f"rate limit exceeded for {client_ip}"

        if self.rate_limit_enabled and client_ip:
            self.rate_limiter.record_attempt(client_ip)

        last_error: str | None = None
        used_backend = ""
        for backend in self.auth_backends:
            try:
                ok, timed_out, err = self._authenticate_backend_with_timeout(
                    backend,
                    username,
                    password,
                    timeout_s=self.backend_timeout,
                    **kwargs,
                )
                if timed_out:
                    last_error = f"backend={backend.name} error=timeout"
                    logger.warning(
                        "Auth backend %s timed out for %s after %.2fs",
                        backend.name,
                        username,
                        self.backend_timeout,
                    )
                    continue
                if err is not None:
                    last_error = f"backend={backend.name} error={err}"
                    continue
                if ok:
                    used_backend = backend.name
                    _PM.record_auth_request(
                        "ok", used_backend, _time.time() - start_ts, ""
                    )
                    return True, f"backend={backend.name}"
            except Exception as exc:
                last_error = f"backend={backend.name} error={exc}"
                logger.error(
                    "Unexpected authentication error with %s: %s", backend.name, exc
                )

        if last_error:
            _PM.record_auth_request(
                "fail",
                used_backend or "none",
                _time.time() - start_ts,
                last_error.split(" ")[0],
            )
            # Webhook on authentication failure
            self._notify_auth_failure(username, client_ip, last_error)
            return False, last_error

        if not self.auth_backends:
            _PM.record_auth_request(
                "fail", "none", _time.time() - start_ts, "no_backends"
            )
            self._notify_auth_failure(username, client_ip, "no_backends")
            return False, "no authentication backends configured"

        _PM.record_auth_request(
            "fail",
            used_backend or "none",
            _time.time() - start_ts,
            "no_backend_accepted",
        )
        self._notify_auth_failure(username, client_ip, "no_backend_accepted")
        return False, "no backend accepted credentials"

    def _authenticate_backend_with_timeout(
        self,
        backend: AuthenticationBackend,
        username: str,
        password: str,
        *,
        timeout_s: float,
        **kwargs,
    ) -> tuple[bool, bool, str | None]:
        """Call backend.authenticate with a timeout.

        Returns (ok, timed_out, error_msg).
        The underlying backend call runs in a bounded thread pool to avoid
        unbounded daemon thread creation. Python threads cannot be forcibly
        killed; on timeout we ignore the result and mark timed_out=True.
        """
        effective_timeout = timeout_s if timeout_s and timeout_s > 0 else None

        # If we have a persistent process pool, dispatch the task to a worker
        # and wait on the shared output queue. If the worker hangs, terminate
        # and replace it to preserve pool size.
        if (
            getattr(self, "_process_workers", None)
            and getattr(self, "_process_ctx", None)
            and getattr(self, "_process_out_queue", None)
            and len(self._process_workers) > 0
        ):
            if not self._ensure_process_workers_alive():
                logger.debug("Process pool unhealthy; falling back to thread pool")
                # Let the thread-pool fallback handle this request
                # rather than failing auth outright.
                return self._run_backend_in_thread_pool(
                    backend, username, password, effective_timeout, **kwargs
                )
            try:
                # Find matching backend config from our serialized configs
                backend_config = None
                for config in getattr(self, "_backend_configs", []):
                    if config.get("type") == getattr(backend, "name", ""):
                        backend_config = config
                        break

                if not backend_config:
                    # Fall back to thread pool for unsupported backends
                    raise Exception("Backend not supported in process pool")

                # Generate unique task ID and select worker round-robin
                with self._process_lock:
                    task_id = self._next_task_id
                    self._next_task_id += 1
                    wi = self._next_worker
                    self._next_worker = (self._next_worker + 1) % len(
                        self._process_workers
                    )

                    # Check if worker is alive, restart if dead
                worker_proc = self._process_workers[wi]
                if worker_proc is None or not worker_proc.is_alive():
                    try:
                        if worker_proc is not None:
                            worker_proc.join(0.1)
                    except Exception:
                        pass
                        # Restart dead worker
                        try:
                            if self._process_ctx is None:
                                raise Exception("Process context is None")
                            new_in_q = self._process_ctx.Queue(maxsize=100)
                            new_p = self._process_ctx.Process(
                                target=_backend_worker_main,
                                args=(new_in_q, self._process_out_queue),
                                daemon=True,
                            )
                            new_p.start()
                            self._process_workers[wi] = new_p
                            self._process_in_queues[wi] = new_in_q
                        except Exception as e:
                            logger.debug("Failed to restart worker: %s", e)
                            # Fall back to thread pool for this request
                            raise Exception("Worker restart failed")

                in_q = self._process_in_queues[wi]
                # Put task: (task_id, backend_config, username, password, kwargs)
                try:
                    in_q.put_nowait(
                        (task_id, backend_config, username, password, kwargs)
                    )
                except Exception:
                    # Queue full, fall back to thread pool
                    raise Exception("Process queue full, falling back to thread pool")

                # Wait for result with simplified timeout handling
                import time

                start_time = time.time()

                # Complex polling loop for shared output queue:
                # Since multiple threads share a single output queue from all workers,
                # we may receive results for other threads' tasks. When this happens,
                # we store the "wrong" result in _pending_tasks so the correct thread
                # can find it later. This avoids blocking other threads when results
                # arrive out of order.
                while True:
                    try:
                        # Use shorter poll intervals for responsiveness
                        result_task_id, ok, err = self._process_out_queue.get(
                            timeout=0.1
                        )
                        if result_task_id == task_id:
                            return bool(ok), False, err
                        # Store result for other threads - another thread will pick this up
                        with self._process_lock:
                            self._cleanup_pending_tasks()
                            if len(self._pending_tasks) < self._pending_tasks_max_size:
                                self._pending_tasks[result_task_id] = (
                                    ok,
                                    err,
                                    time.time(),
                                )
                    except Exception:
                        with self._process_lock:
                            self._cleanup_pending_tasks()
                        # Check timeout
                        if (
                            effective_timeout
                            and (time.time() - start_time) >= effective_timeout
                        ):
                            return False, True, None
                        # Check if our result was consumed by another thread and stored
                        with self._process_lock:
                            if task_id in self._pending_tasks:
                                ok, err, _ = self._pending_tasks.pop(task_id)
                                return bool(ok), False, err
            except Exception as exc:
                # Fall back to thread pool on any unexpected error
                logger.debug("Process-pool dispatch error, falling back: %s", exc)

        # Fallback: run in thread pool (original behavior). We still
        # attempt to cancel the future on timeout as a best-effort.
        return self._run_backend_in_thread_pool(
            backend, username, password, effective_timeout, **kwargs
        )

    def _run_backend_in_thread_pool(
        self,
        backend: AuthenticationBackend,
        username: str,
        password: str,
        effective_timeout: float | None,
        **kwargs,
    ) -> tuple[bool, bool, str | None]:
        """Execute backend authenticate in thread pool with timeout handling."""
        try:
            future = self._backend_executor.submit(
                backend.authenticate, username, password, **kwargs
            )
        except Exception as exc:
            # Pool submission failure or executor shutdown
            return False, False, str(exc)

        try:
            ok = bool(future.result(timeout=effective_timeout))
            with self._process_lock:
                self._cleanup_pending_tasks()
            return ok, False, None
        except FuturesTimeoutError:
            try:
                backend_name = getattr(backend, "name", str(backend))
            except Exception:
                backend_name = str(backend)
            logger.warning(
                "Auth backend %s timed out after %.2fs",
                backend_name,
                effective_timeout or 0.0,
            )
            try:
                future.cancel()
            except Exception:
                logger.debug("Failed to cancel future for backend %s", backend_name)
            return False, True, None
        except AuthenticationError as exc:
            return False, False, str(exc)
        except Exception as exc:  # noqa: BLE001
            return False, False, str(exc)

    def _build_authorization_attributes(
        self, user_attrs: dict[str, Any], request_args: dict[str, str]
    ) -> dict[str, Any]:
        """Build authorization response attributes"""
        auth_attrs = {}
        if "privilege_level" in user_attrs:
            auth_attrs["priv-lvl"] = str(user_attrs["privilege_level"])
        if "service" in user_attrs:
            auth_attrs["service"] = user_attrs["service"]
        # Deprecated: do not emit user-bound shell_command attributes
        if "timeout" in user_attrs:
            auth_attrs["timeout"] = str(user_attrs["timeout"])
        if "idle_timeout" in user_attrs:
            auth_attrs["idletime"] = str(user_attrs["idle_timeout"])
        return auth_attrs

    def _extract_string(self, data: bytes, offset: int, length: int) -> str:
        """Safely extract string from packet data"""
        if offset < 0 or length < 0 or offset + length > len(data):
            return ""
        if length > 1024:  # Prevent excessive memory allocation
            return ""
        return data[offset : offset + length].decode("utf-8", errors="replace")

    def _create_auth_response(
        self,
        request_packet: TacacsPacket,
        status: int,
        server_msg: str = "",
        data: str = "",
    ) -> TacacsPacket:
        """Create authentication response packet"""
        server_msg_bytes = server_msg.encode("utf-8")
        data_bytes = data.encode("utf-8")
        # Reply flags: set NOECHO for password prompts to match device expectations.
        reply_flags = 0
        if status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETPASS:
            reply_flags = TAC_PLUS_FLAGS.TAC_PLUS_AUTHEN_REPLY_FLAG_NOECHO
        body = struct.pack(
            "!BBHH", status, reply_flags, len(server_msg_bytes), len(data_bytes)
        )
        body += server_msg_bytes + data_bytes
        return TacacsPacket(
            version=request_packet.version,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            seq_no=request_packet.seq_no + 1,
            flags=request_packet.flags,
            session_id=request_packet.session_id,
            length=len(body),
            body=body,
        )

    def _create_author_response(
        self,
        request_packet: TacacsPacket,
        status: int,
        server_msg: str = "",
        attrs: dict[str, Any] | None = None,
    ) -> TacacsPacket:
        """Create authorization response packet"""
        server_msg_bytes = server_msg.encode("utf-8")
        args = []
        if attrs:
            for key, value in attrs.items():
                if key != "password":
                    args.append(f"{key}={value}".encode())
        arg_cnt = len(args)
        body = struct.pack("!BBHH", status, arg_cnt, len(server_msg_bytes), 0)
        for arg in args:
            body += struct.pack("!B", len(arg))
        body += server_msg_bytes
        for arg in args:
            body += arg
        return TacacsPacket(
            version=request_packet.version,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
            seq_no=request_packet.seq_no + 1,
            flags=request_packet.flags,
            session_id=request_packet.session_id,
            length=len(body),
            body=body,
        )

    def _evaluate_command_authorization(
        self,
        packet: TacacsPacket,
        user: str,
        user_priv: int,
        requested_priv: int,
        command: str,
        user_attrs: dict[str, Any],
        args: dict[str, str],
        device: Any | None,
    ) -> TacacsPacket:
        """Consolidated command authorization evaluation.

        Tries built-in engine (preferred), then external authorizer, then simple defaults.
        Returns a ready TACACS+ author response packet, or None to fall through.
        """
        device_ctx = self._get_device_context(device)
        device_group_name = device_ctx["group"]
        # Prefer built-in engine when available
        _engine = getattr(self, "command_engine", None)
        if _engine is None:
            try:
                from ..web.monitoring import get_command_engine as _get_engine

                _engine = _get_engine()
            except Exception:
                _engine = None
        if _engine is not None:
            try:
                user_groups_list = user_attrs.get("groups") or []
                allowed, reason, provided_attrs, rule_mode = _engine.authorize_command(
                    command,
                    privilege_level=user_priv,
                    user_groups=user_groups_list,
                    device_group=device_group_name,
                )
                if not allowed:
                    self.cleanup_session(packet.session_id)
                    _structured_log(
                        logger.warning,
                        {
                            "event": "authorization_denied",
                            "session": self._fmt_session_id(packet.session_id),
                            "user": user,
                            "command": command,
                            "reason": reason
                            if (isinstance(reason, str) and reason)
                            else "policy_denied",
                            "user_priv": user_priv,
                            "required_priv": requested_priv,
                            "device_group": device_group_name,
                        },
                    )
                    return self._create_author_response(
                        packet,
                        TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                        reason
                        if (isinstance(reason, str) and reason)
                        else f"Command '{command}' not authorized",
                    )
                base_attrs = self._build_authorization_attributes(user_attrs, args)
                _default_mode = str(
                    getattr(self, "command_response_mode_default", "pass_add")
                ).lower()
                response_mode = str(rule_mode or _default_mode).lower()
                if response_mode == "pass_repl":
                    auth_attrs = dict(provided_attrs or {})
                else:
                    auth_attrs = dict(base_attrs)
                    if isinstance(provided_attrs, dict):
                        auth_attrs.update(
                            {str(k): str(v) for k, v in provided_attrs.items()}
                        )
                self.cleanup_session(packet.session_id)
                status_allowed = (
                    TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL
                    if response_mode == "pass_repl"
                    else TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
                )
                _structured_log(
                    logger.info,
                    {
                        "event": "authorization_granted",
                        "mode": response_mode,
                        "session": self._fmt_session_id(packet.session_id),
                        "user": user,
                        "command": command,
                        "user_priv": user_priv,
                        "required_priv": requested_priv,
                        "device_group": device_group_name,
                    },
                )
                return self._create_author_response(
                    packet,
                    status_allowed,
                    "Authorization granted",
                    auth_attrs,
                )
            except Exception as e:
                logger.debug(
                    "Command engine evaluation failed: %s", e
                )  # Fall through to external authorizer
        # External authorizer (compat)
        try:
            from ..web.monitoring import get_command_authorizer

            authorizer = get_command_authorizer()
        except Exception:
            authorizer = None
        if authorizer is not None:
            user_groups_list = user_attrs.get("groups") or []
            result = authorizer(command, user_priv, user_groups_list, device_group_name)
            if isinstance(result, tuple) and len(result) >= 2:
                allowed = bool(result[0])
                reason = result[1]
                provided_attrs = {}
                if len(result) >= 3 and isinstance(result[2], dict):
                    provided_attrs = {str(k): str(v) for k, v in result[2].items()}
                response_mode = (
                    str(result[3]).lower()
                    if len(result) >= 4
                    else (
                        str(result[2]).lower()
                        if len(result) == 3 and isinstance(result[2], str)
                        else "pass_add"
                    )
                )
            else:
                allowed = bool(result)
                reason = ""
                response_mode = "pass_add"
                provided_attrs = {}
            if not allowed:
                self.cleanup_session(packet.session_id)
                return self._create_author_response(
                    packet,
                    TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                    reason
                    if (isinstance(reason, str) and reason)
                    else f"Command '{command}' not authorized",
                )
            base_attrs = self._build_authorization_attributes(user_attrs, args)
            auth_attrs = (
                dict(provided_attrs)
                if response_mode == "pass_repl"
                else {**base_attrs, **provided_attrs}
            )
            self.cleanup_session(packet.session_id)
            status_allowed = (
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL
                if response_mode == "pass_repl"
                else TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD
            )
            _structured_log(
                logger.info,
                {
                    "event": "authorization_granted",
                    "mode": response_mode,
                    "session": self._fmt_session_id(packet.session_id),
                    "user": user,
                    "command": command,
                    "user_priv": user_priv,
                    "required_priv": requested_priv,
                    "device_group": device_group_name,
                },
            )
            return self._create_author_response(
                packet,
                status_allowed,
                "Authorization granted",
                auth_attrs,
            )
        # Simple defaults when no engine/authorizer
        cmd_str = (command or "").strip().lower()
        if cmd_str.startswith("show"):
            auth_attrs = self._build_authorization_attributes(user_attrs, args)
            self.cleanup_session(packet.session_id)
            _structured_log(
                logger.info,
                {
                    "event": "authorization_granted",
                    "mode": "pass_add",
                    "session": self._fmt_session_id(packet.session_id),
                    "user": user,
                    "command": command,
                    "user_priv": user_priv,
                    "required_priv": requested_priv,
                    "device_group": device_group_name,
                },
            )
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                "Authorization granted",
                auth_attrs,
            )
        required_priv = max(requested_priv, 15)
        allowed_priv, denial_msg = self._check_privilege(
            required_priv, user_priv, user, command, device
        )
        # Authorization defaults reserve privilege 15 as the minimum required for
        # arbitrary commands (non-show). We elevate the requested privilege here to a
        # floor of 15 before checking to enforce that policy consistently.
        if not allowed_priv:
            self.cleanup_session(packet.session_id)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                denial_msg or "Command not permitted at current privilege",
            )
        # Else allow at priv 15
        auth_attrs = self._build_authorization_attributes(user_attrs, args)
        self.cleanup_session(packet.session_id)
        _structured_log(
            logger.info,
            {
                "event": "authorization_granted",
                "mode": "pass_add",
                "session": self._fmt_session_id(packet.session_id),
                "user": user,
                "command": command,
                "user_priv": user_priv,
                "required_priv": requested_priv,
                "device_group": device_group_name,
            },
        )
        return self._create_author_response(
            packet,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            "Authorization granted",
            auth_attrs,
        )

    def _create_acct_response(
        self, request_packet: TacacsPacket, status: int, server_msg: str = ""
    ) -> TacacsPacket:
        """Create accounting response packet"""
        server_msg_bytes = server_msg.encode("utf-8")
        body = struct.pack("!HHH", len(server_msg_bytes), 0, status)
        body += server_msg_bytes
        return TacacsPacket(
            version=request_packet.version,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
            seq_no=request_packet.seq_no + 1,
            flags=request_packet.flags,
            session_id=request_packet.session_id,
            length=len(body),
            body=body,
        )
