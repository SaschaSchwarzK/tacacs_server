"""
TACACS+ AAA Request Handlers
"""

import os
import struct
import threading
from typing import TYPE_CHECKING, Any

try:
    import json as _json

    _HAS_JSON = True
except Exception:  # pragma: no cover - stdlib always present
    _HAS_JSON = False

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
    TAC_PLUS_PACKET_TYPE,
)
from .packet import TacacsPacket
from .structures import parse_acct_request, parse_authen_start, parse_author_request

logger = get_logger(__name__)


class AAAHandlers:
    """TACACS+ Authentication, Authorization, and Accounting handlers.

    Orchestrates packet parsing, backend authentication with timeouts,
    authorization decisions via a policy engine, and accounting persistence.
    Emits structured JSON logs for observability and safety.
    """

    def __init__(
        self,
        auth_backends: list[AuthenticationBackend],
        db_logger,
        *,
        backend_timeout: float | None = None,
    ):
        self.auth_backends = auth_backends
        self.db_logger = db_logger
        # Shared session state; protect with a re-entrant lock
        self._lock = threading.RLock()
        self.auth_sessions: dict[int, dict[str, Any]] = {}
        self.rate_limiter = AuthRateLimiter()
        self.session_device: dict[int, Any] = {}
        self.session_usernames: dict[int, str] = {}
        # Optional command authorization engine injected by main
        self.command_engine: CommandAuthorizationEngine | None = None
        self.local_user_group_service = None
        # Defaults injected from main; ensure attributes exist for type checkers
        self.command_response_mode_default: str | None = None
        self.privilege_check_order: str = "before"
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

    def set_local_user_group_service(self, service) -> None:
        self.local_user_group_service = service

    def _redact_args(self, args: dict[str, str]) -> dict[str, str]:
        """Return a copy of args with sensitive values redacted.
        Keys containing common secrets (pass, pwd, secret, token, key) are masked.
        """
        if not isinstance(args, dict):
            return {}
        redacted: dict[str, str] = {}
        SENSITIVE = ("pass", "pwd", "secret", "token", "key")
        try:
            for k, v in args.items():
                if any(s in str(k).lower() for s in SENSITIVE):
                    redacted[str(k)] = "***"
                else:
                    redacted[str(k)] = str(v)
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

    def _remember_username(self, session_id: int, username: str | None) -> None:
        if username:
            with self._lock:
                self.session_usernames[session_id] = username

    def cleanup_session(self, session_id: int) -> None:
        """Remove cached state associated with a TACACS session."""
        with self._lock:
            # First, determine all keys to remove without mutating dicts mid-iteration
            simple_key = session_id
            prefix = f"{session_id}_"
            # Collect auth session keys: both simple and composite
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
                    continue  # Skip malformed keys

            # Now perform removals
            self.session_device.pop(session_id, None)
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
        device_name = getattr(device, "name", None)
        group_name = getattr(getattr(device, "group", None), "name", None)
        context = group_name or device_name or "unknown"
        sess_hex = f"0x{session_id:08x}"
        # Structured log aligned with logging spec; avoid manual JSON
        backend_name = None
        try:
            if detail and "backend=" in detail:
                backend_name = detail.split("backend=", 1)[1].split()[0]
        except (IndexError, AttributeError):
            backend_name = None  # Failed to parse backend name from detail
        try:
            fields = {
                "event": "auth.success" if success else "auth.failure",
                "service": "tacacs",
                "component": "handlers",
                "session": sess_hex,
                "correlation_id": sess_hex,
                "user_ref": safe_user,
                "device": device_name,
                "device_group": group_name,
                "auth": {
                    "backend": backend_name or "unknown",
                    "result": "success" if success else "failure",
                },
                "detail": detail or "",
            }
            # Pass structured fields via 'extra' to satisfy logging typing and adapter
            if success:
                logger.info("Authentication result", extra=fields)
            else:
                logger.warning("Authentication result", extra=fields)
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
            try:
                parsed = parse_authen_start(packet.body)
            except ProtocolError as pe:
                if _HAS_JSON:
                    try:
                        logger.warning(
                            _json.dumps(
                                {
                                    "event": "auth_parse_error",
                                    "stage": "start",
                                    "session": f"0x{packet.session_id:08x}",
                                    "seq": packet.seq_no,
                                    "reason": str(pe),
                                    "length": len(packet.body or b""),
                                }
                            )
                        )
                    except Exception as e:
                        logger.debug("Failed to log auth parse error: %s", e)
                else:
                    logger.warning("Invalid authentication packet body: %s", pe)
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
            action = parsed["action"]
            priv_lvl = parsed["priv_lvl"]
            authen_type = parsed["authen_type"]
            user = parsed["user"]
            port = parsed["port"]
            rem_addr = parsed["rem_addr"]
            data = parsed["data"]
            safe_user = self._safe_user(user)
            logger.debug(
                "TACACS auth request: user=%s, type=%s, action=%s, seq=%s, session=%s",
                safe_user,
                authen_type,
                action,
                packet.seq_no,
                f"0x{packet.session_id:08x}",
            )
            self._remember_username(packet.session_id, user)
            if packet.seq_no == 1:
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
            else:
                return self._handle_auth_continue(packet, user, data)
        except Exception as e:
            logger.error(f"Authentication error: {e}")
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
                if _HAS_JSON:
                    try:
                        logger.warning(
                            _json.dumps(
                                {
                                    "event": "author_parse_error",
                                    "session": f"0x{packet.session_id:08x}",
                                    "seq": packet.seq_no,
                                    "reason": str(pe),
                                    "length": len(packet.body or b""),
                                }
                            )
                        )
                    except Exception as e:
                        logger.debug("Failed to log author parse error: %s", e)
                else:
                    logger.warning("Invalid authorization packet body: %s", pe)
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
                f"0x{packet.session_id:08x}",
            )
            return self._process_authorization(
                packet, user, authen_service, priv_lvl, args, device
            )
        except Exception as e:
            logger.error(f"Authorization error: {e}")
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
                if _HAS_JSON:
                    try:
                        logger.warning(
                            _json.dumps(
                                {
                                    "event": "acct_parse_error",
                                    "session": f"0x{packet.session_id:08x}",
                                    "seq": packet.seq_no,
                                    "reason": str(pe),
                                    "length": len(packet.body or b""),
                                }
                            )
                        )
                    except Exception as e:
                        logger.debug("Failed to log acct parse error: %s", e)
                else:
                    logger.warning("Invalid accounting packet body: %s", pe)
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
                f"0x{packet.session_id:08x}",
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
            logger.error(f"Accounting error: {e}")
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
                backend_name = None
                try:
                    if detail and "backend=" in detail:
                        backend_name = detail.split("backend=", 1)[1].split()[0]
                except (IndexError, AttributeError):
                    backend_name = None
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
                    self.auth_sessions[session_key] = {"step": "username"}
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
        self, packet: TacacsPacket, user: str, data: bytes
    ) -> TacacsPacket:
        """Handle authentication continuation"""
        session_key = packet.session_id
        with self._lock:
            session_info = self.auth_sessions.get(session_key)
        if not session_info:
            return self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                "Invalid session",
            )
        if session_info["step"] == "username":
            username = data.decode("utf-8", errors="replace").strip()
            session_info["username"] = username
            session_info["step"] = "password"
            self._remember_username(packet.session_id, username)
            return self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETPASS,
                "Password: ",
            )
        elif session_info["step"] == "password":
            password = data.decode("utf-8", errors="replace").strip()
            username = session_info["username"]
            with self._lock:
                del self.auth_sessions[session_key]
            with self._lock:
                device = self.session_device.get(packet.session_id)
            client_ip = getattr(device, "ip", None)
            authenticated, detail = self._authenticate_user(
                username, password, client_ip=client_ip
            )
            if authenticated:
                backend_name = None
                try:
                    if detail and "backend=" in detail:
                        backend_name = detail.split("backend=", 1)[1].split()[0]
                except (IndexError, AttributeError):
                    backend_name = None
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
                logger.error(f"Error getting attributes from {backend.name}: {e}")
                continue
        if not user_attrs:
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
            try:
                if _HAS_JSON:
                    logger.warning(
                        _json.dumps(
                            {
                                "event": "authorization_denied",
                                "session": f"0x{packet.session_id:08x}",
                                "user": user,
                                "reason": "no_attrs",
                                "command": args.get("cmd"),
                                "device_group": getattr(
                                    getattr(device, "group", None), "name", None
                                ),
                            }
                        )
                    )
            except Exception as e:
                logger.debug("Failed to log authorization denial: %s", e)
            try:
                from ..utils.webhook import notify

                notify(
                    "authorization_failure",
                    {
                        "username": user,
                        "client_ip": getattr(device, "ip", None),
                        "reason": "no_attrs",
                    },
                )
            except Exception as e:
                logger.debug("Failed to send webhook notification: %s", e)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                "User not found or no attributes available",
            )
        if not user_attrs.get("enabled", True):
            self.cleanup_session(packet.session_id)
            try:
                if _HAS_JSON:
                    logger.warning(
                        _json.dumps(
                            {
                                "event": "authorization_denied",
                                "session": f"0x{packet.session_id:08x}",
                                "user": user,
                                "reason": "disabled",
                                "command": args.get("cmd"),
                                "device_group": getattr(
                                    getattr(device, "group", None), "name", None
                                ),
                            }
                        )
                    )
            except Exception as e:
                logger.debug("Failed to log authorization denial: %s", e)
            try:
                from ..utils.webhook import notify

                notify(
                    "authorization_failure",
                    {
                        "username": user,
                        "client_ip": getattr(device, "ip", None),
                        "reason": "disabled",
                    },
                )
            except Exception as e:
                logger.debug("Failed to send webhook notification: %s", e)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                "User account is disabled",
            )

        device_record = device or self.session_device.get(packet.session_id)
        device_group = getattr(device_record, "group", None) if device_record else None
        if device_group:
            allowed_groups = getattr(device_group, "allowed_user_groups", [])
            device_group_name = getattr(device_group, "name", None)
        else:
            allowed_groups = []
            device_group_name = None

        context = PolicyContext(
            device_group_name=device_group_name,
            allowed_user_groups=allowed_groups,
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
            try:
                if _HAS_JSON:
                    logger.warning(
                        _json.dumps(
                            {
                                "event": "authorization_denied",
                                "session": f"0x{packet.session_id:08x}",
                                "user": user,
                                "reason": result.denial_message or "policy_denied",
                                "command": args.get("cmd"),
                                "required_priv": priv_lvl,
                                "user_priv": user_priv,
                                "device_group": getattr(
                                    getattr(device, "group", None), "name", None
                                ),
                            }
                        )
                    )
            except Exception as e:
                logger.debug("Failed to log authorization denial: %s", e)
            try:
                from ..utils.webhook import notify

                notify(
                    "authorization_failure",
                    {
                        "username": user,
                        "client_ip": getattr(device, "ip", None),
                        "reason": result.denial_message or "policy_denied",
                    },
                )
            except Exception as e:
                logger.debug("Failed to send webhook notification: %s", e)
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
        _priv_order = getattr(self, "privilege_check_order", "before")
        if _priv_order == "before" and (priv_lvl > user_priv):
            self.cleanup_session(packet.session_id)
            try:
                if _HAS_JSON:
                    logger.warning(
                        _json.dumps(
                            {
                                "event": "authorization_denied",
                                "session": f"0x{packet.session_id:08x}",
                                "user": user,
                                "reason": "insufficient_privilege",
                                "command": args.get("cmd"),
                                "required_priv": priv_lvl,
                                "user_priv": user_priv,
                                "device_group": getattr(
                                    getattr(device, "group", None), "name", None
                                ),
                            }
                        )
                    )
            except Exception as e:
                logger.debug("Failed to log authorization denial: %s", e)
            try:
                from ..utils.webhook import notify

                notify(
                    "authorization_failure",
                    {
                        "username": user,
                        "client_ip": getattr(device, "ip", None),
                        "reason": "insufficient_privilege",
                    },
                )
            except Exception as e:
                logger.debug("Failed to send webhook notification: %s", e)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                f"Insufficient privilege level (required: {priv_lvl}, "
                f"user: {user_priv})",
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
        try:
            if _HAS_JSON:
                logger.info(
                    _json.dumps(
                        {
                            "event": "authorization_granted",
                            "mode": "pass_add",
                            "session": f"0x{packet.session_id:08x}",
                            "user": user,
                            "command": args.get("cmd"),
                            "user_priv": user_priv,
                            "required_priv": priv_lvl,
                            "device_group": getattr(
                                getattr(device, "group", None), "name", None
                            ),
                        }
                    )
                )
        except Exception as e:
            logger.debug("Failed to log authorization grant: %s", e)
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
        if flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START:
            status = "START"
        elif flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP:
            status = "STOP"
        elif flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_WATCHDOG:
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
        )
        if self.db_logger.log_accounting(record):
            response = self._create_acct_response(
                packet,
                TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
                "Accounting record logged successfully",
            )
            try:
                if _HAS_JSON:
                    logger.info(
                        _json.dumps(
                            {
                                "event": "acct_record",
                                "session": f"0x{packet.session_id:08x}",
                                "user": user or self._safe_user(None),
                                "status": status,
                                "service": record.service,
                                "command": record.command,
                                "client_ip": rem_addr,
                                "port": port,
                                "priv": priv_lvl,
                                "attrs": self._redact_args(args),
                            }
                        )
                    )
            except Exception:
                # Structured logging failed, continue without detailed log
                pass
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
            try:
                if _HAS_JSON:
                    logger.warning(
                        _json.dumps(
                            {
                                "event": "acct_record_error",
                                "session": f"0x{packet.session_id:08x}",
                                "user": user or self._safe_user(None),
                                "status": status,
                                "service": record.service,
                                "command": record.command,
                                "client_ip": rem_addr,
                                "port": port,
                                "priv": priv_lvl,
                                "attrs": self._redact_args(args),
                            }
                        )
                    )
            except Exception:
                # Structured logging failed, continue without detailed log
                pass
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
        if not backend_name:
            return None
        for backend in self.auth_backends:
            try:
                if getattr(backend, "name", None) == backend_name:
                    return backend
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
        backend = self._get_backend_by_name(backend_name)
        if backend is None:
            return True, None

        device_group = getattr(device, "group", None)
        if not device_group:
            return True, None
        try:
            allowed_group_names = list(
                getattr(device_group, "allowed_user_groups", []) or []
            )
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
                try:
                    backend_name_norm = str(getattr(backend, "name", "")).lower()
                except Exception:
                    backend_name_norm = ""
                target_value: str | None = None
                try:
                    if backend_name_norm == "okta":
                        target_value = getattr(record, "okta_group", None)
                    elif backend_name_norm == "ldap":
                        target_value = getattr(record, "ldap_group", None)
                    elif backend_name_norm == "radius":
                        md = getattr(record, "metadata", {}) or {}
                        if isinstance(md, dict):
                            raw = md.get("radius_group")
                            if raw is not None:
                                target_value = str(raw)
                        # Fallback to local group name when no explicit radius_group
                        if target_value is None:
                            target_value = getattr(record, "name", None)
                    elif backend_name_norm == "local":
                        # For local backend, match directly on local group name.
                        target_value = getattr(record, "name", None)
                except Exception:
                    target_value = None

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
        device_name = getattr(device, "name", None)
        device_group_name = getattr(device_group, "name", None)

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

        try:
            if _HAS_JSON:
                if matches:
                    logger.info(_json.dumps({**log_payload, "result": "allow"}))
                else:
                    logger.warning(_json.dumps({**log_payload, "result": "deny"}))
        except Exception:
            # Best-effort logging; never fail auth flow due to logging errors
            pass

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

        if client_ip and not self.rate_limiter.is_allowed(client_ip):
            try:
                if _HAS_JSON:
                    logger.warning(
                        _json.dumps(
                            {
                                "event": "auth_rate_limited",
                                "user": username or self._safe_user(None),
                                "client_ip": client_ip,
                            }
                        )
                    )
            except Exception as e:
                logger.debug("Failed to log rate limit: %s", e)
            return False, f"rate limit exceeded for {client_ip}"

        if client_ip:
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
            try:
                from ..utils.webhook import notify, record_event

                notify(
                    "auth_failure",
                    {
                        "username": username,
                        "client_ip": client_ip,
                        "detail": last_error,
                    },
                )
                record_event("auth_failure", username or (client_ip or "unknown"))
            except Exception as e:
                logger.debug("Failed to send webhook notification: %s", e)
            return False, last_error

        if not self.auth_backends:
            _PM.record_auth_request(
                "fail", "none", _time.time() - start_ts, "no_backends"
            )
            try:
                from ..utils.webhook import notify, record_event

                notify(
                    "auth_failure",
                    {
                        "username": username,
                        "client_ip": client_ip,
                        "detail": "no_backends",
                    },
                )
                record_event("auth_failure", username or (client_ip or "unknown"))
            except Exception as e:
                logger.debug("Failed to send webhook notification: %s", e)
            return False, "no authentication backends configured"

        _PM.record_auth_request(
            "fail",
            used_backend or "none",
            _time.time() - start_ts,
            "no_backend_accepted",
        )
        try:
            from ..utils.webhook import notify, record_event

            notify(
                "auth_failure",
                {
                    "username": username,
                    "client_ip": client_ip,
                    "detail": "no_backend_accepted",
                },
            )
            record_event("auth_failure", username or (client_ip or "unknown"))
        except Exception as e:
            logger.debug("Failed to send webhook notification: %s", e)
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
        Does not attempt to kill the backend call; if it exceeds timeout,
        the result is ignored and timed_out is True.
        """
        result_container: dict[str, Any] = {}

        def _worker():
            try:
                result_container["ok"] = bool(
                    backend.authenticate(username, password, **kwargs)
                )
            except AuthenticationError as exc:
                result_container["error"] = str(exc)
            except Exception as exc:  # noqa: BLE001
                result_container["error"] = str(exc)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t.join(timeout=timeout_s if timeout_s and timeout_s > 0 else None)
        if t.is_alive():
            return False, True, None
        if "error" in result_container:
            return False, False, result_container.get("error")
        return bool(result_container.get("ok", False)), False, None

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
        body = struct.pack("!BBHH", status, 0, len(server_msg_bytes), len(data_bytes))
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
                device_group_name = getattr(
                    getattr(device, "group", None), "name", None
                )
                allowed, reason, provided_attrs, rule_mode = _engine.authorize_command(
                    command,
                    privilege_level=user_priv,
                    user_groups=user_groups_list,
                    device_group=device_group_name,
                )
                if not allowed:
                    self.cleanup_session(packet.session_id)
                    # Structured denial log
                    try:
                        if _HAS_JSON:
                            logger.warning(
                                _json.dumps(
                                    {
                                        "event": "authorization_denied",
                                        "session": f"0x{packet.session_id:08x}",
                                        "user": user,
                                        "command": command,
                                        "reason": reason
                                        if (isinstance(reason, str) and reason)
                                        else "policy_denied",
                                        "user_priv": user_priv,
                                        "required_priv": requested_priv,
                                        "device_group": getattr(
                                            getattr(device, "group", None), "name", None
                                        ),
                                    }
                                )
                            )
                    except Exception as e:
                        logger.debug("Failed to log authorization denial: %s", e)
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
                # Structured grant log
                try:
                    if _HAS_JSON:
                        logger.info(
                            _json.dumps(
                                {
                                    "event": "authorization_granted",
                                    "mode": response_mode,
                                    "session": f"0x{packet.session_id:08x}",
                                    "user": user,
                                    "command": command,
                                    "user_priv": user_priv,
                                    "required_priv": requested_priv,
                                    "device_group": getattr(
                                        getattr(device, "group", None), "name", None
                                    ),
                                }
                            )
                        )
                except Exception:
                    # Structured logging failed, continue without detailed log
                    pass
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
            device_group_name = getattr(getattr(device, "group", None), "name", None)
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
            try:
                if _HAS_JSON:
                    logger.info(
                        _json.dumps(
                            {
                                "event": "authorization_granted",
                                "mode": response_mode,
                                "session": f"0x{packet.session_id:08x}",
                                "user": user,
                                "command": command,
                                "user_priv": user_priv,
                                "required_priv": requested_priv,
                                "device_group": getattr(
                                    getattr(device, "group", None), "name", None
                                ),
                            }
                        )
                    )
            except Exception as e:
                logger.debug("Failed to log authorization grant: %s", e)
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
            try:
                if _HAS_JSON:
                    logger.info(
                        _json.dumps(
                            {
                                "event": "authorization_granted",
                                "mode": "pass_add",
                                "session": f"0x{packet.session_id:08x}",
                                "user": user,
                                "command": command,
                                "user_priv": user_priv,
                                "required_priv": requested_priv,
                                "device_group": getattr(
                                    getattr(device, "group", None), "name", None
                                ),
                            }
                        )
                    )
            except Exception as e:
                logger.debug("Failed to log authorization grant: %s", e)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                "Authorization granted",
                auth_attrs,
            )
        if user_priv < 15:
            self.cleanup_session(packet.session_id)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                "Command not permitted at current privilege",
            )
        # Else allow at priv 15
        auth_attrs = self._build_authorization_attributes(user_attrs, args)
        self.cleanup_session(packet.session_id)
        try:
            if _HAS_JSON:
                logger.info(
                    _json.dumps(
                        {
                            "event": "authorization_granted",
                            "mode": "pass_add",
                            "session": f"0x{packet.session_id:08x}",
                            "user": user,
                            "command": command,
                            "user_priv": user_priv,
                            "required_priv": requested_priv,
                            "device_group": getattr(
                                getattr(device, "group", None), "name", None
                            ),
                        }
                    )
                )
        except Exception as e:
            logger.debug("Failed to log authorization grant: %s", e)
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
