"""
LDAP Authentication Backend
"""

import threading
from queue import Empty, Queue
from typing import Any

from tacacs_server.utils.exceptions import ValidationError
from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.metrics import ldap_pool_borrows, ldap_pool_reconnects
from tacacs_server.utils.validation import InputValidator

from .base import AuthenticationBackend

logger = get_logger(__name__)

try:
    import ldap3

    LDAP_AVAILABLE = True
except ImportError:
    logger.warning("ldap3 module not available. Install with: pip install ldap3")
    LDAP_AVAILABLE = False


class LDAPAuthBackend(AuthenticationBackend):
    """LDAP authentication backend"""

    def __init__(
        self,
        ldap_server: str | dict[str, Any],
        base_dn: str | None = None,
        user_attribute: str = "uid",
        bind_dn: str | None = None,
        bind_password: str | None = None,
        use_tls: bool = False,
        timeout: int = 10,
    ):
        super().__init__("ldap")
        # Support both legacy positional params and a dict config
        if isinstance(ldap_server, dict):
            cfg = ldap_server
            self.ldap_server = cfg.get("server") or cfg.get("ldap_server")
            self.base_dn = cfg.get("base_dn") or ""
            self.user_attribute = cfg.get("user_attribute", user_attribute)
            self.bind_dn = cfg.get("bind_dn") or None
            self.bind_password = cfg.get("bind_password") or None
            self.use_tls = bool(cfg.get("use_tls", use_tls))
            # timeouts
            self.timeout = int(cfg.get("timeout", timeout))
            # optional pool size
            try:
                self._pool_size = int(cfg.get("pool_size", 5))
            except Exception:
                self._pool_size = 5
        else:
            # Legacy initialization
            self.ldap_server = ldap_server
            self.base_dn = base_dn or ""
            self.user_attribute = user_attribute
            self.bind_dn = bind_dn
            self.bind_password = bind_password
            self.use_tls = use_tls
            self.timeout = timeout
            self._pool_size = 5

        # Simple connection pool settings
        self._connect_timeout = max(1, int(self.timeout))
        self._pool: Queue[ldap3.Connection] | None = (
            None if not LDAP_AVAILABLE else Queue(maxsize=self._pool_size)
        )
        self._pool_lock = threading.Lock()

        # No static group->privilege mapping in backend; privilege derived by policy engine

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        """Authenticate against LDAP server"""
        if not LDAP_AVAILABLE:
            logger.error("LDAP authentication unavailable - ldap3 module not installed")
            return False

        try:
            # Validate inputs to prevent LDAP injection
            username = InputValidator.validate_username(username)
            if len(password) > 128:
                raise ValidationError("Password too long")

            # Ensure pool initialized
            conn = self._acquire_connection()

            # Build user DN
            if self.bind_dn and self.bind_password:
                # Use service account to search for user
                user_dn = self._find_user_dn(username)
                if not user_dn:
                    logger.debug(f"User {username} not found in LDAP directory")
                    self._release_connection(conn)
                    return False
            else:
                # Direct bind - construct DN from username (escape for safety)
                escaped_username = ldap3.utils.conv.escape_filter_chars(username)
                user_dn = f"{self.user_attribute}={escaped_username},{self.base_dn}"

            # Attempt to bind with user credentials
            try:
                if self.bind_dn and self.bind_password:
                    # Use pooled connection when service account is configured
                    conn.user = user_dn
                    conn.password = password
                    ok = conn.bind()
                    self._release_connection(conn)
                else:
                    # For direct user bind use a fresh connection per attempt
                    server = ldap3.Server(self.ldap_server, use_ssl=self.use_tls)
                    with ldap3.Connection(server, user_dn, password) as tmp:
                        ok = tmp.bind()
                    self._release_connection(conn)
            except Exception:
                ok = False
            if ok:
                logger.info(f"LDAP authentication successful for {username}")
                return True
            else:
                logger.info(f"LDAP authentication failed for {username}")
                return False

        except ldap3.core.exceptions.LDAPException as e:
            logger.error(f"LDAP authentication error for {username}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected LDAP error for {username}: {e}")
            return False

    def get_user_attributes(self, username: str) -> dict[str, Any]:
        """Get user attributes from LDAP"""
        if not LDAP_AVAILABLE:
            return {}

        try:
            user_info = self._get_ldap_user_info(username)
            if not user_info:
                return {}

            # Extract groups
            groups = self._extract_groups(user_info)

            return {
                "service": "exec",
                "groups": groups,
                "full_name": user_info.get("displayName", username),
                "email": user_info.get("mail", ""),
                "department": user_info.get("department", ""),
                "title": user_info.get("title", ""),
                "enabled": True,
            }

        except Exception as e:
            logger.error(f"Error getting LDAP attributes for {username}: {e}")
            return {}

    def _find_user_dn(self, username: str) -> str | None:
        """Find user DN using service account"""
        if not LDAP_AVAILABLE:
            return None

        try:
            server = ldap3.Server(self.ldap_server, use_ssl=self.use_tls)

            with ldap3.Connection(server, self.bind_dn, self.bind_password) as conn:
                if not conn.bind():
                    logger.error("Failed to bind with service account")
                    return None

                # Escape username for LDAP filter to prevent injection
                escaped_username = ldap3.utils.conv.escape_filter_chars(username)
                search_filter = f"({self.user_attribute}={escaped_username})"
                conn.search(
                    search_base=self.base_dn,
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=["dn"],
                )

                if conn.entries:
                    return str(conn.entries[0].entry_dn)

        except Exception as e:
            logger.error(f"Error finding user DN for {username}: {e}")

        return None

    def _get_ldap_user_info(self, username: str) -> dict[str, Any] | None:
        """Get detailed user information from LDAP"""
        if not LDAP_AVAILABLE:
            return None

        try:
            server = ldap3.Server(self.ldap_server, use_ssl=self.use_tls)

            # Use service account if available, otherwise anonymous bind
            if self.bind_dn and self.bind_password:
                connection = ldap3.Connection(server, self.bind_dn, self.bind_password)
            else:
                connection = ldap3.Connection(server)

            with connection as conn:
                if not conn.bind():
                    logger.error("Failed to bind to LDAP server")
                    return None

                # Search for user (escape username to prevent injection)
                escaped_username = ldap3.utils.conv.escape_filter_chars(username)
                search_filter = f"({self.user_attribute}={escaped_username})"
                conn.search(
                    search_base=self.base_dn,
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=["*"],
                )

                if not conn.entries:
                    return None

                entry = conn.entries[0]
                user_info = {}

                # Extract attributes
                for attr in entry.entry_attributes:
                    values = entry[attr].values
                    if len(values) == 1:
                        user_info[attr] = values[0]
                    else:
                        user_info[attr] = values

                return user_info

        except Exception as e:
            logger.error(f"Error getting LDAP user info for {username}: {e}")

        return None

    def _extract_groups(self, user_info: dict[str, Any]) -> list:
        """Extract group memberships from user info"""
        groups = []

        # Common group attributes
        group_attrs = ["memberOf", "groups", "groupMembership"]

        for attr in group_attrs:
            if attr in user_info:
                group_dns = user_info[attr]
                if isinstance(group_dns, str):
                    group_dns = [group_dns]

                for group_dn in group_dns:
                    # Extract CN from DN
                    # (e.g., "CN=administrators,OU=Groups,DC=example,DC=com")
                    if group_dn.upper().startswith("CN="):
                        cn_part = group_dn.split(",")[0]
                        group_name = cn_part[3:].lower()  # Remove "CN=" prefix
                        groups.append(group_name)

        return groups

    # No privilege calculation here; handled by policy engine

    def is_available(self) -> bool:
        """Check if LDAP backend is available"""
        if not LDAP_AVAILABLE:
            return False

        try:
            server = ldap3.Server(self.ldap_server, connect_timeout=5)
            with ldap3.Connection(server) as conn:
                return bool(conn.bind())
        except Exception:
            return False

    # --- Internal pooling helpers ---
    def _build_connection(self) -> ldap3.Connection:
        server = ldap3.Server(
            self.ldap_server,
            use_ssl=self.use_tls,
            connect_timeout=self._connect_timeout,
        )
        return ldap3.Connection(server)

    def _acquire_connection(self) -> ldap3.Connection:
        assert LDAP_AVAILABLE
        with self._pool_lock:
            if self._pool is None:
                self._pool = Queue(maxsize=self._pool_size)
        try:
            conn = self._pool.get_nowait()
            # Ensure connection is alive/boundless
            try:
                if not conn.bound:
                    conn.open()
            except Exception:
                conn = self._build_connection()
                try:
                    ldap_pool_reconnects.inc()
                except Exception:
                    pass
        except Empty:
            conn = self._build_connection()
            try:
                ldap_pool_reconnects.inc()
            except Exception:
                pass
        try:
            ldap_pool_borrows.inc()
        except Exception:
            pass
        return conn

    def _release_connection(self, conn: ldap3.Connection) -> None:
        if not LDAP_AVAILABLE:
            return
        try:
            # Unbind any user credentials; keep TCP session
            try:
                if conn.bound:
                    conn.unbind()
            except Exception:
                pass
            with self._pool_lock:
                if self._pool is not None and not self._pool.full():
                    self._pool.put_nowait(conn)
        except Exception:
            pass

    def test_connection(self) -> dict[str, Any]:
        """Test LDAP connection and return status"""
        result = {
            "available": False,
            "server": self.ldap_server,
            "base_dn": self.base_dn,
            "error": None,
        }

        if not LDAP_AVAILABLE:
            result["error"] = "ldap3 module not available"
            return result

        try:
            server = ldap3.Server(self.ldap_server, connect_timeout=5)

            if self.bind_dn and self.bind_password:
                with ldap3.Connection(server, self.bind_dn, self.bind_password) as conn:
                    if conn.bind():
                        result["available"] = True
                        result["bind_type"] = "service_account"
                    else:
                        result["error"] = "Service account bind failed"
            else:
                with ldap3.Connection(server) as conn:
                    if conn.bind():
                        result["available"] = True
                        result["bind_type"] = "anonymous"
                    else:
                        result["error"] = "Anonymous bind failed"

        except Exception as e:
            result["error"] = str(e)

        return result

    # Removed privilege mapping and command mapping management; use policy engine

    def get_stats(self) -> dict[str, Any]:
        """Get backend statistics"""
        connection_test = self.test_connection()
        return {
            "ldap_server": self.ldap_server,
            "base_dn": self.base_dn,
            "user_attribute": self.user_attribute,
            "use_tls": self.use_tls,
            "available": connection_test["available"],
            "bind_type": connection_test.get("bind_type", "none"),
            "error": connection_test.get("error"),
            "pool_size": getattr(self, "_pool_size", 0),
        }
