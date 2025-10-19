"""Local SQLite-Based Authentication Backend."""

import os
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from tacacs_server.utils.logger import get_logger

from .base import AuthenticationBackend
from .local_models import LocalUserRecord
from .local_user_service import (
    LocalUserExists,
    LocalUserNotFound,
    LocalUserService,
    LocalUserServiceError,
    LocalUserValidationError,
)

logger = get_logger(__name__)


class LocalAuthBackend(AuthenticationBackend):
    """Local authentication backend backed by :class:`LocalUserService`.

    Supports TTL-based user caching to avoid stale reads and reduce load.
    Cache TTL can be configured via config or `LOCAL_AUTH_CACHE_TTL_SECONDS`.
    """

    def __init__(
        self,
        db_path: str = "data/local_auth.db",
        *,
        service: LocalUserService | None = None,
        cache_ttl_seconds: int | None = None,
    ):
        super().__init__("local")
        self.db_path = db_path
        # Track if a service was explicitly provided so we do not override it
        # with any environment-based alignment logic.
        self._service_explicit = service is not None
        self.user_service = service or LocalUserService(db_path)
        try:
            logger.info("LocalAuthBackend using db_path=%s", self.user_service.db_path)
        except Exception:
            logger.info("LocalAuthBackend initialized")

        # Environment alignment: only when a service wasn't explicitly provided.
        # Prefer TACACS_CONFIG's [auth] local_auth_db when present. Do not
        # implicitly override with TACACS_TEST_WORKDIR to avoid diverging from
        # the configured database (tests already generate isolated configs).
        try:
            if not self._service_explicit:
                import configparser as _cp
                import os as _os
                from pathlib import Path as _Path

                cur_path = _Path(str(self.user_service.db_path)).resolve()
                cfg_path = _os.getenv("TACACS_CONFIG")
                if cfg_path and _Path(cfg_path).exists():
                    cfg = _cp.ConfigParser(interpolation=None)
                    cfg.read(cfg_path)
                    cand = cfg.get("auth", "local_auth_db", fallback=str(cur_path))
                    cand = _os.path.expandvars(cand)
                    cand_path = _Path(cand).resolve()
                    if cand_path != cur_path:
                        logger.info(
                            "LocalAuthBackend aligning db_path to %s from TACACS_CONFIG",
                            cand_path,
                        )
                        self._attach_user_service(LocalUserService(str(cand_path)))
        except Exception:
            # Non-fatal; keep existing user_service
            pass
        # Cache of user records with timestamp for TTL eviction
        self._user_cache: dict[str, tuple[LocalUserRecord, float]] = {}
        # TTL for user cache entries (seconds); prevents stale data
        if cache_ttl_seconds is None:
            try:
                ttl = int(os.getenv("LOCAL_AUTH_CACHE_TTL_SECONDS", "60"))
            except Exception:
                ttl = 60
        else:
            ttl = int(cache_ttl_seconds)
        if ttl < 0:
            ttl = 0
        if ttl > 3600:
            ttl = 3600
        self._cache_ttl_seconds = ttl
        self._cache_lock = threading.RLock()
        self._listener_remove: Callable[[], None] | None = None
        self._attach_user_service(self.user_service)

    def _attach_user_service(self, service: LocalUserService) -> None:
        if self._listener_remove:
            try:
                self._listener_remove()
            except Exception:
                logger.exception("Failed detaching previous user service listener")
            finally:
                self._listener_remove = None
        self.user_service = service
        try:
            self._listener_remove = service.add_change_listener(self._on_user_change)
        except AttributeError:
            self._listener_remove = None
        try:
            dbp = getattr(service, "db_path", None)
            logger.info("LocalAuthBackend attached user service db_path=%s", dbp)
        except Exception:
            pass

    def set_user_service(self, service: LocalUserService) -> None:
        if service is None:
            raise ValueError("service must not be None")
        if service is self.user_service:
            return
        self._attach_user_service(service)
        # Prevent later env-based realignment from overriding explicit service
        self._service_explicit = True
        self.invalidate_user_cache()

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        """Authenticate against local user database."""
        # Re-evaluate DB alignment only if no explicit service was supplied and
        # TACACS_CONFIG points to a different local_auth_db than currently used.
        try:
            if not self._service_explicit:
                import configparser as _cp
                import os as _os
                from pathlib import Path as _Path

                cur_path = _Path(str(self.user_service.db_path)).resolve()
                cfg_path = _os.getenv("TACACS_CONFIG")
                if cfg_path and _Path(cfg_path).exists():
                    cfg = _cp.ConfigParser(interpolation=None)
                    cfg.read(cfg_path)
                    cand = cfg.get("auth", "local_auth_db", fallback=str(cur_path))
                    cand = _os.path.expandvars(cand)
                    cand_path = _Path(cand).resolve()
                    if cand_path != cur_path:
                        try:
                            self._attach_user_service(LocalUserService(str(cand_path)))
                            self.invalidate_user_cache()
                            logger.info(
                                "LocalAuthBackend realigned db_path to %s from TACACS_CONFIG",
                                cand_path,
                            )
                        except Exception:
                            pass
        except Exception:
            pass
        try:
            user = self._get_user(username)
        except LocalUserNotFound:
            # Best-effort: reload store and retry once to catch recent writes
            try:
                self.user_service.reload()
                self.invalidate_user_cache(username)
                user = self._get_user(username)
            except LocalUserNotFound:
                logger.debug("User %s not found in local database", username)
                return False

        if not user.enabled:
            logger.info("User %s is disabled", username)
            return False

        # Trace minimal auth context (no secrets) for diagnostics
        try:
            logger.info(
                "LocalAuthBackend auth attempt user=%s has_hash=%s has_plain=%s",
                username,
                bool(user.password_hash),
                user.password is not None,
            )
        except Exception:
            pass

        if user.password_hash:
            try:
                # Delegate to service which supports bcrypt and legacy migration
                ok = self.user_service.verify_user_password(username, password)
                if ok:
                    return True
                # Fallback: if plaintext is stored (test/minimal env), compare directly
                if user.password is not None:
                    result = user.password == password
                    if not result:
                        logger.debug(
                            "LocalAuthBackend plaintext fallback mismatch for %s",
                            username,
                        )
                    if result:
                        logger.info(
                            "Authentication successful for %s (plaintext fallback)",
                            username,
                        )
                    else:
                        logger.info("Authentication failed for %s", username)
                    return result
                return False
            except Exception:
                logger.exception("Password verification failed for %s", username)
                # Attempt plaintext fallback on error as well
                if user.password is not None:
                    return user.password == password
                return False

        if user.password is None:
            logger.debug("User %s has no password configured", username)
            return False

        result = user.password == password
        if result:
            logger.info("Authentication successful for %s", username)
        else:
            logger.info("Authentication failed for %s", username)
        return result

    def get_user_attributes(self, username: str) -> dict[str, Any]:
        try:
            user = self._get_user(username)
        except LocalUserNotFound:
            return {}
        attrs = user.to_dict()
        attrs.pop("password", None)
        attrs.pop("password_hash", None)
        return attrs

    def change_password(
        self, username: str, old_password: str, new_password: str
    ) -> bool:
        if not self.authenticate(username, old_password):
            return False
        try:
            self.user_service.set_password(username, new_password, store_hash=False)
            logger.info("Password changed for user %s", username)
            return True
        except LocalUserServiceError:
            logger.exception("Failed to change password for %s", username)
            return False

    def add_user(self, username: str, password: str, **attributes) -> bool:
        try:
            self.user_service.create_user(
                username,
                password=password,
                privilege_level=attributes.get("privilege_level", 1),
                service=attributes.get("service", "exec"),
                groups=attributes.get("groups", ["users"]),
                enabled=attributes.get("enabled", True),
                description=attributes.get("description"),
            )
            logger.info("User %s added successfully", username)
            return True
        except (LocalUserExists, LocalUserValidationError) as exc:
            logger.error("Failed to add user %s: %s", username, exc)
            return False

    def remove_user(self, username: str) -> bool:
        try:
            self.user_service.delete_user(username)
            logger.info("User %s removed", username)
            self.invalidate_user_cache(username)
            return True
        except LocalUserNotFound:
            return False

    def reload_users(self) -> bool:
        try:
            self.user_service.reload()
            self.invalidate_user_cache()
            logger.info("Local users reloaded successfully")
            return True
        except Exception as exc:
            logger.error("Failed to reload users: %s", exc)
            return False

    def invalidate_user_cache(self, username: str | None = None) -> None:
        with self._cache_lock:
            if username is None:
                self._user_cache.clear()
            else:
                self._user_cache.pop(username, None)

    def _on_user_change(self, _event: str, username: str) -> None:
        self.invalidate_user_cache(username)

    def _get_user(self, username: str) -> LocalUserRecord:
        now = time.monotonic()
        with self._cache_lock:
            entry = self._user_cache.get(username)
            if entry is not None:
                record, ts = entry
                if (
                    self._cache_ttl_seconds == 0
                    or (now - ts) <= self._cache_ttl_seconds
                ):
                    return self._clone_record(record)
                # Expired; remove and fall through to reload
                self._user_cache.pop(username, None)
        record = self.user_service.get_user(username)
        with self._cache_lock:
            self._user_cache[username] = (record, now)
        return self._clone_record(record)

    @staticmethod
    def _clone_record(record: LocalUserRecord) -> LocalUserRecord:
        return replace(
            record,
            groups=list(record.groups),
        )

    # Password hashing and verification are handled by LocalUserService
    # (bcrypt by default, with legacy SHA-256 migration). Keep no local
    # hashing logic here to avoid weak fallbacks.

    def is_available(self) -> bool:
        return True

    def get_stats(self) -> dict[str, Any]:
        users = self.user_service.list_users()
        enabled_users = sum(1 for user in users if user.enabled)
        return {
            "total_users": len(users),
            "enabled_users": enabled_users,
        }
