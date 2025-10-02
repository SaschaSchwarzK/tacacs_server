"""Local SQLite-Based Authentication Backend."""

import threading
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
    """Local authentication backend backed by :class:`LocalUserService`."""

    def __init__(
        self,
        db_path: str = "data/local_auth.db",
        *,
        service: LocalUserService | None = None,
    ):
        super().__init__("local")
        self.db_path = db_path
        self.user_service = service or LocalUserService(db_path)
        self._user_cache: dict[str, LocalUserRecord] = {}
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

    def set_user_service(self, service: LocalUserService) -> None:
        if service is None:
            raise ValueError("service must not be None")
        if service is self.user_service:
            return
        self._attach_user_service(service)
        self.invalidate_user_cache()

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        """Authenticate against local user database."""
        try:
            user = self._get_user(username)
        except LocalUserNotFound:
            logger.debug("User %s not found in local database", username)
            return False

        if not user.enabled:
            logger.info("User %s is disabled", username)
            return False

        if user.password_hash:
            return self._verify_password_hash(password, user.password_hash)

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
                shell_command=attributes.get("shell_command", ["show"]),
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
        with self._cache_lock:
            cached = self._user_cache.get(username)
        if cached is not None:
            return self._clone_record(cached)
        record = self.user_service.get_user(username)
        with self._cache_lock:
            self._user_cache[username] = record
        return self._clone_record(record)

    @staticmethod
    def _clone_record(record: LocalUserRecord) -> LocalUserRecord:
        return replace(
            record,
            shell_command=list(record.shell_command),
            groups=list(record.groups),
        )

    def _hash_password(self, password: str) -> str:
        import hashlib

        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _verify_password_hash(self, password: str, password_hash: str) -> bool:
        # Check if it's a bcrypt hash (starts with $2b$)
        if password_hash.startswith("$2b$"):
            try:
                import bcrypt

                return bcrypt.checkpw(
                    password.encode("utf-8"), password_hash.encode("utf-8")
                )
            except ImportError:
                logger.error("bcrypt not available for password verification")
                return False
        # Fallback to SHA-256 for legacy hashes
        return self._hash_password(password) == password_hash

    def is_available(self) -> bool:
        return True

    def get_stats(self) -> dict[str, Any]:
        users = self.user_service.list_users()
        enabled_users = sum(1 for user in users if user.enabled)
        return {
            "total_users": len(users),
            "enabled_users": enabled_users,
        }
