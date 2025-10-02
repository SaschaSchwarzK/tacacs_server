"""Service helpers for managing local users stored in SQLite."""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Callable, Iterable
from dataclasses import replace
from pathlib import Path

from tacacs_server.utils.exceptions import ValidationError
from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.password_hash import (
    PasswordHasher,
    verify_password,
)
from tacacs_server.utils.validation import InputValidator

from .local_models import LocalUserRecord
from .local_store import LocalAuthStore

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

logger = get_logger(__name__)


class LocalUserServiceError(Exception):
    """Base exception for local user operations."""


class LocalUserValidationError(LocalUserServiceError):
    """Raised when supplied data is invalid."""


class LocalUserNotFound(LocalUserServiceError):
    """Raised when requesting a user that does not exist."""


class LocalUserExists(LocalUserServiceError):
    """Raised when attempting to create a duplicate user."""


class LocalUserService:
    """CRUD operations with validation for local SQLite-based users."""

    def __init__(
        self,
        db_path: Path | str = "data/local_auth.db",
        *,
        store: LocalAuthStore | None = None,
        seed_file: Path | str | None = None,
    ) -> None:
        self.db_path = self._validate_safe_path(db_path, "data")
        self.store = store or LocalAuthStore(self.db_path)
        self._listeners: list[Callable[[str, str], None]] = []
        self._listeners_lock = threading.RLock()
        if seed_file:
            # Validate seed file path to prevent path traversal
            safe_seed_path = self._validate_safe_path(seed_file, "data")
            self._seed_from_json(safe_seed_path)

    # ------------------------------------------------------------------
    # Change listeners
    # ------------------------------------------------------------------
    def add_change_listener(
        self, callback: Callable[[str, str], None]
    ) -> Callable[[], None]:
        with self._listeners_lock:
            self._listeners.append(callback)

        def _remove() -> None:
            with self._listeners_lock:
                try:
                    self._listeners.remove(callback)
                except ValueError:
                    pass

        return _remove

    def _notify_change(self, event: str, username: str) -> None:
        with self._listeners_lock:
            listeners = list(self._listeners)
        for callback in listeners:
            try:
                callback(event, username)
            except Exception:
                logger.exception(
                    "LocalUserService change listener failed"
                )

    # ------------------------------------------------------------------
    # Basic ops
    # ------------------------------------------------------------------
    def list_users(self) -> list[LocalUserRecord]:
        return [self._clone(record) for record in self.store.list_users()]

    def get_user(self, username: str) -> LocalUserRecord:
        record = self.store.get_user(username)
        if not record:
            raise LocalUserNotFound(f"User '{username}' not found")
        return self._clone(record)

    def create_user(
        self,
        username: str,
        *,
        password: str | None = None,
        password_hash: str | None = None,
        privilege_level: int = 1,
        service: str = "exec",
        shell_command: Iterable[str] | None = None,
        groups: Iterable[str] | None = None,
        enabled: bool = True,
        description: str | None = None,
    ) -> LocalUserRecord:
        username = username.strip()
        self._validate_username(username)

        password, password_hash = self._resolve_password(password, password_hash)
        record = LocalUserRecord(
            username=username,
            privilege_level=self._validate_privilege(privilege_level),
            service=self._validate_service(service),
            shell_command=self._validate_list(shell_command, "shell_command"),
            groups=self._validate_list(groups, "groups"),
            enabled=bool(enabled),
            description=description,
            password=password,
            password_hash=password_hash,
        )
        try:
            stored = self.store.insert_user(record)
        except sqlite3.IntegrityError as exc:
            raise LocalUserExists(f"User '{username}' already exists") from exc
        self._notify_change("created", username)
        return self._clone(stored)

    def update_user(
        self,
        username: str,
        *,
        privilege_level: int | None = None,
        service: str | None = None,
        shell_command: Iterable[str] | None = None,
        groups: Iterable[str] | None = None,
        enabled: bool | None = None,
        description: str | None = None,
    ) -> LocalUserRecord:
        existing = self.store.get_user(username)
        if not existing:
            raise LocalUserNotFound(f"User '{username}' not found")

        updates = {
            "privilege_level": (
                self._validate_privilege(privilege_level) 
                if privilege_level is not None else None
            ),
            "service": (
                self._validate_service(service) 
                if service is not None else None
            ),
            "shell_command": (
                self._validate_list(shell_command, "shell_command") 
                if shell_command is not None else None
            ),
            "groups": (
                self._validate_list(groups, "groups") 
                if groups is not None else None
            ),
            "enabled": (
                bool(enabled) if enabled is not None else None
            ),
            "description": (
                description if description is not None else None
            ),
        }
        stored = self.store.update_user(
            username,
            privilege_level=updates["privilege_level"],
            service=updates["service"],
            shell_command=updates["shell_command"],
            groups=updates["groups"],
            enabled=updates["enabled"],
            description=updates["description"],
        )
        if not stored:
            raise LocalUserNotFound(f"User '{username}' not found")
        self._notify_change("updated", username)
        return self._clone(stored)

    def set_password(
        self,
        username: str,
        password: str,
        *,
        store_hash: bool = True,
    ) -> LocalUserRecord:
        # Use centralized password validation
        try:
            password = InputValidator.validate_password(password, min_length=8)
        except ValidationError as e:
            raise LocalUserValidationError(str(e)) from e

        existing = self.store.get_user(username)
        if not existing:
            raise LocalUserNotFound(f"User '{username}' not found")

        password_hash = PasswordHasher.hash_password(password) if store_hash else None
        stored = self.store.set_user_password(
            username,
            password=None,
            password_hash=password_hash,
        )
        if not stored:
            raise LocalUserNotFound(f"User '{username}' not found")
        self._notify_change("password", username)
        return self._clone(stored)

    def delete_user(self, username: str) -> bool:
        if not self.store.delete_user(username):
            raise LocalUserNotFound(f"User '{username}' not found")
        self._notify_change("deleted", username)
        return True

    def reload(self) -> None:
        self.store.reload()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _seed_from_json(self, seed_path: Path) -> None:
        if not seed_path.exists():
            return
        try:
            if self.store.list_users():
                return
        except Exception:
            logger.exception(
                "Failed to inspect local auth store before seeding"
            )
            return

        try:
            with seed_path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            logger.exception(
                "Failed to load legacy users seed from %s", seed_path
            )
            return

        if not isinstance(payload, dict):
            logger.warning(
                "Legacy users seed %s is not a JSON object", seed_path
            )
            return

        for username, data in payload.items():
            if not isinstance(data, dict):
                logger.warning(
                    "Skipping legacy user %s with invalid payload", username
                )
                continue
            try:
                record = LocalUserRecord.from_dict(username, data)
                try:
                    self.store.insert_user(record)
                except sqlite3.IntegrityError:
                    # Already present, skip
                    continue
            except Exception:
                logger.exception(
                    "Failed to import legacy user %s", username
                )

    @staticmethod
    def _clone(record: LocalUserRecord) -> LocalUserRecord:
        return replace(
            record,
            shell_command=list(record.shell_command),
            groups=list(record.groups),
        )

    @staticmethod
    def _validate_username(username: str) -> None:
        if not username:
            raise LocalUserValidationError("Username is required")
        if not USERNAME_PATTERN.match(username):
            raise LocalUserValidationError("Username contains invalid characters")

    @staticmethod
    def _validate_privilege(level: int) -> int:
        try:
            level = int(level)
        except (TypeError, ValueError) as exc:
            raise LocalUserValidationError(
                "Privilege level must be an integer"
            ) from exc
        if level < 0 or level > 15:
            raise LocalUserValidationError("Privilege level must be between 0 and 15")
        return level

    @staticmethod
    def _validate_service(service: str) -> str:
        if not service:
            raise LocalUserValidationError("Service must be provided")
        return service

    @staticmethod
    def _validate_list(values: Iterable[str] | None, field: str) -> list[str]:
        if values is None:
            if field == "shell_command":
                return ["show"]
            if field == "groups":
                return ["users"]
            return []
        result: list[str] = []
        for value in values:
            if not isinstance(value, str) or not value:
                raise LocalUserValidationError(
                    f"{field} entries must be non-empty strings"
                )
            result.append(value)
        return result

    @staticmethod
    def _resolve_password(
        password: str | None,
        password_hash: str | None,
    ) -> tuple[str | None, str | None]:
        if password_hash and password:
            raise LocalUserValidationError(
                "Provide only password or password_hash, not both"
            )
        if password:
            try:
                password = InputValidator.validate_password(password, min_length=8)
            except ValidationError as e:
                raise LocalUserValidationError(str(e)) from e
            return None, PasswordHasher.hash_password(password)
        if password_hash:
            if len(password_hash) != 64:
                raise LocalUserValidationError(
                    "password_hash must be a SHA-256 hex digest"
                )
            return None, password_hash
        raise LocalUserValidationError(
            "Either password or password_hash must be provided"
        )

    def verify_user_password(self, username: str, password: str) -> bool:
        """Verify user password with automatic migration from legacy hashes."""
        user = self.store.get_user(username)
        if not user or not user.password_hash:
            return False
        
        # Try verification with current hash
        if verify_password(password, user.password_hash):
            # Check if we need to migrate from legacy hash
            if not PasswordHasher.is_bcrypt_hash(user.password_hash):
                try:
                    # Migrate to bcrypt
                    new_hash = PasswordHasher.hash_password(password)
                    self.store.set_user_password(
                        username, password=None, password_hash=new_hash
                    )
                    logger.info(f"Migrated password hash for user {username} to bcrypt")
                except Exception as e:
                    logger.error(f"Failed to migrate password for user {username}: {e}")
            return True
        
        return False
    
    @staticmethod
    def _validate_safe_path(path: Path | str, allowed_base: str = "data") -> Path:
        """Validate path to prevent directory traversal attacks."""
        if not path:
            raise LocalUserValidationError("Path cannot be empty")
        
        try:
            # Convert to Path and resolve to absolute path
            path_obj = Path(path).resolve()
            base_path = Path(allowed_base).resolve()
            
            # Ensure path is within allowed base directory
            try:
                path_obj.relative_to(base_path)
            except ValueError:
                # Path is outside allowed base, create safe path
                safe_name = Path(path).name  # Get just the filename
                if not safe_name or safe_name in ('.', '..'):
                    raise LocalUserValidationError("Invalid filename")
                path_obj = base_path / safe_name
            
            return path_obj
            
        except Exception as e:
            raise LocalUserValidationError(f"Invalid path: {e}") from e
