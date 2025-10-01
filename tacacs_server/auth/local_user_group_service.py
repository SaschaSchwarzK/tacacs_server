"""Service helpers for managing local user groups stored in SQLite."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Dict, Optional

from .local_models import LocalUserGroupRecord
from .local_store import LocalAuthStore, UNSET
from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class LocalUserGroupServiceError(Exception):
    """Base exception for user group operations."""


class LocalUserGroupValidationError(LocalUserGroupServiceError):
    """Raised when supplied data is invalid."""


class LocalUserGroupExists(LocalUserGroupServiceError):
    """Raised when attempting to create a duplicate group."""


class LocalUserGroupNotFound(LocalUserGroupServiceError):
    """Raised when referencing a missing group."""


class LocalUserGroupService:
    """CRUD operations for local user groups backed by SQLite."""

    def __init__(
        self,
        db_path: Path | str = "data/local_auth.db",
        *,
        store: Optional[LocalAuthStore] = None,
        seed_file: Optional[Path | str] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.store = store or LocalAuthStore(self.db_path)
        if seed_file:
            self._seed_from_json(Path(seed_file))

    def list_groups(self) -> list[LocalUserGroupRecord]:
        return [self._clone(record) for record in self.store.list_groups()]

    def get_group(self, name: str) -> LocalUserGroupRecord:
        record = self.store.get_group(name)
        if not record:
            raise LocalUserGroupNotFound(f"User group '{name}' not found")
        return self._clone(record)

    def create_group(
        self,
        name: str,
        *,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, object]] = None,
        ldap_group: Optional[str] = None,
        okta_group: Optional[str] = None,
        privilege_level: int = 1,
    ) -> LocalUserGroupRecord:
        validated_name = self._validate_name(name)
        privilege = self._validate_privilege(privilege_level)
        metadata_payload = self._validate_metadata(metadata)
        metadata_payload["privilege_level"] = privilege
        record = LocalUserGroupRecord(
            name=validated_name,
            description=description,
            metadata=metadata_payload,
            ldap_group=ldap_group,
            okta_group=okta_group,
            privilege_level=privilege,
        )
        try:
            stored = self.store.insert_group(record)
        except sqlite3.IntegrityError as exc:
            raise LocalUserGroupExists(f"User group '{validated_name}' already exists") from exc
        return self._clone(stored)

    def update_group(
        self,
        name: str,
        *,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, object]] = None,
        ldap_group: Optional[str] | object = UNSET,
        okta_group: Optional[str] | object = UNSET,
        privilege_level: Optional[int] = None,
    ) -> LocalUserGroupRecord:
        # Ensure the group exists before attempting update
        current = self.store.get_group(name)
        if not current:
            raise LocalUserGroupNotFound(f"User group '{name}' not found")

        metadata_payload = (
            self._validate_metadata(metadata)
            if metadata is not None
            else dict(current.metadata)
        )
        if privilege_level is not None:
            metadata_payload["privilege_level"] = self._validate_privilege(privilege_level)
        else:
            metadata_payload.setdefault("privilege_level", current.privilege_level)
        stored = self.store.update_group(
            name,
            description=description,
            metadata=metadata_payload,
            ldap_group=ldap_group,
            okta_group=okta_group,
        )
        if not stored:
            raise LocalUserGroupNotFound(f"User group '{name}' not found")
        return self._clone(stored)

    def delete_group(self, name: str) -> bool:
        if not self.store.delete_group(name):
            raise LocalUserGroupNotFound(f"User group '{name}' not found")
        return True

    def reload(self) -> None:
        self.store.reload()

    @staticmethod
    def _clone(record: LocalUserGroupRecord) -> LocalUserGroupRecord:
        return replace(record, metadata=dict(record.metadata))

    def _seed_from_json(self, seed_path: Path) -> None:
        if not seed_path.exists():
            return

        try:
            if self.store.list_groups():
                return
        except Exception:
            logger.exception("Failed to inspect local user groups before seeding")
            return

        try:
            with seed_path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            logger.exception("Failed to load legacy user groups from %s", seed_path)
            return

        if not isinstance(payload, dict):
            logger.warning("Legacy user groups seed %s is not a JSON object", seed_path)
            return

        for name, data in payload.items():
            if not isinstance(data, dict):
                logger.warning("Skipping legacy user group %s with invalid payload", name)
                continue
            try:
                record = LocalUserGroupRecord.from_dict(name, data)
                try:
                    self.store.insert_group(record)
                except sqlite3.IntegrityError:
                    continue
            except Exception:
                logger.exception("Failed to import legacy user group %s", name)

    @staticmethod
    def _validate_name(name: str) -> str:
        name = (name or "").strip()
        if not name:
            raise LocalUserGroupValidationError("Group name is required")
        return name

    @staticmethod
    def _validate_metadata(metadata: Optional[Dict[str, object]]) -> Dict[str, object]:
        if metadata is None:
            return {}
        if not isinstance(metadata, dict):
            raise LocalUserGroupValidationError("metadata must be a JSON object")
        return metadata

    @staticmethod
    def _validate_privilege(level: int) -> int:
        try:
            level = int(level)
        except (TypeError, ValueError) as exc:
            raise LocalUserGroupValidationError("privilege_level must be an integer") from exc
        if level < 0 or level > 15:
            raise LocalUserGroupValidationError("privilege_level must be between 0 and 15")
        return level
