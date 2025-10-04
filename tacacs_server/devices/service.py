"""Higher-level service helpers for device and group management."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from typing import Any

from tacacs_server.utils.logger import get_logger

from .store import DeviceGroup, DeviceRecord, DeviceStore

UNSET = object()


logger = get_logger(__name__)


class DeviceServiceError(Exception):
    """Base error for device service operations."""


class DeviceNotFound(DeviceServiceError):
    """Raised when a requested device cannot be located."""


class GroupNotFound(DeviceServiceError):
    """Raised when a requested group cannot be located."""


class DeviceValidationError(DeviceServiceError):
    """Raised when input data fails validation."""


def _ensure_metadata(payload: dict[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise DeviceValidationError("metadata must be a JSON object/dict")
    return payload


class DeviceService:
    """Facade around :class:`DeviceStore` with validation and friendly helpers."""

    def __init__(self, store: DeviceStore) -> None:
        self.store = store
        self._change_listeners: list[Callable[[], None]] = []

    # ------------------------------------------------------------------
    # Change notifications
    # ------------------------------------------------------------------
    def add_change_listener(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Register a callback notified whenever device/group data changes."""
        self._change_listeners.append(callback)

        def _remove() -> None:
            try:
                self._change_listeners.remove(callback)
            except ValueError:
                pass

        return _remove

    def _notify_change(self) -> None:
        for callback in list(self._change_listeners):
            try:
                callback()
            except Exception:
                logger.exception("DeviceService change listener failed")

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------
    def list_groups(self) -> list[DeviceGroup]:
        return self.store.list_groups()

    def get_group(self, group_id: int) -> DeviceGroup:
        group = self.store.get_group_by_id(group_id)
        if not group:
            raise GroupNotFound(f"Group id {group_id} not found")
        return group

    def create_group(
        self,
        name: str,
        *,
        description: str | None = None,
        tacacs_profile: dict[str, Any] | None = None,
        radius_profile: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        radius_secret: str | None = None,
        tacacs_secret: str | None = None,
        device_config: dict[str, Any] | None = None,
        allowed_user_groups: Iterable[str] | None = None,
    ) -> DeviceGroup:
        name = (name or "").strip()
        if not name:
            raise DeviceValidationError("Group name is required")
        existing = self.store.get_group_by_name(name)
        if existing:
            raise DeviceValidationError(f"Group '{name}' already exists")
        merged_metadata = _ensure_metadata(metadata)
        if tacacs_secret:
            self._validate_secret(tacacs_secret, "tacacs_secret")
            merged_metadata["tacacs_secret"] = tacacs_secret
        if radius_secret:
            self._validate_secret(radius_secret, "radius_secret")
            merged_metadata["radius_secret"] = radius_secret
        if device_config is not None:
            if not isinstance(device_config, dict):
                raise DeviceValidationError("device_config must be a JSON object")
            merged_metadata["device_config"] = device_config
        allowed_groups = self._validate_allowed_groups(allowed_user_groups)
        if allowed_groups:
            merged_metadata["allowed_user_groups"] = allowed_groups
        else:
            merged_metadata.pop("allowed_user_groups", None)
        group = self.store.ensure_group(
            name,
            description=description,
            tacacs_profile=_ensure_metadata(tacacs_profile),
            radius_profile=_ensure_metadata(radius_profile),
            metadata=merged_metadata,
        )
        self._notify_change()
        return group

    def update_group(
        self,
        group_id: int,
        *,
        name: str | None = None,
        description: str | None = None,
        tacacs_profile: dict[str, Any] | None = None,
        radius_profile: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        radius_secret: str | None | object = UNSET,
        tacacs_secret: str | None | object = UNSET,
        device_config: dict[str, Any] | None | object = UNSET,
        allowed_user_groups: Iterable[str] | None | object = UNSET,
    ) -> DeviceGroup:
        group = self.get_group(group_id)

        if name is not None:
            new_name = name.strip()
            if not new_name:
                raise DeviceValidationError("Group name cannot be empty")
            existing = self.store.get_group_by_name(new_name)
            if existing and existing.id != group_id:
                raise DeviceValidationError(f"Group '{new_name}' already exists")
        else:
            new_name = None

        merged_metadata: dict[str, Any] | None = None
        if (
            metadata is not None
            or radius_secret is not UNSET
            or tacacs_secret is not UNSET
            or device_config is not UNSET
            or allowed_user_groups is not UNSET
        ):
            merged_metadata = (
                _ensure_metadata(metadata)
                if metadata is not None
                else dict(group.metadata)
            )
            if metadata is None and getattr(group, "allowed_user_groups", None):
                merged_metadata.setdefault(
                    "allowed_user_groups", list(group.allowed_user_groups)
                )
            if tacacs_secret is not UNSET:
                if tacacs_secret:
                    self._validate_secret(str(tacacs_secret), "tacacs_secret")
                    merged_metadata["tacacs_secret"] = tacacs_secret
                else:
                    merged_metadata.pop("tacacs_secret", None)
            if radius_secret is not UNSET:
                if radius_secret:
                    self._validate_secret(str(radius_secret), "radius_secret")
                    merged_metadata["radius_secret"] = radius_secret
                else:
                    merged_metadata.pop("radius_secret", None)
            if device_config is not UNSET:
                if device_config is not None and not isinstance(device_config, dict):
                    raise DeviceValidationError("device_config must be a JSON object")
                if device_config:
                    merged_metadata["device_config"] = device_config
                else:
                    merged_metadata.pop("device_config", None)
            if allowed_user_groups is not UNSET:
                if allowed_user_groups is None:
                    merged_metadata.pop("allowed_user_groups", None)
                else:
                    if isinstance(allowed_user_groups, (list, tuple)):
                        validated = self._validate_allowed_groups(
                            [str(g) for g in allowed_user_groups]
                        )
                    else:
                        validated = None
                    if validated:
                        merged_metadata["allowed_user_groups"] = validated
                    else:
                        merged_metadata.pop("allowed_user_groups", None)

        updated = self.store.update_group(
            group_id,
            name=new_name,
            description=description,
            tacacs_profile=(
                _ensure_metadata(tacacs_profile) if tacacs_profile is not None else None
            ),
            radius_profile=(
                _ensure_metadata(radius_profile) if radius_profile is not None else None
            ),
            metadata=merged_metadata,
        )
        if not updated:
            raise GroupNotFound(f"Group id {group_id} not found")
        self._notify_change()
        return updated

    def delete_group(self, group_id: int, *, cascade: bool = False) -> bool:
        self.get_group(group_id)
        try:
            deleted = self.store.delete_group(group_id, cascade=cascade)
        except ValueError as exc:
            raise DeviceValidationError(str(exc)) from exc
        if deleted:
            self._notify_change()
        return deleted

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------
    def list_devices(self) -> list[DeviceRecord]:
        return self.store.list_devices()

    def list_devices_by_group(self, group_id: int) -> list[DeviceRecord]:
        self.get_group(group_id)
        return self.store.list_devices_by_group(group_id)

    def get_device(self, device_id: int) -> DeviceRecord:
        device = self.store.get_device_by_id(device_id)
        if not device:
            raise DeviceNotFound(f"Device id {device_id} not found")
        return device

    def create_device(
        self,
        *,
        name: str,
        network: str,
        group: str | None = None,
    ) -> DeviceRecord:
        name = (name or "").strip()
        if not name:
            raise DeviceValidationError("Device name is required")

        network_obj = self._validate_network(network)

        if group:
            self._require_group(group)

        device = self.store.ensure_device(
            name,
            str(network_obj),
            group=group,
        )
        if not device:
            raise DeviceServiceError("Failed to create device")
        self._notify_change()
        return device

    def update_device(
        self,
        device_id: int,
        *,
        name: str | None = None,
        network: str | None = None,
        group: str | None = None,
        clear_group: bool = False,
    ) -> DeviceRecord:
        self.get_device(device_id)

        if name is not None:
            stripped_name = name.strip()
            if not stripped_name:
                raise DeviceValidationError("Device name cannot be empty")
        else:
            stripped_name = None

        network_obj = self._validate_network(network) if network is not None else None

        if group and clear_group:
            raise DeviceValidationError("Cannot set and clear group simultaneously")

        if group:
            self._require_group(group)

        updated = self.store.update_device(
            device_id,
            name=stripped_name,
            network=str(network_obj) if network_obj else None,
            group=group,
            clear_group=clear_group,
        )
        if not updated:
            raise DeviceNotFound(f"Device id {device_id} not found")
        self._notify_change()
        return updated

    def delete_device(self, device_id: int) -> bool:
        self.get_device(device_id)
        deleted = self.store.delete_device(device_id)
        if deleted:
            self._notify_change()
        return deleted

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _validate_network(network: str) -> ipaddress._BaseNetwork:
        if not network:
            raise DeviceValidationError("network is required")
        try:
            return ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            raise DeviceValidationError(f"Invalid network '{network}': {exc}") from exc

    @staticmethod
    def _validate_secret(secret: str, field: str) -> None:
        if len(secret.strip()) < 4:
            raise DeviceValidationError(f"{field} must be at least 4 characters")

    @staticmethod
    def _validate_allowed_groups(groups: Iterable[str] | None) -> list[str]:
        if groups is None:
            return []
        result: list[str] = []
        for group in groups:
            if not isinstance(group, str):
                raise DeviceValidationError(
                    "allowed_user_groups entries must be strings"
                )
            trimmed = group.strip()
            if not trimmed:
                raise DeviceValidationError(
                    "allowed_user_groups entries must not be empty"
                )
            if trimmed not in result:
                result.append(trimmed)
        return result

    def _require_group(self, group_name: str) -> DeviceGroup:
        group = self.store.get_group_by_name(group_name)
        if not group:
            raise GroupNotFound(f"Group '{group_name}' not found")
        return group
