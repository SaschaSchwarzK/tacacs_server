"""Higher-level service helpers for device and group management."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from typing import Any

from tacacs_server.utils.logger import get_logger

from .store import DeviceGroup, DeviceRecord, DeviceStore, Proxy

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
        # Prime indexes for fast lookups
        try:
            self.store.refresh_indexes()
        except Exception:
            logger.exception("DeviceService: failed to refresh indexes on init")

        # Ensure cache/index refresh on changes
        def _refresh():
            try:
                self.store.refresh_indexes()
            except Exception:
                logger.exception("DeviceService: failed to refresh indexes on change")

        self.add_change_listener(_refresh)

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
                pass  # Callback already removed, ignore

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

    def get_device_groups(
        self, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        """
        Get device groups (API-friendly).

        Wrapper around list_groups().
        """
        groups = self.list_groups()
        group_dicts = []
        for g in groups:
            try:
                group_dicts.append(self._group_to_dict(g))
            except Exception as e:
                logger.exception(f"Failed to convert group {getattr(g, 'id', '?')} to dict: {e}")
                # Skip this group and continue
                continue
        return group_dicts[offset : offset + limit]

    def get_device_group_by_id(self, group_id: int) -> dict[str, Any] | None:
        """
        Get device group by ID (API-friendly).

        Wrapper around get_group().
        """
        try:
            group = self.get_group(group_id)
            return self._group_to_dict(group)
        except GroupNotFound:
            return None

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
        realm: str | None = None,
        proxy_network: str | None = None,
        proxy_id: int | None = None,
    ) -> DeviceGroup:
        from tacacs_server.utils.validation import InputValidator

        name = (name or "").strip()
        if not name:
            raise DeviceValidationError("Group name is required")
        # Enforce safe character set for group names
        name = InputValidator.validate_safe_text(
            name, "group name", min_len=1, max_len=64
        )
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
        # If proxy_id provided and proxy_network not provided, resolve
        if proxy_id is not None and proxy_network is None:
            proxy = self.store.get_proxy_by_id(int(proxy_id))
            if not proxy:
                raise DeviceValidationError(f"Proxy id {proxy_id} not found")
            proxy_network = str(proxy.network)

        # Validate proxy_network CIDR when provided explicitly
        if proxy_network is not None:
            try:
                ipaddress.ip_network(str(proxy_network), strict=False)
            except ValueError as exc:
                raise DeviceValidationError(
                    f"Invalid proxy network: {proxy_network}"
                ) from exc

        group = self.store.ensure_group(
            name,
            description=description,
            realm=realm,
            proxy_network=proxy_network,
            tacacs_profile=_ensure_metadata(tacacs_profile),
            radius_profile=_ensure_metadata(radius_profile),
            metadata=merged_metadata,
        )
        self._notify_change()
        return group

    def create_device_group(
        self,
        name: str,
        description: str | None = None,
        tacacs_secret: str | None = None,
        radius_secret: str | None = None,
        allowed_user_groups: list[str] | None = None,
        proxy_network: str | None = None,
        proxy_id: int | None = None,
    ) -> dict[str, Any]:
        """
        Create device group (API-friendly).

        Wrapper around create_group() with simpler parameters.
        """
        group = self.create_group(
            name,
            description=description,
            tacacs_secret=tacacs_secret,
            radius_secret=radius_secret,
            allowed_user_groups=allowed_user_groups,
            proxy_network=proxy_network,
            proxy_id=proxy_id,
        )
        return self._group_to_dict(group)

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
        proxy_id: int | None | object = UNSET,
        proxy_network: str | None | object = UNSET,
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
            proxy_id=(int(proxy_id) if isinstance(proxy_id, int) else None)
            if proxy_id is not UNSET
            else None,
        )
        if not updated:
            raise GroupNotFound(f"Group id {group_id} not found")
        self._notify_change()
        return updated

    def update_device_group(
        self,
        group_id: int,
        name: str | None = None,
        description: str | None = None,
        tacacs_secret: str | None = None,
        radius_secret: str | None = None,
        allowed_user_groups: list[str] | None = None,
        proxy_network: str | None = None,
        proxy_id: int | None = None,
    ) -> dict[str, Any]:
        """
        Update device group (API-friendly).

        Wrapper around update_group() with simpler parameters.
        """
        # Build kwargs dynamically
        kwargs: dict[str, Any] = {}
        if name is not None:
            kwargs["name"] = name
        if description is not None:
            kwargs["description"] = description
        if tacacs_secret is not None:
            kwargs["tacacs_secret"] = tacacs_secret if tacacs_secret else None
        if radius_secret is not None:
            kwargs["radius_secret"] = radius_secret if radius_secret else None
        if allowed_user_groups is not None:
            kwargs["allowed_user_groups"] = allowed_user_groups

        group = self.update_group(
            group_id, proxy_id=proxy_id, proxy_network=proxy_network, **kwargs
        )
        return self._group_to_dict(group)

    def delete_group(self, group_id: int, *, cascade: bool = False) -> bool:
        self.get_group(group_id)
        try:
            deleted = self.store.delete_group(group_id, cascade=cascade)
        except ValueError as exc:
            raise DeviceValidationError(str(exc)) from exc
        if deleted:
            self._notify_change()
        return deleted

    def delete_device_group(self, group_id: int) -> None:
        """
        Delete device group (API-friendly).

        Wrapper around delete_group().
        """
        self.delete_group(group_id, cascade=False)

    def _group_to_dict(self, group: DeviceGroup) -> dict[str, Any]:
        """Convert DeviceGroup to API-friendly dict."""
        try:
            if group is None:
                raise DeviceValidationError("Cannot convert None group to dict")
            # Count devices in this group
            device_count = 0
            if group.id is not None:
                try:
                    devices = self.list_devices_by_group(group.id)
                    device_count = len(devices)
                except Exception as e:
                    logger.warning(f"Failed to count devices for group {group.id}: {e}")
                    device_count = 0

            # Extract secrets status without exposing actual secrets
            # Secrets are stored as direct attributes on DeviceGroup, not in metadata
            tacacs_secret_set = bool(getattr(group, "tacacs_secret", None))
            radius_secret_set = bool(getattr(group, "radius_secret", None))

            # Extract allowed user groups from the DeviceGroup attribute
            # Return as-is (names) since API expects names, not IDs
            allowed_groups_names = getattr(group, "allowed_user_groups", []) or []
            # Ensure it's a list of strings
            if not isinstance(allowed_groups_names, list):
                allowed_groups_names = []

            # Best-effort resolve proxy id
            proxy_id_val = None
            try:
                for p in self.store.list_proxies():
                    if str(p.network) == str(getattr(group, "proxy_network", None) or ""):
                        proxy_id_val = p.id
                        break
            except Exception as e:
                logger.warning(f"Failed to resolve proxy_id for group {group.id}: {e}")
                proxy_id_val = None

            # Safely get created_at
            created_at_val = None
            try:
                if hasattr(group, "created_at") and group.created_at:
                    created_at_val = group.created_at.isoformat()
            except Exception as e:
                logger.warning(f"Failed to get created_at for group {group.id}: {e}")
                created_at_val = None

            # Ensure profiles are always dicts
            tacacs_prof = getattr(group, "tacacs_profile", None)
            if not isinstance(tacacs_prof, dict):
                tacacs_prof = {}
            radius_prof = getattr(group, "radius_profile", None)
            if not isinstance(radius_prof, dict):
                radius_prof = {}

            return {
                "id": getattr(group, "id", None),
                "name": getattr(group, "name", ""),
                "description": getattr(group, "description", None),
                "proxy_network": getattr(group, "proxy_network", None),
                "proxy_id": proxy_id_val,
                "tacacs_secret_set": tacacs_secret_set,
                "radius_secret_set": radius_secret_set,
                "allowed_user_groups": allowed_groups_names,
                "device_count": device_count,
                "created_at": created_at_val,
                "tacacs_profile": tacacs_prof,
                "radius_profile": radius_prof,
            }
        except Exception as e:
            logger.exception(f"Failed to convert group to dict: {e}")
            raise

    # ------------------------------
    # Proxies management
    # ------------------------------
    def list_proxies(self) -> list[Proxy]:
        return self.store.list_proxies()

    def create_proxy(
        self, name: str, network: str, metadata: dict[str, Any] | None = None
    ) -> Proxy:
        if str(name).lower().startswith("auto-proxy:"):
            raise DeviceValidationError(
                "Proxy name cannot start with reserved prefix 'auto-proxy:'"
            )
        try:
            return self.store.create_proxy(
                name=name, network=network, metadata=metadata or {}
            )
        except ValueError as e:
            raise DeviceValidationError(str(e))

    def update_proxy(
        self,
        proxy_id: int,
        *,
        name: str | None = None,
        network: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Proxy:
        if name is not None and str(name).lower().startswith("auto-proxy:"):
            raise DeviceValidationError(
                "Proxy name cannot start with reserved prefix 'auto-proxy:'"
            )
        try:
            rec = self.store.update_proxy(
                proxy_id, name=name, network=network, metadata=metadata
            )
        except ValueError as e:
            raise DeviceValidationError(str(e))
        if rec is None:
            raise DeviceValidationError("Proxy not found")
        return rec

    def delete_proxy(self, proxy_id: int) -> bool:
        return self.store.delete_proxy(proxy_id)

    def get_proxy(self, proxy_id: int) -> Proxy:
        rec = self.store.get_proxy_by_id(proxy_id)
        if rec is None:
            raise DeviceValidationError("Proxy not found")
        return rec

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

    def get_devices(
        self,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        device_group_id: int | None = None,
        enabled: bool | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get devices with filtering (API-friendly).

        Wrapper around list_devices() with filtering support.
        """
        devices = self.list_devices()

        # Convert to dict format
        device_dicts = [self._device_to_dict(d) for d in devices]

        # Apply filters
        if search:
            search_lower = search.lower()
            device_dicts = [
                d
                for d in device_dicts
                if search_lower in d["name"].lower()
                or search_lower in d["network"].lower()
            ]

        if device_group_id is not None:
            # Filter by group name (since your store uses group names)
            group = self.store.get_group_by_id(device_group_id)
            if group:
                device_dicts = [d for d in device_dicts if d.get("group") == group.name]

        if enabled is not None:
            # Your current model doesn't have 'enabled' field
            # This would require adding it to the DeviceRecord model
            pass

        # Apply pagination
        return device_dicts[offset : offset + limit]

    def get_device_by_id(self, device_id: int) -> dict[str, Any] | None:
        """
        Get device by ID (API-friendly).

        Wrapper around get_device().
        """
        try:
            device = self.get_device(device_id)
            return self._device_to_dict(device)
        except DeviceNotFound:
            return None

    def _device_to_dict(self, device: DeviceRecord) -> dict[str, Any]:
        """Convert DeviceRecord to API-friendly dict."""
        group = device.group
        group_id = group.id if group else None
        group_name = group.name if group else None

        return {
            "id": device.id,
            "name": device.name,
            "ip_address": str(device.network),  # Your field is 'network'
            "network": str(device.network),
            "device_group_id": group_id if group_id is not None else 0,
            "device_group_name": group_name or "",
            "enabled": True,  # Default since not in your model yet
            "metadata": device.metadata or {},
            "created_at": device.created_at.isoformat()
            if hasattr(device, "created_at")
            else None,
            "updated_at": device.updated_at.isoformat()
            if hasattr(device, "updated_at")
            else None,
        }

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

    def create_device_from_dict(
        self,
        name: str,
        ip_address: str,
        device_group_id: int,
        enabled: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Create device from API-style parameters.

        Converts device_group_id to group name and calls create_device.
        """
        # Get group name from ID
        group = self.store.get_group_by_id(device_group_id)
        if not group:
            raise GroupNotFound(f"Device group with ID {device_group_id} not found")

        # Create device using existing method
        device = self.create_device(name=name, network=ip_address, group=group.name)

        return self._device_to_dict(device)

    def update_device_from_dict(
        self,
        device_id: int,
        name: str | None = None,
        ip_address: str | None = None,
        device_group_id: int | None = None,
        enabled: bool | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Update device from API-style parameters.

        Converts device_group_id to group name and calls update_device.
        """
        kwargs: dict[str, Any] = {}

        if name is not None:
            kwargs["name"] = name

        if ip_address is not None:
            kwargs["network"] = ip_address

        if device_group_id is not None:
            group = self.store.get_group_by_id(device_group_id)
            if not group:
                raise GroupNotFound(f"Device group with ID {device_group_id} not found")
            kwargs["group"] = group.name

        # enabled and metadata are not yet in your model
        # They would need to be added to DeviceRecord

        device = self.update_device(device_id, **kwargs)
        return self._device_to_dict(device)

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

    def _validate_allowed_groups(self, groups: Iterable[str | int] | None) -> list[str]:
        """Validate and normalize allowed_user_groups to list of names.
        
        Accepts both names (strings) and IDs (integers), converts IDs to names.
        """
        if groups is None:
            return []
        result: list[str] = []
        for group in groups:
            group_name = None
            if isinstance(group, int):
                # Convert ID to name - best effort, don't fail if user group doesn't exist yet
                try:
                    from tacacs_server.web.api.usergroups import get_group_service as _get_gsvc
                    gsvc = _get_gsvc()
                    ug = gsvc.get_group(group)
                    if ug and hasattr(ug, 'name') and ug.name:
                        group_name = ug.name
                except Exception:
                    # User group not found or service not available - skip this entry
                    logger.debug(f"Cannot resolve user group ID {group}, skipping")
                    continue
            elif isinstance(group, str):
                group_name = group.strip()
                if not group_name:
                    raise DeviceValidationError(
                        "allowed_user_groups entries must not be empty"
                    )
            else:
                raise DeviceValidationError(
                    "allowed_user_groups entries must be strings or integers"
                )
            if group_name and group_name not in result:
                result.append(group_name)
        return result

    def _require_group(self, group_name: str) -> DeviceGroup:
        group = self.store.get_group_by_name(group_name)
        if not group:
            raise GroupNotFound(f"Group '{group_name}' not found")
        return group
