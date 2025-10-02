"""SQLite-backed device inventory for TACACS+ and RADIUS."""
from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


JsonDict = dict[str, Any]
NetworkType = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class DeviceGroup:
    """Logical grouping of devices with shared configuration."""

    id: int
    name: str
    description: str | None = None
    tacacs_profile: JsonDict = field(default_factory=dict)
    radius_profile: JsonDict = field(default_factory=dict)
    metadata: JsonDict = field(default_factory=dict)
    tacacs_secret: str | None = None
    radius_secret: str | None = None
    device_config: JsonDict = field(default_factory=dict)
    allowed_user_groups: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DeviceRecord:
    """Stored device or network entry."""

    id: int
    name: str
    network: NetworkType
    group: DeviceGroup | None
    tacacs_secret: str | None
    radius_secret: str | None
    metadata: JsonDict = field(default_factory=dict)

    @property
    def is_network(self) -> bool:
        return self.network.prefixlen not in (32, 128)

    @property
    def display_name(self) -> str:
        return self.name or str(self.network)


@dataclass(frozen=True)
class RadiusClientConfig:
    """Radius client configuration ready for server consumption."""

    network: NetworkType
    secret: str
    name: str
    group: str | None = None
    attributes: JsonDict = field(default_factory=dict)
    allowed_user_groups: list[str] = field(default_factory=list)

    def matches(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return ip_obj in self.network


class DeviceStore:
    """Device inventory with SQLite persistence."""

    def __init__(self, db_path: str | Path = "data/devices.db") -> None:
        # Resolve and validate path to prevent path traversal
        self.db_path = Path(db_path).resolve()
        # Ensure path is within expected directory structure (allow pytest temp dirs)
        cwd = str(Path.cwd().resolve())
        db_str = str(self.db_path)
        if not (db_str.startswith(cwd) or "/pytest-" in db_str):
            raise ValueError(f"Database path outside allowed directory: {self.db_path}")
        if not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------
    def _ensure_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS device_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    tacacs_profile TEXT,
                    radius_profile TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    network TEXT NOT NULL,
                    tacacs_secret TEXT,
                    radius_secret TEXT,
                    metadata TEXT,
                    group_id INTEGER REFERENCES device_groups(id) ON DELETE SET NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, network)
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_devices_group
                ON devices(group_id);
                """
            )
            cur.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_name
                ON device_groups(name);
                """
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _json_dump(self, data: JsonDict | None) -> str:
        return json.dumps(data or {})

    def _json_load(self, payload: str | None) -> JsonDict:
        if not payload:
            return {}
        try:
            loaded = json.loads(payload)
            return loaded if isinstance(loaded, dict) else {}
        except json.JSONDecodeError:
            logger.warning("DeviceStore: failed to JSON-decode payload: %s", payload)
            return {}

    def _row_to_group(self, row: sqlite3.Row) -> DeviceGroup:
        metadata = self._json_load(row["metadata"])
        tacacs_secret = metadata.pop("tacacs_secret", None)
        radius_secret = metadata.pop("radius_secret", None)
        device_config = metadata.pop("device_config", {}) or {}
        if not isinstance(device_config, dict):
            device_config = {}
        allowed_groups_raw = metadata.pop("allowed_user_groups", [])
        if isinstance(allowed_groups_raw, list):
            allowed_groups = [
                str(item) for item in allowed_groups_raw 
                if isinstance(item, str) and item
            ]
        else:
            allowed_groups = []
        return DeviceGroup(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            tacacs_profile=self._json_load(row["tacacs_profile"]),
            radius_profile=self._json_load(row["radius_profile"]),
            metadata=metadata,
            tacacs_secret=tacacs_secret,
            radius_secret=radius_secret,
            device_config=device_config,
            allowed_user_groups=allowed_groups,
        )

    def _row_to_device(
        self, row: sqlite3.Row, groups: dict[int, DeviceGroup]
    ) -> DeviceRecord:
        network = ipaddress.ip_network(row["network"], strict=False)
        group = groups.get(row["group_id"])
        return DeviceRecord(
            id=row["id"],
            name=row["name"],
            network=network,
            group=group,
            tacacs_secret=None,
            radius_secret=None,
            metadata=self._json_load(row["metadata"]),
        )

    def _load_groups(self) -> dict[int, DeviceGroup]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM device_groups")
            groups = {row["id"]: self._row_to_group(row) for row in cur.fetchall()}
        return groups

    # ------------------------------------------------------------------
    # Group operations
    # ------------------------------------------------------------------
    def list_groups(self) -> list[DeviceGroup]:
        return list(self._load_groups().values())

    def ensure_group(
        self,
        name: str,
        description: str | None = None,
        tacacs_profile: JsonDict | None = None,
        radius_profile: JsonDict | None = None,
        metadata: JsonDict | None = None,
    ) -> DeviceGroup:
        """Create the group if it does not exist or update metadata."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM device_groups WHERE name = ?",
                (name,),
            )
            row = cur.fetchone()
            if row:
                # Update existing group if new data provided
                updates: list[str] = []
                params: list[Any] = []
                if description is not None:
                    updates.append("description = ?")
                    params.append(description)
                if tacacs_profile is not None:
                    updates.append("tacacs_profile = ?")
                    params.append(self._json_dump(tacacs_profile))
                if radius_profile is not None:
                    updates.append("radius_profile = ?")
                    params.append(self._json_dump(radius_profile))
                if metadata is not None:
                    updates.append("metadata = ?")
                    params.append(self._json_dump(metadata))
                if updates:
                    params.append(name)
                    # Use parameterized query to prevent SQL injection
                    update_clause = ', '.join(updates)
                    query_sql = (
                        f"UPDATE device_groups SET {update_clause}, "
                        "updated_at = CURRENT_TIMESTAMP WHERE name = ?"
                    )
                    self._conn.execute(query_sql, params)
                    self._conn.commit()
                    return self.get_group_by_name(name)  # refreshed row
                return self._row_to_group(row)

            self._conn.execute(
                """
                INSERT INTO device_groups (name, description, tacacs_profile, 
                                         radius_profile, metadata)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    name,
                    description,
                    self._json_dump(tacacs_profile),
                    self._json_dump(radius_profile),
                    self._json_dump(metadata),
                ),
            )
            self._conn.commit()
            return self.get_group_by_name(name)

    def get_group_by_name(self, name: str) -> DeviceGroup | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM device_groups WHERE name = ?",
                (name,),
            )
            row = cur.fetchone()
            return self._row_to_group(row) if row else None

    def get_group_by_id(self, group_id: int) -> DeviceGroup | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM device_groups WHERE id = ?",
                (group_id,),
            )
            row = cur.fetchone()
            return self._row_to_group(row) if row else None

    def update_group(
        self,
        group_id: int,
        *,
        name: str | None = None,
        description: str | None = None,
        tacacs_profile: JsonDict | None = None,
        radius_profile: JsonDict | None = None,
        metadata: JsonDict | None = None,
    ) -> DeviceGroup | None:
        updates: list[str] = []
        params: list[Any] = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if tacacs_profile is not None:
            updates.append("tacacs_profile = ?")
            params.append(self._json_dump(tacacs_profile))
        if radius_profile is not None:
            updates.append("radius_profile = ?")
            params.append(self._json_dump(radius_profile))
        if metadata is not None:
            updates.append("metadata = ?")
            params.append(self._json_dump(metadata))

        if not updates:
            return self.get_group_by_id(group_id)

        params.append(group_id)
        with self._lock:
            # Use parameterized query to prevent SQL injection
            update_clause = ', '.join(updates)
            query_sql = (
                f"UPDATE device_groups SET {update_clause}, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            )
            self._conn.execute(query_sql, params)
            self._conn.commit()

        return self.get_group_by_id(group_id)

    def delete_group(self, group_id: int, *, cascade: bool = False) -> bool:
        """Delete a device group. 
        If cascade is False and devices exist, raise ValueError.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(1) AS cnt FROM devices WHERE group_id = ?",
                (group_id,),
            )
            count_row = cur.fetchone()
            device_count = count_row["cnt"] if count_row else 0
            if device_count and not cascade:
                raise ValueError("Group is in use by one or more devices")
            if device_count and cascade:
                self._conn.execute(
                    "DELETE FROM devices WHERE group_id = ?",
                    (group_id,),
                )
            result = self._conn.execute(
                "DELETE FROM device_groups WHERE id = ?",
                (group_id,),
            )
            self._conn.commit()
            return result.rowcount > 0

    # ------------------------------------------------------------------
    # Device operations
    # ------------------------------------------------------------------
    def list_devices(self) -> list[DeviceRecord]:
        groups = self._load_groups()
        with self._lock:
            cur = self._conn.execute("SELECT * FROM devices ORDER BY name")
            rows = cur.fetchall()
        return [self._row_to_device(row, groups) for row in rows]

    def list_devices_by_group(self, group_id: int) -> list[DeviceRecord]:
        groups = self._load_groups()
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM devices WHERE group_id = ? ORDER BY name",
                (group_id,),
            )
            rows = cur.fetchall()
        return [self._row_to_device(row, groups) for row in rows]

    def get_device_by_id(self, device_id: int) -> DeviceRecord | None:
        groups = self._load_groups()
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM devices WHERE id = ?",
                (device_id,),
            )
            row = cur.fetchone()
        return self._row_to_device(row, groups) if row else None

    def ensure_device(
        self,
        name: str,
        network: str | NetworkType,
        *,
        group: str | None = None,
    ) -> DeviceRecord:
        """Create or update a device entry."""
        network_obj = ipaddress.ip_network(str(network), strict=False)
        group_id: int | None = None
        if group:
            grp = self.ensure_group(group)
            group_id = grp.id
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM devices WHERE name = ? AND network = ?",
                (name, str(network_obj)),
            )
            row = cur.fetchone()
            if row:
                updates: list[str] = []
                params: list[Any] = []
                if group_id is not None:
                    updates.append("group_id = ?")
                    params.append(group_id)
                if updates:
                    params.append(name)
                    params.append(str(network_obj))
                    # Use parameterized query to prevent SQL injection
                    update_clause = ', '.join(updates)
                    query_sql = (
                        f"UPDATE devices SET {update_clause}, "
                        "updated_at = CURRENT_TIMESTAMP WHERE name = ? AND network = ?"
                    )
                    self._conn.execute(query_sql, params)
                    self._conn.commit()
                groups = self._load_groups()
                return self._row_to_device(row, groups)

            self._conn.execute(
                """
                INSERT INTO devices (name, network, tacacs_secret, radius_secret, 
                                     metadata, group_id)
                VALUES (?, ?, NULL, NULL, NULL, ?)
                """,
                (
                    name,
                    str(network_obj),
                    group_id,
                ),
            )
            self._conn.commit()

        groups = self._load_groups()
        cur = self._conn.execute(
            "SELECT * FROM devices WHERE name = ? AND network = ?",
            (name, str(network_obj)),
        )
        row = cur.fetchone()
        return self._row_to_device(row, groups) if row else None  # type: ignore[arg-type]

    def update_device(
        self,
        device_id: int,
        *,
        name: str | None = None,
        network: str | NetworkType | None = None,
        group: str | None = None,
        clear_group: bool = False,
    ) -> DeviceRecord | None:
        """Update an existing device entry."""
        updates: list[str] = []
        params: list[Any] = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)

        if network is not None:
            network_obj = ipaddress.ip_network(str(network), strict=False)
            updates.append("network = ?")
            params.append(str(network_obj))
        else:
            network_obj = None

        if group is not None and clear_group:
            raise ValueError("Cannot set group and clear it simultaneously")

        if group is not None:
            group_obj = self.ensure_group(group)
            updates.append("group_id = ?")
            params.append(group_obj.id)

        if clear_group:
            updates.append("group_id = NULL")

        if not updates:
            return self.get_device_by_id(device_id)

        params.append(device_id)
        with self._lock:
            # Use parameterized query to prevent SQL injection
            update_clause = ', '.join(updates)
            query_sql = (
                f"UPDATE devices SET {update_clause}, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            )
            self._conn.execute(query_sql, params)
            self._conn.commit()

        return self.get_device_by_id(device_id)

    def delete_device(self, device_id: int) -> bool:
        with self._lock:
            result = self._conn.execute(
                "DELETE FROM devices WHERE id = ?",
                (device_id,),
            )
            self._conn.commit()
            return result.rowcount > 0

    # ------------------------------------------------------------------
    # RADIUS helpers
    # ------------------------------------------------------------------
    def iter_radius_clients(self) -> list[RadiusClientConfig]:
        devices = self.list_devices()
        clients: list[RadiusClientConfig] = []
        for device in devices:
            group_obj = device.group
            group_name = group_obj.name if group_obj else None
            secret = None
            merged_attrs: JsonDict = {}
            device_cfg: JsonDict = {}

            if group_obj:
                secret = group_obj.radius_secret or None
                group_radius_profile = group_obj.radius_profile
                if not secret and isinstance(group_radius_profile, dict):
                    secret = group_radius_profile.get("secret")
                    attrs = group_radius_profile.get("attributes")
                    if isinstance(attrs, dict):
                        merged_attrs.update(attrs)

                device_cfg = group_obj.device_config or {}
                if isinstance(device_cfg, dict):
                    attrs = device_cfg.get("radius_attributes")
                    if isinstance(attrs, dict):
                        merged_attrs.update(attrs)

            if not secret:
                logger.debug(
                    "DeviceStore: skipping device '%s' (%s) - "
                    "no RADIUS secret via group",
                    device.name,
                    device.network,
                )
                continue

            client_name = (
                device_cfg.get("radius_name") if isinstance(device_cfg, dict) else None
            )
            if not client_name:
                client_name = device.name
            clients.append(
                RadiusClientConfig(
                    network=device.network,
                    secret=secret,
                    name=str(client_name),
                    group=group_name,
                    attributes=merged_attrs,
                    allowed_user_groups=list(
                        group_obj.allowed_user_groups if group_obj else []
                    ),
                )
            )
        # Sort by prefix length descending so longest match wins during lookup
        clients.sort(key=lambda c: c.network.prefixlen, reverse=True)
        return clients

    def resolve_radius_client(self, ip: str) -> RadiusClientConfig | None:
        ip_obj = ipaddress.ip_address(ip)
        for client in self.iter_radius_clients():
            if ip_obj in client.network:
                return client
        return None

    def find_device_by_network(self, network: str | NetworkType) -> DeviceRecord | None:
        network_obj = ipaddress.ip_network(str(network), strict=False)
        groups = self._load_groups()
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM devices WHERE network = ?",
                (str(network_obj),),
            )
            row = cur.fetchone()
        return self._row_to_device(row, groups) if row else None

    def find_device_for_ip(self, ip: str) -> DeviceRecord | None:
        """Resolve a device record for the given client IP address."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        groups = self._load_groups()
        with self._lock:
            cur = self._conn.execute("SELECT * FROM devices")
            rows = cur.fetchall()

        for row in rows:
            device = self._row_to_device(row, groups)
            if ip_obj in device.network:
                return device
        return None

    # ------------------------------------------------------------------
    # Context management
    # ------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> DeviceStore:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        self.close()
