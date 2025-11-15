"""SQLite-backed device inventory for TACACS+ and RADIUS."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.maintenance import get_db_manager

logger = get_logger(__name__)


JsonDict = dict[str, Any]
NetworkType = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class DeviceGroup:
    """Logical grouping of devices with shared configuration."""

    id: int
    name: str
    description: str | None = None
    realm_id: int | None = None
    # Derived from linked Proxy record (via proxy_id)
    proxy_network: str | None = None
    tacacs_profile: JsonDict = field(default_factory=dict)
    radius_profile: JsonDict = field(default_factory=dict)
    metadata: JsonDict = field(default_factory=dict)
    tacacs_secret: str | None = None
    radius_secret: str | None = None
    device_config: JsonDict = field(default_factory=dict)
    allowed_user_groups: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Proxy:
    id: int
    name: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    metadata: JsonDict = field(default_factory=dict)


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


# Allowed device name characters: letters, digits, space, dot, underscore, hyphen
# Max length 64
_DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9 ._\-]{1,64}$")


def validate_device_name(name: object) -> str:
    """
    Validate and normalise a device name.
    Raises ValueError on invalid names.
    """
    if name is None:
        raise ValueError("Device name is required")
    s = str(name).strip()
    if not s:
        raise ValueError("Device name cannot be empty")
    if not _DEVICE_NAME_RE.match(s):
        raise ValueError(
            "Invalid device name. Allowed characters: letters, digits, space, '.', '_', '-' (max 64 chars)"
        )
    return s


class DeviceStore:
    """Device inventory with SQLite persistence."""

    def __init__(
        self,
        db_path: str | Path = "data/devices.db",
        *,
        identity_cache_ttl_seconds: int | None = None,
        identity_cache_maxsize: int | None = None,
        proxy_enabled: bool | None = None,
    ) -> None:
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
        # Register with maintenance manager so restore can close connections
        try:
            get_db_manager().register(self, self.close_connections)
        except Exception:
            pass  # DB manager registration failed, cleanup will be manual
        self._ensure_schema()
        # Proxy-aware lookup accelerators
        self._idx_lock = threading.RLock()
        self._proxy_index: list[
            tuple[ipaddress._BaseNetwork, ipaddress._BaseNetwork, int]
        ] = []
        self._fallback_index: list[tuple[ipaddress._BaseNetwork, int]] = []
        self._id_index: dict[int, DeviceRecord] = {}
        # Index generation for lazy refresh
        self._index_version = 0
        self._index_built_version = -1
        self._last_refresh_time = 0.0  # Track last refresh for time-based refresh
        from tacacs_server.utils.simple_cache import TTLCache

        # Identity cache sizing is sourced from the configuration passed into
        # the DeviceStore (see main.py wiring via TacacsConfig.get_device_store_config()).
        # If not provided, use conservative defaults.
        ttl = (
            int(identity_cache_ttl_seconds)
            if identity_cache_ttl_seconds is not None
            else 60
        )
        maxsize = (
            int(identity_cache_maxsize) if identity_cache_maxsize is not None else 10000
        )
        self._identity_cache: TTLCache[tuple[str, str | None], int] = TTLCache(
            ttl_seconds=ttl, maxsize=maxsize
        )
        self.proxy_enabled = bool(proxy_enabled) if proxy_enabled is not None else True
        self.refresh_indexes()

    def close_connections(self) -> None:
        # Close the underlying SQLite connection; log on failure
        with self._lock:
            try:
                self._conn.close()
            except Exception as exc:
                logger.warning("DeviceStore close failed: %s", exc)

    def reload(self) -> None:
        """Re-open the underlying SQLite connection after maintenance."""
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass  # Connection already closed, ignore
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._ensure_schema()
        # Rebuild in-memory indexes
        try:
            self.refresh_indexes()
        except Exception:
            pass  # Index refresh failed, will retry on next operation

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------
    def _ensure_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS realms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS device_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    realm_id INTEGER REFERENCES realms(id) ON DELETE SET NULL,
                    proxy_network TEXT,
                    proxy_id INTEGER REFERENCES proxies(id) ON DELETE SET NULL,
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
                    network_start_int INTEGER,
                    network_end_int INTEGER,
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
            # Index for FK proxy lookups
            try:
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_groups_proxy_id ON device_groups(proxy_id)"
                )
            except sqlite3.OperationalError:
                pass  # Index already exists
            # Proxies table to manage proxy networks independently
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS proxies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    network TEXT NOT NULL,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_proxies_network
                ON proxies(network);
                """
            )
            # Try adding realm_id if missing (migration for existing DBs)
            try:
                cur.execute("SELECT realm_id FROM device_groups LIMIT 1")
            except sqlite3.OperationalError:
                cur.execute(
                    "ALTER TABLE device_groups ADD COLUMN realm_id INTEGER REFERENCES realms(id) ON DELETE SET NULL"
                )
            # Try adding proxy_network if missing
            try:
                cur.execute("SELECT proxy_network FROM device_groups LIMIT 1")
            except sqlite3.OperationalError:
                cur.execute("ALTER TABLE device_groups ADD COLUMN proxy_network TEXT")
            # Create schema_migrations table for one-time migrations
            try:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        name TEXT PRIMARY KEY,
                        applied_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        info TEXT
                    );
                    """
                )
            except sqlite3.OperationalError:
                pass  # Index already exists

            # Skip automatic legacy column drop; handled via explicit migration if needed
            # Try adding proxy_id if missing
            try:
                cur.execute("SELECT proxy_id FROM device_groups LIMIT 1")
            except sqlite3.OperationalError:
                cur.execute(
                    "ALTER TABLE device_groups ADD COLUMN proxy_id INTEGER REFERENCES proxies(id) ON DELETE SET NULL"
                )
            # Try adding device integer network range columns and index
            # Integer-typed range columns for correct typing and performance
            try:
                cur.execute(
                    "SELECT network_start_int, network_end_int FROM devices LIMIT 1"
                )
            except sqlite3.OperationalError:
                try:
                    cur.execute(
                        "ALTER TABLE devices ADD COLUMN network_start_int INTEGER"
                    )
                except sqlite3.OperationalError:
                    pass  # Column already exists
                try:
                    cur.execute(
                        "ALTER TABLE devices ADD COLUMN network_end_int INTEGER"
                    )
                except sqlite3.OperationalError:
                    pass  # Column already exists
            # Drop legacy text-range index creation; we only use integer indexes now
            try:
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_devices_net_range_int ON devices(network_start_int, network_end_int)"
                )
            except sqlite3.OperationalError:
                pass  # Index already exists
            # Ensure default realm exists and backfill NULL realm_id
            cur.execute(
                "INSERT OR IGNORE INTO realms(name, description) VALUES(?, ?)",
                ("default", "Default realm"),
            )
            cur.execute(
                "UPDATE device_groups SET realm_id = (SELECT id FROM realms WHERE name='default') WHERE realm_id IS NULL"
            )
            # Skip automatic backfill from legacy proxy_network; explicit migration not required per policy
            # Backfill integer range columns if missing
            try:
                cur2 = self._conn.execute(
                    "SELECT id, network, network_start_int, network_end_int FROM devices"
                )
                rows = cur2.fetchall()
                for r in rows:
                    if r["network_start_int"] is None or r["network_end_int"] is None:
                        try:
                            net = ipaddress.ip_network(r["network"], strict=False)
                            s_int = int(net.network_address)
                            e_int = int(net.broadcast_address)
                            self._conn.execute(
                                "UPDATE devices SET network_start_int=?, network_end_int=? WHERE id=?",
                                (s_int, e_int, r["id"]),
                            )
                        except Exception:
                            continue
                self._conn.commit()
            except Exception:
                self._conn.commit()

    def get_identity_cache_stats(self) -> dict[str, int]:
        """Expose identity cache stats for monitoring tests."""
        try:
            cache = self._identity_cache
            return {
                "hits": int(cache.hits),
                "misses": int(cache.misses),
                "evictions": int(cache.evictions),
            }
        except Exception:
            return {"hits": 0, "misses": 0, "evictions": 0}

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
                str(item)
                for item in allowed_groups_raw
                if isinstance(item, str) and item
            ]
        else:
            allowed_groups = []
        return DeviceGroup(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            realm_id=row["realm_id"] if "realm_id" in row.keys() else None,
            proxy_network=(
                row["proxy_network"] if "proxy_network" in row.keys() else None
            ),
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
        # Join proxies so that DeviceGroup.proxy_network reflects proxy network from proxies table
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT g.id, g.name, g.description, g.realm_id,
                       p.network AS proxy_network,
                       g.tacacs_profile, g.radius_profile, g.metadata
                  FROM device_groups g
             LEFT JOIN proxies p ON p.id = g.proxy_id
                """
            )
            groups = {row["id"]: self._row_to_group(row) for row in cur.fetchall()}
        return groups

    # ------------------------------------------------------------------
    # Group operations
    # ------------------------------------------------------------------
    def list_groups(self) -> list[DeviceGroup]:
        return list(self._load_groups().values())

    # ------------------------------------------------------------------
    # Index and cache maintenance
    # ------------------------------------------------------------------
    def refresh_indexes(self) -> None:
        """Rebuild in-memory indexes for proxy-aware lookups."""
        groups = self._load_groups()
        with self._lock:
            cur = self._conn.execute("SELECT * FROM devices")
            rows = cur.fetchall()
        proxy_idx: list[tuple[ipaddress._BaseNetwork, ipaddress._BaseNetwork, int]] = []
        fallback_idx: list[tuple[ipaddress._BaseNetwork, int]] = []
        id_index: dict[int, DeviceRecord] = {}
        for row in rows:
            dev = self._row_to_device(row, groups)
            id_index[dev.id] = dev
            grp = dev.group
            if grp and getattr(grp, "proxy_network", None):
                try:
                    pn = ipaddress.ip_network(str(grp.proxy_network), strict=False)
                    proxy_idx.append((dev.network, pn, dev.id))
                except ValueError:
                    # Skip invalid proxy networks
                    fallback_idx.append((dev.network, dev.id))
            else:
                fallback_idx.append((dev.network, dev.id))
        # Sort by client prefixlen desc for longest-prefix match
        proxy_idx.sort(key=lambda t: t[0].prefixlen, reverse=True)
        fallback_idx.sort(key=lambda t: t[0].prefixlen, reverse=True)
        with self._idx_lock:
            self._proxy_index = proxy_idx
            self._fallback_index = fallback_idx
            self._id_index = id_index
            self._index_built_version = self._index_version
            import time

            self._last_refresh_time = time.time()
        self.clear_identity_cache()

    def _mark_dirty(self) -> None:
        """Mark indexes as stale; they will be lazily refreshed on next lookup."""
        with self._idx_lock:
            self._index_version += 1

    def _ensure_indexes_current(self) -> None:
        import time

        with self._idx_lock:
            need_refresh = self._index_built_version < self._index_version
            # Also refresh if enough time has passed (to detect external DB changes)
            time_since_refresh = time.time() - self._last_refresh_time
            if (
                not need_refresh and time_since_refresh > 0.5
            ):  # Refresh every 0.5 seconds
                need_refresh = True
        if need_refresh:
            # Rebuild indexes (will set built_version)
            self.refresh_indexes()

    def clear_identity_cache(self) -> None:
        try:
            self._identity_cache.clear()
        except Exception:
            pass  # Cache clear failed, will be cleared on next operation

    def ensure_group(
        self,
        name: str,
        description: str | None = None,
        *,
        realm: str | None = None,
        proxy_network: str | None = None,
        tacacs_profile: JsonDict | None = None,
        radius_profile: JsonDict | None = None,
        metadata: JsonDict | None = None,
    ) -> DeviceGroup:
        """Create the group if it does not exist or update metadata."""
        with self._lock:
            # Resolve realm id if provided
            realm_id: int | None = None
            if realm:
                realm_id = self.ensure_realm(realm)

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
                if realm_id is not None:
                    updates.append("realm_id = ?")
                    params.append(realm_id)
                if proxy_network is not None:
                    # ensure proxy exists and set proxy_id
                    proxy_id = self._ensure_proxy_for_network(proxy_network)
                    updates.append("proxy_id = ?")
                    params.append(proxy_id)
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
                    update_clause = ", ".join(updates)
                    query_sql = (
                        f"UPDATE device_groups SET {update_clause}, "
                        "updated_at = CURRENT_TIMESTAMP WHERE name = ?"
                    )
                    self._conn.execute(query_sql, params)
                    self._conn.commit()
                    self._mark_dirty()
                    result = self.get_group_by_name(name)  # refreshed row
                    if result is None:
                        raise RuntimeError(
                            f"Failed to retrieve group after update: {name}"
                        )
                    return result
                return self._row_to_group(row)

            # Insert new group; if proxy_network provided link via proxy_id
            proxy_id_val = None
            if proxy_network is not None:
                proxy_id_val = self._ensure_proxy_for_network(proxy_network)
            self._conn.execute(
                """
                INSERT INTO device_groups (name, description, realm_id, proxy_id, tacacs_profile, 
                                         radius_profile, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    description,
                    realm_id,
                    proxy_id_val,
                    self._json_dump(tacacs_profile),
                    self._json_dump(radius_profile),
                    self._json_dump(metadata),
                ),
            )
            self._conn.commit()
            self._mark_dirty()
            result = self.get_group_by_name(name)
            if result is None:
                raise RuntimeError(f"Failed to retrieve group after insert: {name}")
            return result

    # ------------------------------
    # Proxies management
    # ------------------------------
    def _ensure_proxy_for_network(self, network_cidr: str) -> int:
        """Ensure a proxy exists for the given CIDR. Returns proxy id.

        Names are derived as "proxy:<cidr>" if not existing.
        """
        # Validate network
        ip_net = ipaddress.ip_network(str(network_cidr), strict=False)
        network_s = str(ip_net)
        # Try by network first
        cur = self._conn.execute(
            "SELECT id FROM proxies WHERE network = ?",
            (network_s,),
        )
        row = cur.fetchone()
        if row:
            return int(row[0])
        # Insert
        # Pick a unique, human-readable name; avoid collisions with user-defined names
        # Use reserved prefix 'auto-proxy:' to reduce user collision risk
        base = f"auto-proxy:{network_s}"
        name = base
        attempt = 1
        while True:
            try:
                self._conn.execute(
                    "INSERT INTO proxies(name, network, metadata) VALUES(?, ?, ?)",
                    (name, network_s, None),
                )
                break
            except sqlite3.IntegrityError:
                # If name is taken, try with a numeric suffix; if network exists, we'll exit via fetch below
                name = f"{base}-{attempt}"
                attempt += 1
        self._conn.commit()
        cur = self._conn.execute(
            "SELECT id FROM proxies WHERE network = ?",
            (network_s,),
        )
        row = cur.fetchone()
        if not row:
            raise RuntimeError("Failed to create proxy")
        return int(row[0])

    def list_proxies(self) -> list[Proxy]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, name, network, metadata FROM proxies ORDER BY name"
            )
            rows = cur.fetchall()
        items: list[Proxy] = []
        for r in rows:
            try:
                net = ipaddress.ip_network(r["network"], strict=False)
            except Exception:
                continue
            items.append(
                Proxy(
                    id=int(r["id"]),
                    name=str(r["name"]),
                    network=net,
                    metadata=self._json_load(r["metadata"]),
                )
            )
        return items

    def get_proxy_by_id(self, proxy_id: int) -> Proxy | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, name, network, metadata FROM proxies WHERE id=?",
                (proxy_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        try:
            net = ipaddress.ip_network(row["network"], strict=False)
        except Exception:
            return None
        return Proxy(
            id=int(row["id"]),
            name=str(row["name"]),
            network=net,
            metadata=self._json_load(row["metadata"]),
        )

    def create_proxy(
        self, name: str, network: str, metadata: JsonDict | None = None
    ) -> Proxy:
        ip_net = ipaddress.ip_network(str(network), strict=False)
        # Prevent overlapping/duplicate proxy networks
        conflict = self._find_conflicting_proxy(ip_net, exclude_id=None)
        if conflict is not None:
            raise ValueError(
                f"Proxy network {ip_net} overlaps existing proxy '{conflict['name']}' {conflict['network']} (id={conflict['id']})"
            )
        with self._lock:
            self._conn.execute(
                "INSERT INTO proxies(name, network, metadata) VALUES(?, ?, ?)",
                (name, str(ip_net), self._json_dump(metadata or {})),
            )
            self._conn.commit()
            cur = self._conn.execute(
                "SELECT id, name, network, metadata FROM proxies WHERE name=?",
                (name,),
            )
            row = cur.fetchone()
        if not row:
            raise RuntimeError("Failed to create proxy")
        return Proxy(
            id=int(row["id"]),
            name=str(row["name"]),
            network=ipaddress.ip_network(row["network"], strict=False),
            metadata=self._json_load(row["metadata"]),
        )

    def update_proxy(
        self,
        proxy_id: int,
        *,
        name: str | None = None,
        network: str | None = None,
        metadata: JsonDict | None = None,
    ) -> Proxy | None:
        updates: list[str] = []
        params: list[Any] = []
        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if network is not None:
            ip_net = ipaddress.ip_network(str(network), strict=False)
            # Prevent overlapping/duplicate proxy networks
            conflict = self._find_conflicting_proxy(ip_net, exclude_id=proxy_id)
            if conflict is not None:
                raise ValueError(
                    f"Proxy network {ip_net} overlaps existing proxy '{conflict['name']}' {conflict['network']} (id={conflict['id']})"
                )
            updates.append("network = ?")
            params.append(str(ip_net))
        if metadata is not None:
            updates.append("metadata = ?")
            params.append(self._json_dump(metadata))
        if not updates:
            return self.get_proxy_by_id(proxy_id)
        params.append(proxy_id)
        with self._lock:
            clause = ", ".join(updates)
            self._conn.execute(
                f"UPDATE proxies SET {clause}, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                params,
            )
            self._conn.commit()
        return self.get_proxy_by_id(proxy_id)

    def delete_proxy(self, proxy_id: int) -> bool:
        with self._lock:
            # Unlink groups referencing this proxy
            self._conn.execute(
                "UPDATE device_groups SET proxy_id = NULL, updated_at=CURRENT_TIMESTAMP WHERE proxy_id = ?",
                (proxy_id,),
            )
            result = self._conn.execute(
                "DELETE FROM proxies WHERE id=?",
                (proxy_id,),
            )
            self._conn.commit()
            return result.rowcount > 0

    def _find_conflicting_proxy(
        self, ip_net: ipaddress._BaseNetwork, exclude_id: int | None
    ) -> dict[str, Any] | None:
        """Return an existing proxy dict that overlaps with ip_net, excluding exclude_id."""
        with self._lock:
            cur = self._conn.execute("SELECT id, name, network FROM proxies")
            rows = cur.fetchall()
        for r in rows:
            pid = int(r["id"])
            if exclude_id is not None and pid == int(exclude_id):
                continue
            try:
                other = ipaddress.ip_network(str(r["network"]), strict=False)
            except Exception:
                continue
            if ip_net.overlaps(other):
                return {"id": pid, "name": str(r["name"]), "network": str(other)}
        return None

    # Realms APIs
    def ensure_realm(self, name: str, description: str | None = None) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT id FROM realms WHERE name = ?", (name,))
            row = cur.fetchone()
            if row:
                return int(row[0])
            self._conn.execute(
                "INSERT INTO realms(name, description) VALUES(?, ?)",
                (name, description),
            )
            self._conn.commit()
            cur = self._conn.execute("SELECT id FROM realms WHERE name = ?", (name,))
            row = cur.fetchone()
            if not row:
                raise RuntimeError("Failed to create realm")
            return int(row[0])

    def list_realms(self) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, name, description FROM realms ORDER BY name"
            )
            return [dict(id=r[0], name=r[1], description=r[2]) for r in cur.fetchall()]

    def assign_group_to_realm(self, group_name: str, realm_name: str) -> None:
        realm_id = self.ensure_realm(realm_name)
        with self._lock:
            self._conn.execute(
                "UPDATE device_groups SET realm_id = ?, updated_at=CURRENT_TIMESTAMP WHERE name = ?",
                (realm_id, group_name),
            )
            self._conn.commit()

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
        proxy_id: int | None = None,
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
        if proxy_id is not None:
            updates.append("proxy_id = ?")
            params.append(int(proxy_id))

        if not updates:
            return self.get_group_by_id(group_id)

        params.append(group_id)
        with self._lock:
            # Use parameterized query to prevent SQL injection
            update_clause = ", ".join(updates)
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
        # validate name early to avoid storing unsafe values
        name = validate_device_name(name)

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
                    update_clause = ", ".join(updates)
                    query_sql = (
                        f"UPDATE devices SET {update_clause}, "
                        "updated_at = CURRENT_TIMESTAMP WHERE name = ? AND network = ?"
                    )
                    self._conn.execute(query_sql, params)
                    self._conn.commit()
                    self._mark_dirty()
                groups = self._load_groups()
                return self._row_to_device(row, groups)

            # Precompute range for potential large-scale indexes
            if network_obj.version == 6:
                start_int = None
                end_int = None
            else:
                start_int = int(network_obj.network_address)
                end_int = int(network_obj.broadcast_address)
            self._conn.execute(
                """
                INSERT INTO devices (name, network, network_start_int, network_end_int, tacacs_secret, radius_secret, 
                                     metadata, group_id)
                VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?)
                """,
                (
                    name,
                    str(network_obj),
                    start_int,
                    end_int,
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
        if row is None:
            raise RuntimeError(f"Failed to retrieve device after insert: {name}")
        return self._row_to_device(row, groups)

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
            # update range columns in tandem
            if network_obj.version == 4:
                updates.append("network_start_int = ?")
                params.append(int(network_obj.network_address))
                updates.append("network_end_int = ?")
                params.append(int(network_obj.broadcast_address))
        else:
            _ = None  # Network parsing failed or not provided

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
            update_clause = ", ".join(updates)
            query_sql = (
                f"UPDATE devices SET {update_clause}, "
                "updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            )
            self._conn.execute(query_sql, params)
            self._conn.commit()
        self._mark_dirty()

        return self.get_device_by_id(device_id)

    def delete_device(self, device_id: int) -> bool:
        with self._lock:
            result = self._conn.execute(
                "DELETE FROM devices WHERE id = ?",
                (device_id,),
            )
            self._conn.commit()
            deleted = result.rowcount > 0
        if deleted:
            self._mark_dirty()
        return deleted

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
        # Lazy refresh to avoid stale indexes after mutations
        self._ensure_indexes_current()
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        groups = self._load_groups()
        with self._lock:
            cur = self._conn.execute("SELECT * FROM devices")
            rows = cur.fetchall()

        # Select best match: longest prefix; tie-breaker prefers groups with tacacs_secret
        best: DeviceRecord | None = None
        best_pl = -1
        best_has_secret = False

        for row in rows:
            device = self._row_to_device(row, groups)
            # Skip disabled devices to honor runtime toggles
            try:
                if getattr(device, "enabled", True) is False:
                    continue
            except Exception:
                # If attribute missing, assume enabled
                pass
            try:
                if ip_obj not in device.network:
                    continue
            except Exception:
                continue
            pl = int(device.network.prefixlen)
            grp = device.group
            # Determine if group carries an explicit TACACS secret
            has_secret = False
            if grp is not None:
                try:
                    if getattr(grp, "tacacs_secret", None):
                        has_secret = True
                    else:
                        md = getattr(grp, "metadata", {}) or {}
                        if isinstance(md, dict) and md.get("tacacs_secret"):
                            has_secret = True
                except Exception:
                    has_secret = False

            if pl > best_pl or (pl == best_pl and not best_has_secret and has_secret):
                best = device
                best_pl = pl
                best_has_secret = has_secret

        return best

    def find_device_for_identity(
        self, client_ip: str, proxy_ip: str | None
    ) -> DeviceRecord | None:
        """Resolve a device for (client_ip, proxy_ip) with proxy-aware fallback.

        Order:
          1) Exact: client_ip in device.network AND proxy_ip in device.group.proxy_network
          2) Fallback: client_ip in device.network AND device.group.proxy_network IS NULL
          3) None
        Longest-prefix match wins within each tier.
        """
        # If proxies disabled, ignore proxy_ip and do simple lookup
        if not getattr(self, "proxy_enabled", True):
            return self.find_device_for_ip(client_ip)
        # Lazy refresh to avoid stale indexes after mutations
        self._ensure_indexes_current()
        # Normalize proxy value: treat "none", "null", "" as None for cache and matching
        norm_proxy: str | None
        if proxy_ip is None:
            norm_proxy = None
        else:
            p = str(proxy_ip).strip().lower()
            norm_proxy = None if p in ("none", "null", "") else proxy_ip
        try:
            client = ipaddress.ip_address(client_ip)
        except ValueError:
            return None

        proxy_addr = None
        if norm_proxy:
            try:
                proxy_addr = ipaddress.ip_address(norm_proxy)
            except ValueError:
                proxy_addr = None

        # Cache lookup
        cache_key = (str(client), str(proxy_addr) if proxy_addr is not None else None)
        cached = self._identity_cache.get(cache_key)
        if cached is not None:
            with self._idx_lock:
                return self._id_index.get(cached)

        with self._idx_lock:
            proxy_idx = list(self._proxy_index)
            fallback_idx = list(self._fallback_index)
            id_index = dict(self._id_index)

        # Optional SQL pre-filter by numeric range to reduce scanned candidates
        candidate_rows = None
        try:
            client_int = int(client)
            with self._lock:
                cur = self._conn.execute(
                    "SELECT * FROM devices WHERE network_start_int IS NOT NULL AND network_end_int IS NOT NULL AND network_start_int <= ? AND network_end_int >= ?",
                    (client_int, client_int),
                )
                candidate_rows = cur.fetchall()
        except Exception:
            candidate_rows = None

        chosen_id: int | None = None
        if candidate_rows is not None:
            # Build device objects for candidates only
            groups = self._load_groups()
            devices: list[DeviceRecord] = [
                self._row_to_device(row, groups) for row in candidate_rows
            ]
            # First exact matches
            if proxy_addr is not None:
                exact = []
                for d in devices:
                    grp = d.group
                    pn = getattr(grp, "proxy_network", None) if grp else None
                    if pn:
                        try:
                            if (
                                client in d.network
                                and proxy_addr
                                in ipaddress.ip_network(str(pn), strict=False)
                            ):
                                exact.append(d)
                        except ValueError:
                            pass  # IP address parsing failed, skip this device
                if exact:
                    chosen = max(exact, key=lambda d: d.network.prefixlen)
                    chosen_id = chosen.id
            if chosen_id is None:
                fb = [
                    d
                    for d in devices
                    if getattr(d.group, "proxy_network", None) in (None, "")
                    and client in d.network
                ]
                if fb:
                    chosen = max(fb, key=lambda d: d.network.prefixlen)
                    chosen_id = chosen.id
        else:
            if proxy_addr is not None:
                for net, pnet, dev_id in proxy_idx:
                    if client in net and proxy_addr in pnet:
                        chosen_id = dev_id
                        break
            if chosen_id is None:
                for net, dev_id in fallback_idx:
                    if client in net:
                        chosen_id = dev_id
                        break
        if chosen_id is not None:
            self._identity_cache.set(cache_key, chosen_id)
            return id_index.get(chosen_id)
        return None

    # ------------------------------------------------------------------
    # Context management
    # ------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> DeviceStore:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
