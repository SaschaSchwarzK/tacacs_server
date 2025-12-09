"""SQLite-backed device inventory for TACACS+ and RADIUS."""
# mypy: ignore-errors

from __future__ import annotations

import ipaddress
import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from alembic.config import Config
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from alembic import command
from tacacs_server.db.engine import Base, get_session_factory, session_scope
from tacacs_server.devices.models import (
    DeviceGroupModel,
    DeviceModel,
    ProxyModel,
    RealmModel,
)
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
        self._session_factory = get_session_factory(str(self.db_path))
        self._engine = getattr(self._session_factory, "bind", None) or getattr(
            self._session_factory, "engine", None
        )
        if self._engine is None:
            raise RuntimeError("Failed to initialize device store engine")
        Base.metadata.create_all(self._engine)
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
        # Close the underlying engine; log on failure
        with self._lock:
            try:
                if self._engine:
                    self._engine.dispose()
            except Exception as exc:
                logger.warning("DeviceStore close failed: %s", exc)

    def reload(self) -> None:
        """Recreate the session factory after maintenance."""
        with self._lock:
            try:
                if self._engine:
                    self._engine.dispose()
            except Exception:
                pass
            self._session_factory = get_session_factory(str(self.db_path))
            self._engine = getattr(self._session_factory, "bind", None) or getattr(
                self._session_factory, "engine", None
            )
            if self._engine is None:
                raise RuntimeError("Failed to reload device store engine")
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
        # Prefer Alembic migrations when available; ensure tables are present afterward
        self._run_alembic_migrations()
        with self._lock:
            Base.metadata.create_all(self._engine)

    def _run_alembic_migrations(self) -> bool:
        """Run Alembic migrations if the tooling/config is available."""
        project_root = Path(__file__).resolve().parents[2]
        ini_path = project_root / "alembic.ini"
        script_location = project_root / "alembic"
        if not ini_path.exists() or not script_location.exists():
            return False

        cfg = Config(str(ini_path))
        cfg.set_main_option("script_location", str(script_location))
        cfg.set_main_option("sqlalchemy.url", f"sqlite:///{self.db_path}")
        try:
            command.upgrade(cfg, "head")
            return True
        except Exception as exc:
            logger.warning(
                "Alembic migration failed; falling back to legacy schema handling",
                error=str(exc),
            )
            return False

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

    def _model_to_group(self, row: Any) -> DeviceGroup:
        def _get(row_obj: Any, key: str, default: Any = None) -> Any:
            # Prefer direct dict access for ORM objects to avoid loader calls
            if hasattr(row_obj, "_sa_instance_state"):
                raw = getattr(row_obj, "__dict__", {})
                if key in raw:
                    return raw.get(key, default)
                return default
            if hasattr(row_obj, key):
                return getattr(row_obj, key)
            if isinstance(row_obj, dict):
                return row_obj.get(key, default)
            try:
                return row_obj[key]
            except Exception:
                return default

        metadata = self._json_load(_get(row, "metadata_json"))
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
            id=_get(row, "id"),
            name=_get(row, "name"),
            description=_get(row, "description"),
            realm_id=_get(row, "realm_id"),
            proxy_network=_get(row, "proxy_network"),
            tacacs_profile=self._json_load(_get(row, "tacacs_profile")),
            radius_profile=self._json_load(_get(row, "radius_profile")),
            metadata=metadata,
            tacacs_secret=tacacs_secret,
            radius_secret=radius_secret,
            device_config=device_config,
            allowed_user_groups=allowed_groups,
        )

    def _row_to_group(self, row) -> DeviceGroup:
        # Backwards compatibility for legacy sqlite access
        return self._model_to_group(row)

    def _row_to_device(self, row, groups: dict[int, DeviceGroup]) -> DeviceRecord:
        network = ipaddress.ip_network(row["network"], strict=False)
        group = groups.get(row["group_id"])
        return DeviceRecord(
            id=row["id"],
            name=row["name"],
            network=network,
            group=group,
            tacacs_secret=getattr(row, "tacacs_secret", None),
            radius_secret=getattr(row, "radius_secret", None),
            metadata=self._json_load(row["metadata_json"]),
        )

    def _model_to_device(
        self, row: Any, groups: dict[int, DeviceGroup]
    ) -> DeviceRecord:
        network = ipaddress.ip_network(row.network, strict=False)
        group = groups.get(row.group_id)
        return DeviceRecord(
            id=row.id,
            name=row.name,
            network=network,
            group=group,
            tacacs_secret=getattr(row, "tacacs_secret", None),
            radius_secret=getattr(row, "radius_secret", None),
            metadata=self._json_load(getattr(row, "metadata_json", None)),
        )

    def _post_process_device(
        self, device: DeviceRecord, groups: dict[int, DeviceGroup]
    ) -> DeviceRecord:
        """
        Hook for subclasses/tests to adjust DeviceRecord without altering core logic.

        Legacy compatibility: if _row_to_device is overridden, invoke it with a
        lightweight mapping derived from the already-built DeviceRecord.
        """
        if self._row_to_device.__func__ is not DeviceStore._row_to_device:  # type: ignore[attr-defined]
            try:
                mapped_row = {
                    "id": device.id,
                    "name": device.name,
                    "network": str(device.network),
                    "group_id": getattr(device.group, "id", None)
                    if device.group
                    else None,
                    "tacacs_secret": device.tacacs_secret,
                    "radius_secret": device.radius_secret,
                    "metadata_json": self._json_dump(device.metadata),
                }
                return self._row_to_device(mapped_row, groups)
            except Exception:
                return device
        return device

    def _load_groups(self) -> dict[int, DeviceGroup]:
        # Join proxies so that DeviceGroup.proxy_network reflects proxy network from proxies table
        with self._lock, session_scope(self._session_factory) as session:
            stmt = (
                select(
                    DeviceGroupModel.id,
                    DeviceGroupModel.name,
                    DeviceGroupModel.description,
                    DeviceGroupModel.realm_id,
                    ProxyModel.network.label("proxy_network"),
                    DeviceGroupModel.tacacs_profile,
                    DeviceGroupModel.radius_profile,
                    DeviceGroupModel.metadata_json,
                )
                .select_from(DeviceGroupModel)
                .join(
                    ProxyModel, ProxyModel.id == DeviceGroupModel.proxy_id, isouter=True
                )
            )
            rows = session.execute(stmt).mappings().all()
            groups = {row["id"]: self._model_to_group(row) for row in rows}
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
        with self._lock, session_scope(self._session_factory) as session:
            rows = session.query(DeviceModel).all()
        proxy_idx: list[tuple[ipaddress._BaseNetwork, ipaddress._BaseNetwork, int]] = []
        fallback_idx: list[tuple[ipaddress._BaseNetwork, int]] = []
        id_index: dict[int, DeviceRecord] = {}
        for row in rows:
            dev = self._model_to_device(row, groups)
            dev = self._post_process_device(dev, groups)
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
        with self._lock, session_scope(self._session_factory) as session:
            realm_id: int | None = None
            if realm:
                realm_id = self.ensure_realm(realm)

            proxy_id_val: int | None = None
            proxy_net_value = None
            if proxy_network is not None:
                proxy_id_val = self._ensure_proxy_for_network(proxy_network)
                proxy_net_value = proxy_network

            existing = session.execute(
                select(DeviceGroupModel).where(DeviceGroupModel.name == name)
            ).scalar_one_or_none()
            if existing:
                if description is not None:
                    existing.description = description
                if realm_id is not None:
                    existing.realm_id = realm_id
                if proxy_id_val is not None:
                    existing.proxy_id = proxy_id_val
                    existing.proxy_network = proxy_net_value
                if tacacs_profile is not None:
                    existing.tacacs_profile = self._json_dump(tacacs_profile)
                if radius_profile is not None:
                    existing.radius_profile = self._json_dump(radius_profile)
                if metadata is not None:
                    existing.metadata_json = self._json_dump(metadata)
                session.flush()
                session.refresh(existing)
                self._mark_dirty()
                return self._model_to_group(existing)

            new_group = DeviceGroupModel(
                name=name,
                description=description,
                realm_id=realm_id,
                proxy_id=proxy_id_val,
                proxy_network=proxy_net_value,
                tacacs_profile=self._json_dump(tacacs_profile),
                radius_profile=self._json_dump(radius_profile),
                metadata_json=self._json_dump(metadata),
            )
            session.add(new_group)
            session.flush()
            session.refresh(new_group)
        self._mark_dirty()
        return self._model_to_group(new_group)

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
        with self._lock, session_scope(self._session_factory) as session:
            existing = (
                session.query(ProxyModel)
                .filter(ProxyModel.network == network_s)
                .one_or_none()
            )
            if existing:
                return int(existing.id)

            base = f"auto-proxy:{network_s}"
            name = base
            attempt = 1
            while True:
                try:
                    proxy = ProxyModel(name=name, network=network_s, metadata_json=None)
                    session.add(proxy)
                    session.flush()
                    session.refresh(proxy)
                    return int(proxy.id)
                except IntegrityError:
                    session.rollback()
                    name = f"{base}-{attempt}"
                    attempt += 1

    def list_proxies(self) -> list[Proxy]:
        with self._lock, session_scope(self._session_factory) as session:
            rows = session.query(ProxyModel).order_by(ProxyModel.name).all()
        items: list[Proxy] = []
        for r in rows:
            try:
                net = ipaddress.ip_network(r.network, strict=False)
            except Exception:
                continue
            items.append(
                Proxy(
                    id=int(r.id),
                    name=r.name,
                    network=net,
                    metadata=self._json_load(r.metadata_json),
                )
            )
        return items

    def get_proxy_by_id(self, proxy_id: int) -> Proxy | None:
        with self._lock, session_scope(self._session_factory) as session:
            proxy = session.get(ProxyModel, proxy_id)
        if not proxy:
            return None
        try:
            net = ipaddress.ip_network(proxy.network, strict=False)
        except Exception:
            return None
        return Proxy(
            id=int(proxy.id),
            name=proxy.name,
            network=net,
            metadata=self._json_load(proxy.metadata_json),
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
        with self._lock, session_scope(self._session_factory) as session:
            proxy = ProxyModel(
                name=name,
                network=str(ip_net),
                metadata_json=self._json_dump(metadata or {}),
            )
            session.add(proxy)
            session.flush()
            session.refresh(proxy)
        return Proxy(
            id=int(proxy.id),
            name=proxy.name,
            network=ipaddress.ip_network(proxy.network, strict=False),
            metadata=self._json_load(proxy.metadata_json),
        )

    def update_proxy(
        self,
        proxy_id: int,
        *,
        name: str | None = None,
        network: str | None = None,
        metadata: JsonDict | None = None,
    ) -> Proxy | None:
        with self._lock, session_scope(self._session_factory) as session:
            proxy = session.get(ProxyModel, proxy_id)
            if not proxy:
                return None
            if name is not None:
                proxy.name = name
            if network is not None:
                ip_net = ipaddress.ip_network(str(network), strict=False)
                conflict = self._find_conflicting_proxy(ip_net, exclude_id=proxy_id)
                if conflict is not None:
                    raise ValueError(
                        f"Proxy network {ip_net} overlaps existing proxy '{conflict['name']}' {conflict['network']} (id={conflict['id']})"
                    )
                proxy.network = str(ip_net)
            if metadata is not None:
                proxy.metadata_json = self._json_dump(metadata)
            session.flush()
            session.refresh(proxy)
        return self.get_proxy_by_id(proxy_id)

    def delete_proxy(self, proxy_id: int) -> bool:
        with self._lock, session_scope(self._session_factory) as session:
            # Unlink groups referencing this proxy
            session.execute(
                DeviceGroupModel.__table__.update()
                .where(DeviceGroupModel.proxy_id == proxy_id)
                .values(proxy_id=None, proxy_network=None)
            )
            deleted = session.execute(
                ProxyModel.__table__.delete().where(ProxyModel.id == proxy_id)
            )
        self._mark_dirty()
        return bool(deleted.rowcount)

    def _find_conflicting_proxy(
        self, ip_net: ipaddress._BaseNetwork, exclude_id: int | None
    ) -> dict[str, Any] | None:
        """Return an existing proxy dict that overlaps with ip_net, excluding exclude_id."""
        with self._lock, session_scope(self._session_factory) as session:
            rows = session.query(ProxyModel).all()
        for r in rows:
            pid = int(r.id)
            if exclude_id is not None and pid == int(exclude_id):
                continue
            try:
                other = ipaddress.ip_network(str(r.network), strict=False)
            except Exception:
                continue
            if ip_net.overlaps(other):
                return {"id": pid, "name": str(r.name), "network": str(other)}
        return None

    # Realms APIs
    def ensure_realm(self, name: str, description: str | None = None) -> int:
        with self._lock, session_scope(self._session_factory) as session:
            existing = (
                session.query(RealmModel).filter(RealmModel.name == name).one_or_none()
            )
            if existing:
                return int(existing.id)
            realm = RealmModel(name=name, description=description or "")
            session.add(realm)
            session.flush()
            session.refresh(realm)
            return int(realm.id)

    def list_realms(self) -> list[dict[str, Any]]:
        with self._lock, session_scope(self._session_factory) as session:
            rows = session.query(RealmModel).order_by(RealmModel.name).all()
            return [
                {"id": int(r.id), "name": r.name, "description": r.description}
                for r in rows
            ]

    def assign_group_to_realm(self, group_name: str, realm_name: str) -> None:
        realm_id = self.ensure_realm(realm_name)
        with self._lock, session_scope(self._session_factory) as session:
            session.execute(
                DeviceGroupModel.__table__.update()
                .where(DeviceGroupModel.name == group_name)
                .values(realm_id=realm_id, updated_at=datetime.utcnow())
            )

    def get_group_by_name(self, name: str) -> DeviceGroup | None:
        with self._lock, session_scope(self._session_factory) as session:
            row = session.execute(
                select(DeviceGroupModel, ProxyModel.network.label("proxy_network"))
                .join(
                    ProxyModel, ProxyModel.id == DeviceGroupModel.proxy_id, isouter=True
                )
                .where(DeviceGroupModel.name == name)
            ).first()
        if not row:
            return None
        model = row[0]
        if row[1] is not None:
            model.proxy_network = row[1]
        return self._model_to_group(model)

    def get_group_by_id(self, group_id: int) -> DeviceGroup | None:
        with self._lock, session_scope(self._session_factory) as session:
            row = session.execute(
                select(DeviceGroupModel, ProxyModel.network.label("proxy_network"))
                .join(
                    ProxyModel, ProxyModel.id == DeviceGroupModel.proxy_id, isouter=True
                )
                .where(DeviceGroupModel.id == group_id)
            ).first()
        if not row:
            return None
        model = row[0]
        if row[1] is not None:
            model.proxy_network = row[1]
        return self._model_to_group(model)

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
        with self._lock, session_scope(self._session_factory) as session:
            grp = session.get(DeviceGroupModel, group_id)
            if not grp:
                return None
            if name is not None:
                grp.name = name
            if description is not None:
                grp.description = description
            if tacacs_profile is not None:
                grp.tacacs_profile = self._json_dump(tacacs_profile)
            if radius_profile is not None:
                grp.radius_profile = self._json_dump(radius_profile)
            if metadata is not None:
                grp.metadata_json = self._json_dump(metadata)
            if proxy_id is not None:
                grp.proxy_id = int(proxy_id)
            session.flush()
            session.refresh(grp)
        return self.get_group_by_id(group_id)

    def delete_group(self, group_id: int, *, cascade: bool = False) -> bool:
        """Delete a device group.
        If cascade is False and devices exist, raise ValueError.
        """
        with self._lock, session_scope(self._session_factory) as session:
            count_row = session.execute(
                select(func.count())
                .select_from(DeviceModel)
                .where(DeviceModel.group_id == group_id)
            ).scalar()
            device_count = count_row or 0
            if device_count and not cascade:
                raise ValueError("Group is in use by one or more devices")
            if device_count and cascade:
                session.execute(
                    DeviceModel.__table__.delete().where(
                        DeviceModel.group_id == group_id
                    )
                )
        with self._lock, session_scope(self._session_factory) as session:
            deleted = session.execute(
                DeviceGroupModel.__table__.delete().where(
                    DeviceGroupModel.id == group_id
                )
            )
        self._mark_dirty()
        return bool(deleted.rowcount)

    # ------------------------------------------------------------------
    # Device operations
    # ------------------------------------------------------------------
    def list_devices(self) -> list[DeviceRecord]:
        groups = self._load_groups()
        with self._lock, session_scope(self._session_factory) as session:
            rows = session.query(DeviceModel).order_by(DeviceModel.name).all()
        return [self._model_to_device(row, groups) for row in rows]

    def list_devices_by_group(self, group_id: int) -> list[DeviceRecord]:
        groups = self._load_groups()
        with self._lock, session_scope(self._session_factory) as session:
            rows = (
                session.query(DeviceModel)
                .where(DeviceModel.group_id == group_id)
                .order_by(DeviceModel.name)
                .all()
            )
        return [self._model_to_device(row, groups) for row in rows]

    def get_device_by_id(self, device_id: int) -> DeviceRecord | None:
        groups = self._load_groups()
        with self._lock, session_scope(self._session_factory) as session:
            row = session.get(DeviceModel, device_id)
        return self._model_to_device(row, groups) if row else None

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
        with self._lock, session_scope(self._session_factory) as session:
            existing = (
                session.query(DeviceModel)
                .filter(
                    DeviceModel.name == name, DeviceModel.network == str(network_obj)
                )
                .one_or_none()
            )
            if existing:
                if group_id is not None:
                    existing.group_id = group_id
                session.flush()
                session.refresh(existing)
                self._mark_dirty()
                groups = self._load_groups()
                return self._model_to_device(existing, groups)

            if network_obj.version in (4, 6) and network_obj.prefixlen in (32, 128):
                start_int = end_int = int(network_obj.network_address)
            else:
                start_int = int(network_obj.network_address)
                end_int = int(network_obj.broadcast_address)

            device = DeviceModel(
                name=name,
                network=str(network_obj),
                network_start_int=start_int,
                network_end_int=end_int,
                group_id=group_id,
            )
            session.add(device)
            session.flush()
            session.refresh(device)
        groups = self._load_groups()
        return self._model_to_device(device, groups)

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
        if group is not None and clear_group:
            raise ValueError("Cannot set group and clear it simultaneously")

        with self._lock, session_scope(self._session_factory) as session:
            device = session.get(DeviceModel, device_id)
            if not device:
                return None

            if name is not None:
                device.name = name

            if network is not None:
                network_obj = ipaddress.ip_network(str(network), strict=False)
                device.network = str(network_obj)
                if network_obj.version in (4, 6) and network_obj.prefixlen in (32, 128):
                    start_int = end_int = int(network_obj.network_address)
                else:
                    start_int = int(network_obj.network_address)
                    end_int = int(network_obj.broadcast_address)
                device.network_start_int = start_int
                device.network_end_int = end_int

            if group is not None:
                group_obj = self.ensure_group(group)
                device.group_id = group_obj.id
            if clear_group:
                device.group_id = None

            session.flush()
            session.refresh(device)
        self._mark_dirty()
        return self.get_device_by_id(device_id)

    def delete_device(self, device_id: int) -> bool:
        with self._lock, session_scope(self._session_factory) as session:
            deleted = session.execute(
                DeviceModel.__table__.delete().where(DeviceModel.id == device_id)
            ).rowcount
        if deleted:
            self._mark_dirty()
        return bool(deleted)

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
        with self._lock, session_scope(self._session_factory) as session:
            row = (
                session.query(DeviceModel)
                .filter(DeviceModel.network == str(network_obj))
                .one_or_none()
            )
        return self._model_to_device(row, groups) if row else None

    def find_device_for_ip(self, ip: str) -> DeviceRecord | None:
        """Resolve a device record for the given client IP address."""
        # Lazy refresh to avoid stale indexes after mutations
        self._ensure_indexes_current()
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None

        # Select best match: longest prefix; tie-breaker prefers groups with tacacs_secret
        best: DeviceRecord | None = None
        best_pl = -1
        best_has_secret = False

        with self._idx_lock:
            id_index = dict(self._id_index)
        groups = self._load_groups()

        for dev_id, device in id_index.items():
            # device may not have group populated if indexes stale; refresh if needed
            if device.group is None and device.group_id is not None:
                grp = groups.get(device.group_id)
                if grp:
                    device = DeviceRecord(
                        id=device.id,
                        name=device.name,
                        network=device.network,
                        group=grp,
                        tacacs_secret=device.tacacs_secret,
                        radius_secret=device.radius_secret,
                        metadata=device.metadata,
                    )
            # Skip disabled devices if present on record (used in tests)
            try:
                if getattr(device, "enabled", True) is False:
                    continue
            except Exception:
                pass
            try:
                if ip_obj not in device.network:
                    continue
            except Exception:
                continue
            pl = int(device.network.prefixlen)
            grp = device.group
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
        with self._idx_lock:
            cached = self._identity_cache.get(cache_key)
            if cached is not None:
                return self._id_index.get(cached)

        with self._idx_lock:
            proxy_idx = list(self._proxy_index)
            fallback_idx = list(self._fallback_index)
            id_index = dict(self._id_index)

        # Optional SQL pre-filter by numeric range to reduce scanned candidates
        candidate_rows = None
        try:
            client_int = int(client)
            with self._lock, session_scope(self._session_factory) as session:
                candidate_rows = (
                    session.query(DeviceModel)
                    .filter(
                        DeviceModel.network_start_int.isnot(None),
                        DeviceModel.network_end_int.isnot(None),
                        DeviceModel.network_start_int <= client_int,
                        DeviceModel.network_end_int >= client_int,
                    )
                    .all()
                )
        except Exception:
            candidate_rows = None

        chosen_id: int | None = None
        if candidate_rows is not None:
            # Build device objects for candidates only
            groups = self._load_groups()
            devices: list[DeviceRecord] = [
                self._model_to_device(row, groups) for row in candidate_rows
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
            with self._idx_lock:
                self._identity_cache.set(cache_key, chosen_id)
            return id_index.get(chosen_id)
        return None

    # ------------------------------------------------------------------
    # Context management
    # ------------------------------------------------------------------
    def close(self) -> None:
        with self._lock:
            try:
                if self._engine:
                    self._engine.dispose()
            except Exception:
                pass

    def __enter__(self) -> DeviceStore:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
