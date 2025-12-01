import ipaddress
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from tacacs_server.utils.logger import get_logger

logger = get_logger("tacacs_server.radius.client", component="radius")


@dataclass
class RadiusClient:
    """Resolved RADIUS client configuration (single host or network)."""

    network: ipaddress._BaseNetwork
    secret: str
    name: str
    group: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    allowed_user_groups: list[str] = field(default_factory=list)

    def contains(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return ip_obj in self.network

    @property
    def secret_bytes(self) -> bytes:
        return self.secret.encode("utf-8")


def _sort_clients(clients: Iterable[RadiusClient]) -> list[RadiusClient]:
    return sorted(clients, key=lambda entry: entry.network.prefixlen, reverse=True)


def add_radius_client(
    clients: list[RadiusClient],
    client_lock: threading.RLock,
    network: str,
    secret: str,
    name: str | None = None,
    *,
    group: str | None = None,
    attributes: dict[str, Any] | None = None,
    allowed_user_groups: list[str] | None = None,
) -> bool:
    """Add a RADIUS client by IP or network."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        logger.error(
            "Invalid RADIUS client network",
            event="radius.client.invalid_network",
            network=network,
        )
        return False

    client = RadiusClient(
        network=net,
        secret=secret,
        name=name or str(net),
        group=group,
        attributes=attributes or {},
        allowed_user_groups=list(allowed_user_groups or []),
    )
    with client_lock:
        clients.append(client)
        clients[:] = _sort_clients(clients)
    logger.debug(
        "Added RADIUS client",
        event="radius.client.added",
        client_name=client.name,
        network=str(client.network),
        group=group,
    )
    return True


def load_radius_clients(
    clients: list[RadiusClient],
    client_lock: threading.RLock,
    new_clients: list[RadiusClient],
) -> None:
    """Replace current clients with pre-built entries (e.g. from DeviceStore)."""
    with client_lock:
        clients[:] = _sort_clients(new_clients)
    logger.debug(
        "Loaded RADIUS client definitions",
        event="radius.client.loaded",
        count=len(new_clients),
    )


def refresh_radius_clients(
    clients: list[RadiusClient],
    client_lock: threading.RLock,
    client_configs: Iterable[Any],
) -> None:
    """Rebuild client list from iterable configs (network, secret, etc.)."""
    new_clients: list[RadiusClient] = []
    for cfg in client_configs:
        try:
            network = getattr(cfg, "network")
            secret = getattr(cfg, "secret")
            name = getattr(cfg, "name", str(network))
            group = getattr(cfg, "group", None)
            attributes = dict(getattr(cfg, "attributes", {}) or {})
            allowed_user_groups = list(getattr(cfg, "allowed_user_groups", []) or [])
        except AttributeError as exc:
            logger.warning(
                "Skipping invalid RADIUS client config",
                event="radius.client.config_invalid",
                config=str(cfg),
                error=str(exc),
            )
            continue
        new_clients.append(
            RadiusClient(
                network=network,
                secret=secret,
                name=name,
                group=group,
                attributes=attributes,
                allowed_user_groups=allowed_user_groups,
            )
        )
    with client_lock:
        clients[:] = _sort_clients(new_clients)
    logger.debug(
        "Refreshed RADIUS client definitions",
        event="radius.client.refreshed",
        count=len(new_clients),
    )


def lookup_client_by_ip(
    clients: list[RadiusClient], client_lock: threading.RLock, ip: str
) -> RadiusClient | None:
    """Find a matching client for the given IP (most specific network first)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        logger.warning(
            "Received RADIUS packet from invalid IP",
            event="radius.packet.invalid_ip",
            client_ip=ip,
        )
        return None
    with client_lock:
        for client in clients:
            if ip_obj in client.network:
                return client
    return None


__all__ = [
    "RadiusClient",
    "add_radius_client",
    "load_radius_clients",
    "refresh_radius_clients",
    "lookup_client_by_ip",
]
