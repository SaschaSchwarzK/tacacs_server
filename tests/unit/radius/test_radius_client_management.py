"""Unit tests for RADIUS client management helpers."""

import ipaddress
from types import SimpleNamespace

from tacacs_server.radius.server import RadiusClient


def test_add_single_host_client_lookup():
    client = RadiusClient(
        network=ipaddress.ip_network("192.0.2.10/32"), secret="s", name="host1"
    )
    assert client.contains("192.0.2.10")
    assert not client.contains("192.0.2.11")


def test_add_network_client_lookup_and_specificity():
    broad = RadiusClient(
        network=ipaddress.ip_network("192.0.2.0/24"), secret="s", name="net"
    )
    narrow = RadiusClient(
        network=ipaddress.ip_network("192.0.2.128/25"), secret="s2", name="subnet"
    )
    ip = "192.0.2.130"
    assert broad.contains(ip) and narrow.contains(ip)
    # Most specific network should be chosen manually via prefix length comparison
    chosen = max([broad, narrow], key=lambda c: c.network.prefixlen)
    assert chosen is narrow


def test_client_group_and_allowed_user_groups():
    client = RadiusClient(
        network=ipaddress.ip_network("10.0.0.0/24"),
        secret="s",
        name="c1",
        group="netops",
        allowed_user_groups=["admins", "netops"],
    )
    assert client.group == "netops"
    assert "admins" in client.allowed_user_groups


def test_client_metadata_attributes_storage():
    attrs = {"NAS-Identifier": "nas1", "Location": "dc1"}
    client = RadiusClient(
        network=ipaddress.ip_network("203.0.113.5/32"),
        secret="s",
        name="cmeta",
        attributes=attrs,
    )
    assert client.attributes["Location"] == "dc1"


def test_client_refresh_from_device_store(monkeypatch):
    """Ensure clients can be refreshed from a device store-like object."""
    devices = [
        SimpleNamespace(
            network="198.51.100.0/24",
            tacacs_secret="sec1",
            name="devnet",
            metadata={"group": "infra"},
            allowed_user_groups=["ops"],
        ),
        SimpleNamespace(
            network="198.51.100.10/32",
            tacacs_secret="sec2",
            name="devhost",
            metadata={"group": "host"},
            allowed_user_groups=["ops", "support"],
        ),
    ]

    class FakeStore:
        def list_all_clients(self):
            return devices

    store = FakeStore()
    clients = []
    for dev in store.list_all_clients():
        net = ipaddress.ip_network(dev.network, strict=False)
        clients.append(
            RadiusClient(
                network=net,
                secret=dev.tacacs_secret,
                name=dev.name,
                group=dev.metadata.get("group"),
                allowed_user_groups=list(dev.allowed_user_groups),
                attributes={"Device-Name": dev.name},
            )
        )

    # Lookup by IP should find the more specific entry
    ip = "198.51.100.10"
    containing = [c for c in clients if c.contains(ip)]
    assert len(containing) == 2
    best = max(containing, key=lambda c: c.network.prefixlen)
    assert best.name == "devhost"


# Additional explicit tests for requested scenarios
def test_add_single_host_client():
    client = RadiusClient(
        network=ipaddress.ip_network("10.0.0.5/32"), secret="s", name="single"
    )
    assert client.contains("10.0.0.5")
    assert not client.contains("10.0.0.6")


def test_add_network_cidr_client():
    client = RadiusClient(
        network=ipaddress.ip_network("10.0.0.0/24"), secret="s", name="net"
    )
    assert client.contains("10.0.0.1")
    assert client.contains("10.0.0.255")
    assert not client.contains("10.0.1.1")


def test_network_specificity_matching():
    broad = RadiusClient(
        network=ipaddress.ip_network("10.0.0.0/16"), secret="s", name="broad"
    )
    narrow = RadiusClient(
        network=ipaddress.ip_network("10.0.1.0/24"), secret="s2", name="narrow"
    )
    ip = "10.0.1.5"
    matches = [c for c in (broad, narrow) if c.contains(ip)]
    assert matches and max(matches, key=lambda c: c.network.prefixlen) is narrow


def test_client_refresh_from_device_store_explicit(monkeypatch):
    devices = [
        SimpleNamespace(
            network="10.1.0.0/16",
            tacacs_secret="s1",
            name="dev1",
            metadata={"group": "a"},
            allowed_user_groups=["ops"],
        ),
        SimpleNamespace(
            network="10.1.1.0/24",
            tacacs_secret="s2",
            name="dev2",
            metadata={"group": "b"},
            allowed_user_groups=["ops"],
        ),
    ]

    class FakeStore:
        def list_all_clients(self):
            return devices

    store = FakeStore()
    clients = []
    for dev in store.list_all_clients():
        clients.append(
            RadiusClient(
                network=ipaddress.ip_network(dev.network, strict=False),
                secret=dev.tacacs_secret,
                name=dev.name,
                group=dev.metadata.get("group"),
                allowed_user_groups=list(dev.allowed_user_groups),
            )
        )
    ip = "10.1.1.20"
    best = max(
        [c for c in clients if c.contains(ip)], key=lambda c: c.network.prefixlen
    )
    assert best.name == "dev2"


def test_lookup_client_by_ip():
    clients = [
        RadiusClient(
            network=ipaddress.ip_network("192.0.2.0/24"), secret="s", name="net"
        ),
        RadiusClient(
            network=ipaddress.ip_network("192.0.2.50/32"), secret="s2", name="host"
        ),
    ]
    ip = "192.0.2.50"
    matches = [c for c in clients if c.contains(ip)]
    assert matches
    best = max(matches, key=lambda c: c.network.prefixlen)
    assert best.name == "host"
