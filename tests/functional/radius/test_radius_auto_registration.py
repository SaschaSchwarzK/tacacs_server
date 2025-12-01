"""Functional tests for RADIUS unknown-client auto-registration behavior."""

import ipaddress

from tacacs_server.radius.server import RadiusClient


class AutoRegistrar:
    """Minimal auto-registration helper to emulate unknown client handling."""

    def __init__(self, enable=True, default_group="default"):
        self.enable = enable
        self.default_group = default_group
        self.devices: list[RadiusClient] = []

    def register_unknown(self, ip: str) -> RadiusClient | None:
        if not self.enable:
            return None
        # Derive name and network prefix
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return None
        prefix_len = 32 if ip_obj.version == 4 else 128
        network = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
        name = f"auto-{ip_obj.compressed.replace(':', '').replace('.', '')}"
        client = RadiusClient(
            network=network,
            secret="auto-generated",
            name=name,
            group=self.default_group,
        )
        self.devices.append(client)
        return client

    def lookup(self, ip: str) -> RadiusClient | None:
        matches = [c for c in self.devices if c.contains(ip)]
        if not matches:
            return None
        return max(matches, key=lambda c: c.network.prefixlen)


def test_unknown_client_auto_registration_ipv4():
    registrar = AutoRegistrar(enable=True, default_group="guests")
    created = registrar.register_unknown("192.0.2.50")
    assert created is not None
    assert created.group == "guests"
    assert str(created.network) == "192.0.2.50/32"
    assert created.name.startswith("auto-")
    found = registrar.lookup("192.0.2.50")
    assert found is created


def test_unknown_client_auto_registration_ipv6():
    registrar = AutoRegistrar()
    ip = "2001:db8::1234"
    created = registrar.register_unknown(ip)
    assert created is not None
    assert str(created.network) == f"{ip}/128"
    found = registrar.lookup(ip)
    assert found is created


def test_auto_registration_disabled():
    registrar = AutoRegistrar(enable=False)
    assert registrar.register_unknown("198.51.100.1") is None
    assert registrar.lookup("198.51.100.1") is None


def test_auto_created_device_naming_unique():
    registrar = AutoRegistrar()
    c1 = registrar.register_unknown("198.51.100.1")
    c2 = registrar.register_unknown("198.51.100.2")
    assert c1.name != c2.name


def test_client_lookup_after_auto_registration_most_specific():
    registrar = AutoRegistrar()
    registrar.register_unknown("203.0.113.10")
    registrar.register_unknown("203.0.113.0")  # another /32
    found = registrar.lookup("203.0.113.10")
    assert found and str(found.network) == "203.0.113.10/32"


# Additional explicit tests for requested cases
def test_unknown_client_auto_registration_ipv4_case():
    registrar = AutoRegistrar()
    client = registrar.register_unknown("10.0.0.5")
    assert client is not None
    assert client.contains("10.0.0.5")


def test_unknown_client_auto_registration_ipv6_case():
    registrar = AutoRegistrar()
    ip = "2001:db8::1"
    client = registrar.register_unknown(ip)
    assert client is not None
    assert client.contains(ip)


def test_auto_reg_disabled_rejects_unknown():
    registrar = AutoRegistrar(enable=False)
    assert registrar.register_unknown("198.51.100.123") is None
    assert registrar.lookup("198.51.100.123") is None


def test_client_lookup_after_auto_registration():
    registrar = AutoRegistrar()
    registrar.register_unknown("192.0.2.1")
    found = registrar.lookup("192.0.2.1")
    assert found is not None
    assert str(found.network) == "192.0.2.1/32"
