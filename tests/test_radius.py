"""
RADIUS Server Tests
"""

import ipaddress
import time
from types import SimpleNamespace

import pytest

from tacacs_server.devices.service import DeviceService
from tacacs_server.devices.store import DeviceStore
from tacacs_server.radius.server import RadiusClient, RADIUSPacket, RADIUSServer


def test_radius_packet_creation():
    """Test RADIUS packet creation"""
    packet = RADIUSPacket(
        code=1,  # Access-Request
        identifier=123,
        authenticator=b"\x00" * 16,
    )

    packet.add_string(1, "testuser")
    packet.add_integer(6, 6)  # Service-Type: Administrative

    assert packet.code == 1
    assert packet.identifier == 123
    assert len(packet.attributes) == 2


def test_radius_packet_pack_unpack():
    """Test packet packing and unpacking"""
    original = RADIUSPacket(
        code=2,  # Access-Accept
        identifier=42,
        authenticator=b"\xff" * 16,
    )
    original.add_string(18, "Welcome")

    # Pack
    secret = b"secret123"
    request_auth = b"\x00" * 16
    packed = original.pack(secret, request_auth)

    # Unpack
    unpacked = RADIUSPacket.unpack(packed, secret)

    assert unpacked.code == original.code
    assert unpacked.identifier == original.identifier
    assert len(unpacked.attributes) == len(original.attributes)


@pytest.fixture
def radius_server(tmp_path):
    """Create RADIUS server for testing"""
    import uuid

    from tacacs_server.auth.local import LocalAuthBackend
    from tacacs_server.auth.local_store import LocalAuthStore
    from tacacs_server.auth.local_user_service import LocalUserService

    # Use unique database and username to avoid conflicts
    unique_id = str(uuid.uuid4())[:8]
    auth_db = tmp_path / f"radius_auth_{unique_id}.db"
    store = LocalAuthStore(auth_db)
    service = LocalUserService(auth_db, store=store)
    service.create_user(
        f"testuser_{unique_id}",
        password_hash="e" * 64,
        privilege_level=15,
    )

    # Create server
    server = RADIUSServer(
        host="127.0.0.1", port=11812, accounting_port=11813, secret="testsecret"
    )

    # Add backend
    backend = LocalAuthBackend(str(auth_db))
    server.add_auth_backend(backend)

    # Add test client
    server.add_client("127.0.0.1", "testsecret", "test-nas")

    # Start server
    server.start()
    time.sleep(0.5)  # Wait for server to start

    yield server

    # Cleanup
    server.stop()


def test_radius_authentication(radius_server):
    """Test RADIUS authentication flow"""
    # This would use the test client to authenticate
    # Simplified version here
    assert radius_server.running
    assert len(radius_server.clients) == 1
    assert any(client.contains("127.0.0.1") for client in radius_server.clients)


def test_radius_stats(radius_server):
    """Test RADIUS statistics"""
    stats = radius_server.get_stats()

    assert "auth_requests" in stats
    assert "auth_accepts" in stats
    assert "auth_rejects" in stats
    assert "configured_clients" in stats
    assert stats["running"]


def test_radius_refresh_clients_on_change(tmp_path):
    store = DeviceStore(tmp_path / "devices.db")
    service = DeviceService(store)
    radius = RADIUSServer(secret="test123")

    service.add_change_listener(
        lambda: radius.refresh_clients(store.iter_radius_clients())
    )

    group = service.create_group("firewall", radius_secret="secret1")
    device = service.create_device(name="fw1", network="127.0.0.1/32", group="firewall")

    radius.refresh_clients(store.iter_radius_clients())
    client = radius.lookup_client("127.0.0.1")
    assert client is not None
    assert client.secret == "secret1"

    service.update_group(group.id, radius_secret="secret2")
    client = radius.lookup_client("127.0.0.1")
    assert client is not None
    assert client.secret == "secret2"

    service.update_device(device.id, network="127.0.0.2/32")
    assert radius.lookup_client("127.0.0.1") is None
    client = radius.lookup_client("127.0.0.2")
    assert client is not None
    assert client.secret == "secret2"

    service.delete_device(device.id)
    assert radius.lookup_client("127.0.0.2") is None


def test_radius_ignores_device_specific_secret(tmp_path):
    store = DeviceStore(tmp_path / "devices.db")
    service = DeviceService(store)
    radius = RADIUSServer(secret="test123")

    group = service.create_group("firewall", radius_secret=None)
    device = service.create_device(
        name="fw1",
        network="203.0.113.1/32",
        group="firewall",
    )

    # How Service stores device metadata secrets: update device with metadata
    # containing radius_secret. This simulates legacy data – should not produce a
    # client because group lacks a secret.
    store._conn.execute(
        "UPDATE devices SET radius_secret = ? WHERE id = ?",
        ("device-secret", device.id),
    )
    store._conn.commit()

    radius.refresh_clients(store.iter_radius_clients())
    assert radius.lookup_client("203.0.113.1") is None

    # Once the group secret is set, client becomes available
    service.update_group(group.id, radius_secret="group-secret")
    radius.refresh_clients(store.iter_radius_clients())
    client = radius.lookup_client("203.0.113.1")
    assert client is not None
    assert client.secret == "group-secret"


def test_radius_group_policy_allows_privilege_override():
    radius = RADIUSServer(secret="test123")
    radius.set_local_user_group_service(
        SimpleNamespace(get_group=lambda name: SimpleNamespace(privilege_level=9))
    )
    client = RadiusClient(
        network=ipaddress.ip_network("192.0.2.0/24"),
        secret="secret",
        name="fw",
        group="firewall",
        attributes={},
        allowed_user_groups=["firewall"],
    )
    user_attrs = {"groups": ["firewall"], "privilege_level": 1}
    allowed, message = radius._apply_user_group_policy(client, user_attrs)
    assert allowed is True
    assert message == ""
    assert user_attrs["privilege_level"] == 9


def test_radius_group_policy_denies_without_membership():
    radius = RADIUSServer(secret="test123")
    radius.set_local_user_group_service(
        SimpleNamespace(get_group=lambda name: SimpleNamespace(privilege_level=5))
    )
    client = RadiusClient(
        network=ipaddress.ip_network("198.51.100.0/24"),
        secret="secret",
        name="switch",
        group="switches",
        attributes={},
        allowed_user_groups=["switch-admins"],
    )
    user_attrs = {"groups": ["firewall"], "privilege_level": 15}
    allowed, message = radius._apply_user_group_policy(client, user_attrs)
    assert allowed is False
    assert message.startswith("User not permitted")


# (Duplicate tests removed to resolve redefinition and import-order issues.)
