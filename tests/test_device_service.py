import pytest

from tacacs_server.devices.service import (
    DeviceNotFound,
    DeviceService,
    DeviceValidationError,
    GroupNotFound,
)
from tacacs_server.devices.store import DeviceStore


@pytest.fixture
def device_service(tmp_path):
    store = DeviceStore(tmp_path / "devices.db")
    return DeviceService(store)


def test_group_crud(device_service: DeviceService):
    group = device_service.create_group(
        "core",
        description="Core switches",
        radius_secret="radius123",
        tacacs_secret="tacacs123",
        device_config={"radius_attributes": {"Framed-IP-Address": "1.1.1.1"}},
        allowed_user_groups=["netadmins", "ops"],
    )
    assert group.name == "core"
    assert group.radius_secret == "radius123"
    assert group.tacacs_secret == "tacacs123"
    assert group.device_config == {
        "radius_attributes": {"Framed-IP-Address": "1.1.1.1"}
    }
    assert group.allowed_user_groups == ["netadmins", "ops"]

    with pytest.raises(DeviceValidationError):
        device_service.create_group("core")

    updated = device_service.update_group(
        group.id,
        description="Updated",
        radius_secret="radius456",
        tacacs_secret=None,
        device_config={"radius_attributes": {"Framed-IP-Netmask": "255.255.255.0"}},
        allowed_user_groups=["ops"],
    )
    assert updated.description == "Updated"
    assert updated.radius_secret == "radius456"
    assert updated.tacacs_secret is None
    assert updated.device_config == {
        "radius_attributes": {"Framed-IP-Netmask": "255.255.255.0"}
    }
    assert updated.allowed_user_groups == ["ops"]

    groups = device_service.list_groups()
    assert len(groups) == 1

    with pytest.raises(GroupNotFound):
        device_service.get_group(group.id + 123)


def test_group_delete_with_devices(device_service: DeviceService):
    core = device_service.create_group("core", radius_secret="secret123")
    device = device_service.create_device(
        name="router1",
        network="10.0.0.1/32",
        group="core",
    )
    clients = device_service.store.iter_radius_clients()
    assert any(c.secret == "secret123" for c in clients)

    with pytest.raises(DeviceValidationError):
        device_service.delete_group(core.id)

    # Cascade delete removes both group and device
    assert device_service.delete_group(core.id, cascade=True)
    with pytest.raises(GroupNotFound):
        device_service.get_group(core.id)
    with pytest.raises(DeviceNotFound):
        device_service.get_device(device.id)


def test_device_crud(device_service: DeviceService):
    device_service.create_group("core", radius_secret="radius123")
    device_service.create_group("edge")

    device = device_service.create_device(
        name="router1",
        network="10.0.1.0/24",
        group="core",
    )

    updated = device_service.update_device(
        device.id,
        name="router1b",
        group="edge",
    )
    assert updated.name == "router1b"
    assert updated.group and updated.group.name == "edge"

    with pytest.raises(GroupNotFound):
        device_service.update_device(device.id, group="missing")

    cleared = device_service.update_device(device.id, clear_group=True)
    assert cleared.group is None

    assert device_service.delete_device(device.id)
    with pytest.raises(DeviceNotFound):
        device_service.get_device(device.id)

    with pytest.raises(DeviceValidationError):
        device_service.create_device(name="bad", network="invalid-network")

    with pytest.raises(DeviceNotFound):
        device_service.update_device(device_id=9999, name="missing")

    with pytest.raises(GroupNotFound):
        device_service.create_device(
            name="router2", network="10.0.2.0/24", group="missing"
        )


def test_device_service_notifies_listeners(device_service: DeviceService):
    events: list[str] = []
    device_service.add_change_listener(lambda: events.append("change"))

    group = device_service.create_group("core", radius_secret="secret123")
    assert events
    events.clear()

    device = device_service.create_device(
        name="router1", network="10.0.0.1/32", group="core"
    )
    assert events
    events.clear()

    device_service.update_group(group.id, radius_secret="secret456")
    assert events
    events.clear()

    device_service.update_device(device.id, network="10.0.0.2/32")
    assert events
    events.clear()

    device_service.delete_device(device.id)
    assert events
    events.clear()

    device_service.delete_group(group.id, cascade=True)
    assert events
