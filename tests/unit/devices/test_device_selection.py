from pathlib import Path

from tacacs_server.devices.store import DeviceStore


class _TestStore(DeviceStore):
    def _row_to_device(self, row, groups):  # type: ignore[override]
        dev = super()._row_to_device(row, groups)
        # Attach an 'enabled' attribute dynamically for testing skip-disabled logic
        # Disable device named 'disabled-dev'
        try:
            object.__setattr__(dev, "enabled", False if dev.name == "disabled-dev" else True)
        except Exception:
            # If dataclass frozen prevents setattr, use a proxy pattern
            pass
        return dev


def test_find_device_for_ip_skips_disabled(tmp_path: Path):
    dbp = tmp_path / "devices.db"
    store = _TestStore(str(dbp))
    # Ensure a group exists
    store.ensure_group("g1")
    # Two overlapping networks, both /32
    store.ensure_device(name="disabled-dev", network="10.0.0.5/32", group="g1")
    store.ensure_device(name="active-dev", network="10.0.0.5/32", group="g1")

    # With our _row_to_device override, the first device appears disabled to the resolver
    dev = store.find_device_for_ip("10.0.0.5")
    assert dev is not None
    assert dev.name == "active-dev"

