from __future__ import annotations

import tempfile
from pathlib import Path

from tacacs_server.devices.store import DeviceStore


def test_device_lookup_persists_across_reload() -> None:
    """Ensure device indexes survive reload and longest-prefix match still works."""
    with tempfile.TemporaryDirectory(dir=".") as tmpdir:
        db_path = Path(tmpdir) / "devices.db"
        store = DeviceStore(db_path=db_path)
        store.ensure_group("g1")
        store.ensure_device("edge-24", "192.168.0.0/24", group="g1")
        store.ensure_device("edge-25", "192.168.0.0/25", group="g1")

        # Validate initial lookup
        first = store.find_device_for_ip("192.168.0.42")
        assert first is not None and first.name == "edge-25"

        # Reload store (simulates restart) and ensure indexes rebuilt lazily
        store.reload()
        second = store.find_device_for_ip("192.168.0.42")
        assert second is not None and second.name == "edge-25"
