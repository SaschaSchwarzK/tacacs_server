import tempfile
import time
from pathlib import Path

import pytest

from tacacs_server.devices.store import DeviceStore


@pytest.mark.performance
def test_device_lookup_scale_reasonable_time() -> None:
    """
    Populate a few thousand devices and ensure lookup remains quick.

    Threshold is intentionally lenient to avoid flakiness in CI.
    """
    with tempfile.TemporaryDirectory(dir=".") as tmpdir:
        db_path = Path(tmpdir) / "devices.db"
        store = DeviceStore(db_path=db_path)
        store.ensure_group("scale")

        # Insert 2k network entries to exercise index building
        for i in range(2000):
            store.ensure_device(
                f"dev-{i}", f"10.{i // 256}.{i % 256}.0/24", group="scale"
            )

        start = time.perf_counter()
        result = store.find_device_for_ip("10.7.42.10")
        elapsed = time.perf_counter() - start

        assert result is not None
        assert result.name.startswith("dev-")
        # Expect lookup under ~1s even on shared CI runners
        assert elapsed < 1.0
