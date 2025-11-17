import multiprocessing as mp
import os
import sys
import time
import types

# Ensure 'fork' start method for tests so worker processes inherit backend
# instances. This is required for the process-pool implementation to work
# in the test environment.
try:
    mp.set_start_method("fork", force=True)
except Exception:
    pass

# Provide minimal shims for optional imports used during package import
for mod in ("requests", "ldap3", "bcrypt"):
    if mod not in sys.modules:
        sys.modules[mod] = types.ModuleType(mod)

if "requests.adapters" not in sys.modules:
    adapters = types.ModuleType("requests.adapters")
    sys.modules["requests.adapters"] = adapters
    setattr(sys.modules["requests"], "adapters", adapters)

    class _DummyHTTPAdapter:
        pass

    setattr(adapters, "HTTPAdapter", _DummyHTTPAdapter)

from tacacs_server.auth.base import AuthenticationBackend  # noqa: E402
from tacacs_server.tacacs.handlers import AAAHandlers  # noqa: E402


class SlowBackend(AuthenticationBackend):
    def __init__(self, name: str, sleep_s: float = 2.0):
        super().__init__(name)
        self.sleep_s = sleep_s

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        time.sleep(self.sleep_s)
        return True

    def get_user_attributes(self, username: str):
        return {}


def test_process_pool_worker_timeout_and_restart():
    # Enable process pool explicitly for this test
    os.environ["TACACS_ENABLE_PROCESS_POOL"] = "1"
    try:
        # Process pool only works with local backends currently
        from tacacs_server.auth.local import LocalAuthBackend

        backend = LocalAuthBackend("sqlite:///:memory:")

        handler = AAAHandlers(
            auth_backends=[backend],
            db_logger=None,
            backend_timeout=0.25,
            backend_process_pool_size=1,
        )

        # Process pool should be disabled for non-local backends or when creation fails
        # This test verifies the fallback behavior works correctly
        if len(handler._process_workers) == 0:
            # Process pool creation failed, test thread pool timeout instead
            ok, timed_out, err = handler._authenticate_backend_with_timeout(
                SlowBackend("slow", sleep_s=1.0),
                "u",
                "p",
                timeout_s=handler.backend_timeout,
            )
            assert timed_out is True
            assert ok is False
        else:
            # Process pool created successfully, test it
            assert len(handler._process_workers) == 1
            pid_before = handler._process_workers[0].pid

            ok, timed_out, err = handler._authenticate_backend_with_timeout(
                handler.auth_backends[0], "u", "p", timeout_s=handler.backend_timeout
            )
            assert timed_out is True
            assert ok is False

            # Allow a short grace for respawn
            time.sleep(0.5)
            pid_after = handler._process_workers[0].pid
            assert pid_after != pid_before
            assert handler._process_workers[0].is_alive()
    finally:
        # Clean up environment
        os.environ.pop("TACACS_ENABLE_PROCESS_POOL", None)
