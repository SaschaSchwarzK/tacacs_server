import multiprocessing as mp
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

# Provide dummy modules that sometimes aren't installed in the test env
for mod in ("requests", "ldap3", "bcrypt"):
    if mod not in sys.modules:
        sys.modules[mod] = types.ModuleType(mod)

# Some modules import submodules like 'requests.adapters' directly; ensure
# minimal submodule entries exist so importlib doesn't attempt to load the
# real packages during this isolated unit test.
if "requests.adapters" not in sys.modules:
    adapters = types.ModuleType("requests.adapters")
    sys.modules["requests.adapters"] = adapters
    # allow attribute access as package
    setattr(sys.modules["requests"], "adapters", adapters)

    # minimal HTTPAdapter shim used by some backends at import-time
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


def test_backend_times_out_and_returns_timed_out_flag():
    # Create handler with very small backend timeout
    handler = AAAHandlers(
        auth_backends=[SlowBackend("slow", sleep_s=1.0)],
        db_logger=None,
        backend_timeout=0.25,
    )
    backend = handler.auth_backends[0]

    ok, timed_out, err = handler._authenticate_backend_with_timeout(
        backend, "u", "p", timeout_s=handler.backend_timeout
    )

    assert timed_out is True
    assert ok is False
    assert err is None
