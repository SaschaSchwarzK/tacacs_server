"""Unit tests for process-pool dynamic backend registration without real network.

Purpose
-------
- Complement the containerized E2E by validating behaviors that are impractical there,
  specifically: dynamic backend registration to the process pool via
  `AAAHandlers.on_backend_added` and `TacacsServer.add_auth_backend`.
- Ensure that once a backend is added post-initialization, it is serialized and eligible
  for process-pool dispatch (or clean thread fallback when pool is unavailable).

Environment considerations
--------------------------
- Prefer the "fork" start method for Linux/CI to match production semantics; tolerate
  failures (e.g., macOS restrictions) and assert only on types/paths rather than real
  network behavior.
- No Okta or external network usage; Local backend is used with in-memory storage.

Assertions
----------
- Serialized configs in handlers are updated after dynamic addition.
- Authentication path executes (types asserted) without requiring a live network.
"""

from __future__ import annotations

import multiprocessing as mp
import sys
import types

import pytest

# Prefer 'fork' start method where possible (Linux/CI). On macOS, this may be
# limited, so tolerate exceptions as other unit tests do.
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

    class _DummyHTTPAdapter:  # noqa: D401 - simple shim
        """Dummy HTTPAdapter shim for environments without requests extras."""

    setattr(adapters, "HTTPAdapter", _DummyHTTPAdapter)


from tacacs_server.tacacs.handlers import AAAHandlers  # noqa: E402
from tacacs_server.tacacs.server import TacacsServer  # noqa: E402


def test_on_backend_added_updates_pool_configs():
    """Backends added after handlers init are serialized for the process pool.

    Setup:
    - Create `AAAHandlers` with no initial backends and an enabled process-pool size.
    - Add a Local backend via `on_backend_added` (no external services).

    Expectations:
    - The newly added backend appears in `_backend_configs` (serialized for workers).
    - An authentication call exercises the dispatch path and returns typed results
      (bools), independent of actual credentials or network.
    """
    from tacacs_server.auth.local import LocalAuthBackend

    handlers = AAAHandlers(
        auth_backends=[], db_logger=None, backend_process_pool_size=1
    )

    # Initially, no backends serialized
    assert isinstance(getattr(handlers, "_backend_configs", []), list)
    assert len(handlers._backend_configs) == 0

    # Add a supported backend dynamically
    backend = LocalAuthBackend("sqlite:///:memory:")
    handlers.on_backend_added(backend)

    # It must appear in the serialized configs
    assert any(c.get("type") == "local" for c in handlers._backend_configs)

    # If a process pool exists, authentication should be routable via pool path
    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "user", "pass", timeout_s=1.0
    )
    # We only assert types here since actual auth result may vary by env
    assert isinstance(ok, bool)
    assert isinstance(timed_out, bool)


def test_server_add_auth_backend_registers_pool(monkeypatch: pytest.MonkeyPatch):
    """Server wiring ensures dynamic backend registration reaches the process pool.

    Setup:
    - Force `TACACS_BACKEND_PROCESS_POOL_SIZE=1` to enable pool creation when possible.
    - Instantiate `TacacsServer(config=None)` (no file-based config dependency).
    - Add a Local backend via `add_auth_backend`, which must call `handlers.on_backend_added`.

    Expectations:
    - Handlers' `_backend_configs` grows and contains the Local backend entry.
    - An authentication call through handlers returns typed results (bools), without
      relying on external network or services.
    """
    from tacacs_server.auth.local import LocalAuthBackend

    # Ensure process pool is enabled without relying on config file
    monkeypatch.setenv("TACACS_BACKEND_PROCESS_POOL_SIZE", "1")

    server = TacacsServer(config=None)
    assert server.handlers is not None
    # Initially empty
    assert isinstance(getattr(server.handlers, "_backend_configs", []), list)
    initial_len = len(server.handlers._backend_configs)

    backend = LocalAuthBackend("sqlite:///:memory:")
    server.add_auth_backend(backend)

    # After adding, the handlers should have serialized config for the backend
    assert len(server.handlers._backend_configs) >= initial_len + 1
    assert any(c.get("type") == "local" for c in server.handlers._backend_configs)

    # Try an auth call through handlers to exercise the dispatch path
    ok, timed_out, err = server.handlers._authenticate_backend_with_timeout(
        backend, "user", "pass", timeout_s=1.0
    )
    assert isinstance(ok, bool)
    assert isinstance(timed_out, bool)
