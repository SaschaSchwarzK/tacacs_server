from __future__ import annotations

import time
from typing import Any

from tacacs_server.tacacs.handlers import AAAHandlers


class _DummyBackend:
    name = "dummy"

    def __init__(self, sleep_seconds: float, result: bool = True) -> None:
        self._sleep = sleep_seconds
        self._result = result

    def authenticate(self, username: str, password: str, **kwargs: Any) -> bool:
        time.sleep(self._sleep)
        return self._result


def test_backend_timeout_marks_timed_out():
    """A slow backend should be marked as timed out without hanging."""
    # Use a backend that sleeps longer than the timeout
    backend = _DummyBackend(sleep_seconds=0.5, result=True)
    handlers = AAAHandlers(auth_backends=[backend], db_logger=None, backend_timeout=0.1)

    ok, timed_out, err = handlers._authenticate_backend_with_timeout(
        backend, "user", "pass", timeout_s=0.1
    )

    assert not ok
    assert timed_out
    assert err is None
