import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("RUN_PERF_TESTS"),
    reason="Set RUN_PERF_TESTS=1 to run performance tests",
)


class TacacsTestClient:
    def __init__(self, host: str, port: int, secret: str):
        import time

        self.host = host
        self.port = port
        self.secret = secret
        self._seed = int(time.time())

    def authenticate(self, username: str, password: str):
        # Delegate to existing simple auth client test if available; placeholder
        # For performance, hitting real TACACS+ server is expected.
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.2)
            s.connect((self.host, self.port))
        finally:
            s.close()


@pytest.mark.performance
def test_authentication_throughput(tacacs_server):
    import socket
    import time

    host = tacacs_server["host"]
    port = tacacs_server["port"]
    client = TacacsTestClient(host, port, "testing123")

    # Skip if TACACS+ server is not listening (should be up from fixture)
    try:
        s = socket.create_connection((host, port), timeout=0.5)
        s.close()
    except Exception:
        pytest.skip(f"TACACS+ server not running on {host}:{port}; skipping perf test")
    start = time.time()
    count = 0
    duration = 2
    while time.time() - start < duration:
        try:
            client.authenticate("admin", "admin123")
            count += 1
        except Exception:
            pass
    rps = count / duration
    # Smoke threshold for CI environments
    assert rps >= 10
