import socket
import threading
import time

import pytest


@pytest.mark.integration
def test_tacacs_per_ip_rate_limiter(server_factory):
    # Start server with a low per-IP concurrent connection cap
    server = server_factory(
        enable_tacacs=True, config={"security": {"max_connections_per_ip": 3}}
    )
    with server:
        host = "127.0.0.1"
        port = server.tacacs_port

        results: list[str] = []

        def opener(idx: int):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                s.connect((host, port))
                # Hold open to create concurrency
                time.sleep(0.3)
                try:
                    data = s.recv(1)
                    if data == b"":
                        results.append("closed")
                    else:
                        results.append("open")
                except TimeoutError:
                    results.append("open")
            except Exception:
                results.append("refused")
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        threads = [threading.Thread(target=opener, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        limited = results.count("closed") + results.count("refused")
        assert limited >= 1, f"Expected some connections limited; results={results}"

        # Verify logs indicate limiter activity
        time.sleep(0.1)
        logs = server.get_logs()
        low = logs.lower()
        assert (
            "per-ip connection cap exceeded" in low
            or "rate limit exceeded" in low
            or "rate limit" in low
        ), "Expected TACACS rate/connection limit message in logs"
