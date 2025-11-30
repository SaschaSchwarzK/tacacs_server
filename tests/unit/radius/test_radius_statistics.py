"""Statistics tracking tests for RADIUS server counters."""

import concurrent.futures

from tacacs_server.radius.server import RADIUSServer


def test_auth_request_counter_increments():
    srv = RADIUSServer()
    srv._inc("auth_requests")
    srv._inc("auth_requests", 2)
    assert srv.stats["auth_requests"] == 3


def test_accept_reject_counter_updates():
    srv = RADIUSServer()
    srv._inc("auth_accepts")
    srv._inc("auth_rejects", 2)
    assert srv.stats["auth_accepts"] == 1
    assert srv.stats["auth_rejects"] == 2


def test_success_rate_calculation():
    srv = RADIUSServer()
    srv._inc("auth_requests", 5)
    srv._inc("auth_accepts", 3)
    rate = srv.stats["auth_accepts"] / srv.stats["auth_requests"]
    assert rate == 0.6


def test_acct_counter_increments():
    srv = RADIUSServer()
    srv._inc("acct_requests", 4)
    srv._inc("acct_responses")
    assert srv.stats["acct_requests"] == 4
    assert srv.stats["acct_responses"] == 1


def test_statistics_thread_safety():
    srv = RADIUSServer()

    def bump():
        for _ in range(100):
            srv._inc("auth_requests")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        pool.map(lambda _: bump(), range(5))

    assert srv.stats["auth_requests"] == 500
