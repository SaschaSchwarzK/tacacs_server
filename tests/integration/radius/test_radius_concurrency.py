"""Concurrency and correctness checks for RADIUS request handling utilities."""

import concurrent.futures
import os
import socket
import struct
import threading

from tacacs_server.radius.server import (
    ATTR_ACCT_SESSION_ID,
    ATTR_ACCT_STATUS_TYPE,
    ATTR_NAS_IP_ADDRESS,
    ATTR_USER_NAME,
    RADIUSAttribute,
    RADIUSPacket,
)
from tacacs_server.utils.rate_limiter import ConnectionLimiter, RateLimiter


def _build_auth_packet(identifier: int) -> RADIUSPacket:
    return RADIUSPacket(
        code=1,
        identifier=identifier,
        authenticator=os.urandom(16),
        attributes=[
            RADIUSAttribute(ATTR_USER_NAME, f"user{identifier}".encode()),
            RADIUSAttribute(ATTR_NAS_IP_ADDRESS, socket.inet_aton("127.0.0.1")),
        ],
    )


def _build_acct_packet(identifier: int) -> RADIUSPacket:
    attrs = [
        RADIUSAttribute(ATTR_USER_NAME, b"alice"),
        RADIUSAttribute(ATTR_ACCT_STATUS_TYPE, struct.pack("!I", 1)),  # Start
        RADIUSAttribute(ATTR_ACCT_SESSION_ID, f"sess-{identifier}".encode()),
    ]
    return RADIUSPacket(
        code=4,
        identifier=identifier,
        authenticator=os.urandom(16),
        attributes=attrs,
    )


def test_multiple_simultaneous_auth_requests():
    secret = b"secret"
    ids = list(range(20))

    def roundtrip(i):
        pkt = _build_auth_packet(i)
        raw = pkt.pack(secret)
        parsed = RADIUSPacket.unpack(raw)
        return parsed.identifier

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(roundtrip, ids))

    assert sorted(results) == ids


def test_multiple_simultaneous_acct_requests():
    secret = b"secret"
    ids = list(range(10))

    def roundtrip(i):
        pkt = _build_acct_packet(i)
        raw = pkt.pack(secret)
        parsed = RADIUSPacket.unpack(raw)
        return parsed.identifier, parsed.get_attribute(ATTR_ACCT_SESSION_ID).value

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(roundtrip, ids))

    assert {ident for ident, _ in results} == set(ids)


def test_mixed_auth_and_acct_requests():
    secret = b"secret"
    jobs = [("auth", i) for i in range(5)] + [("acct", i) for i in range(5)]

    def run(job):
        kind, i = job
        pkt = _build_auth_packet(i) if kind == "auth" else _build_acct_packet(i)
        raw = pkt.pack(secret)
        parsed = RADIUSPacket.unpack(raw)
        return parsed.code, parsed.identifier

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(run, jobs))

    assert len(results) == len(jobs)
    assert all(code in (1, 4) for code, _ in results)


def test_client_connection_from_multiple_ips():
    limiter = ConnectionLimiter(max_per_ip=2)
    ips = ["192.0.2.1", "192.0.2.2"]
    for ip in ips:
        assert limiter.acquire(ip)
        assert limiter.acquire(ip)
        assert limiter.acquire(ip) is False  # over limit
        limiter.release(ip)
        assert limiter.get_count(ip) == 1


def test_thread_pool_exhaustion_simulated():
    secret = b"secret"

    def work(i):
        pkt = _build_auth_packet(i)
        raw = pkt.pack(secret)
        parsed = RADIUSPacket.unpack(raw)
        return parsed.identifier

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(work, range(10)))

    assert sorted(results) == list(range(10))


def test_context_cleanup_on_errors():
    limiter = ConnectionLimiter(max_per_ip=1)
    ip = "203.0.113.1"

    def task():
        if not limiter.acquire(ip):
            return False
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            return False
        finally:
            limiter.release(ip)
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: task(), range(2)))

    assert any(r is False for r in results)
    assert limiter.get_count(ip) == 0


def test_rate_limiter_thread_safety():
    rl = RateLimiter(max_requests=5, window_seconds=1)
    ip = "198.51.100.1"
    success = []
    lock = threading.Lock()

    def hit():
        allowed = rl.allow_request(ip)
        with lock:
            success.append(allowed)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        pool.map(lambda _: hit(), range(10))

    # At least some requests should be rate limited when bursts exceed capacity
    assert any(success)
    assert any(not s for s in success)


# Helper to retrieve attribute by type for brevity
def _get_attr(packet: RADIUSPacket, attr_type: int):
    for attr in packet.attributes:
        if attr.attr_type == attr_type:
            return attr
    return None


# Monkey-patch a small helper for tests to avoid repetitive loops
RADIUSPacket.get_attribute = _get_attr
