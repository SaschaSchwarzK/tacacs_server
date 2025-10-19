from __future__ import annotations

import asyncio
import socket

import pytest

from tacacs_server import runtime as rt_mod


class _Counter:
    def __init__(self):
        self.counts = {}

    def labels(self, **kw):
        key = tuple(sorted(kw.items()))
        self._current = key
        return self

    def inc(self, n: int = 1):
        key = getattr(self, "_current", ())
        self.counts[key] = self.counts.get(key, 0) + n


class _Hist:
    def __init__(self):
        self.values = []
        self._by_label = {}

    def observe(self, v: float):
        self.values.append(v)

    # support labeled histogram usage
    def labels(self, **kw):
        key = tuple(sorted(kw.items()))
        obj = _Hist()
        # chain back to record per-label values too
        def _obs(v: float):
            obj.values.append(v)
            self._by_label.setdefault(key, []).append(v)
        obj.observe = _obs  # type: ignore
        return obj


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _tacacs_frame(body: bytes) -> bytes:
    from tacacs_server.runtime import TACACS_HEADER_LEN

    ver = bytes([0xC0])
    typ = bytes([0x01])
    seq = bytes([0x01])
    flg = bytes([0x00])
    sess = (1).to_bytes(4, "big")
    length = len(body).to_bytes(4, "big")
    hdr = ver + typ + seq + flg + sess + length
    assert len(hdr) == TACACS_HEADER_LEN
    return hdr + body


def _tacacs_frame_with_type(body: bytes, type_byte: int) -> bytes:
    from tacacs_server.runtime import TACACS_HEADER_LEN

    ver = bytes([0xC0])
    typ = bytes([type_byte & 0xFF])
    seq = bytes([0x01])
    flg = bytes([0x00])
    sess = (1).to_bytes(4, "big")
    length = len(body).to_bytes(4, "big")
    hdr = ver + typ + seq + flg + sess + length
    assert len(hdr) == TACACS_HEADER_LEN
    return hdr + body


@pytest.mark.asyncio
async def test_tacacs_metrics_ok_and_err(monkeypatch):
    tac_ok = _Counter()
    tac_hist = _Hist()

    monkeypatch.setattr(rt_mod._metrics, "tacacs_requests_total", tac_ok)
    monkeypatch.setattr(rt_mod._metrics, "tacacs_latency_seconds", tac_hist)

    port = _free_port()

    seen = {"calls": 0}

    async def handler(frame: bytes, _peer) -> bytes:
        seen["calls"] += 1
        # First call raises to count err, second echoes
        if seen["calls"] == 1:
            raise RuntimeError("boom")
        return frame

    rt = rt_mod.ServerRuntime(
        tacacs_host="127.0.0.1",
        tacacs_port=port,
        radius_host="127.0.0.1",
        radius_port=_free_port(),
        handler_tacacs=handler,
        tcp_idle_timeout_sec=0.5,
        tcp_read_timeout_sec=0.5,
        max_concurrency_tcp=1,
        max_concurrency_udp=1,
    )
    await rt.start()
    try:
        # First request triggers error path
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(_tacacs_frame(b"A"))
        await w.drain()
        await asyncio.sleep(0.1)
        w.close(); await w.wait_closed()

        # Second request ok
        r, w = await asyncio.open_connection("127.0.0.1", port)
        frm = _tacacs_frame(b"B")
        w.write(frm); await w.drain()
        data = await asyncio.wait_for(r.readexactly(len(frm)), timeout=1.0)
        assert data == frm
        w.close(); await w.wait_closed()
    finally:
        await rt.stop()

    # Verify counters recorded
    # We expect at least one err and one ok status
    keys = tac_ok.counts
    assert any(k for k in keys if dict(k).get("status") == "err")
    assert any(k for k in keys if dict(k).get("status") == "ok")
    assert tac_hist.values  # at least one observation recorded


@pytest.mark.asyncio
async def test_radius_metrics_ok(monkeypatch):
    rad_ok = _Counter()
    rad_hist = _Hist()
    drops = _Counter()

    monkeypatch.setattr(rt_mod._metrics, "radius_requests_total", rad_ok)
    monkeypatch.setattr(rt_mod._metrics, "radius_latency_seconds", rad_hist)
    monkeypatch.setattr(rt_mod._metrics, "udp_drops_total", drops)

    port = _free_port()

    async def no_resp(data: bytes, addr):
        return None

    rt = rt_mod.ServerRuntime(
        tacacs_host="127.0.0.1",
        tacacs_port=_free_port(),
        radius_host="127.0.0.1",
        radius_port=port,
        handler_radius=no_resp,
        max_concurrency_udp=1,
    )
    await rt.start()
    try:
        loop = asyncio.get_running_loop()
        tr, _ = await loop.create_datagram_endpoint(lambda: asyncio.DatagramProtocol(), local_addr=("127.0.0.1", 0))
        try:
            tr.sendto(b"X", ("127.0.0.1", port))
            await asyncio.sleep(0.1)
        finally:
            tr.close()
    finally:
        await rt.stop()

    # One ok processed, some latency observed
    assert any(dict(k).get("status") == "ok" for k in rad_ok.counts)
    assert rad_hist.values


@pytest.mark.asyncio
async def test_tacacs_per_type_counters_and_latency(monkeypatch):
    by_type = _Counter()
    lat = _Hist()
    # Patch per-type metrics
    monkeypatch.setattr(rt_mod._metrics, "tacacs_requests_by_type_total", by_type)
    monkeypatch.setattr(rt_mod._metrics, "tacacs_latency_by_type_seconds", lat)

    port = _free_port()

    async def handler(frame: bytes, _peer):
        return frame

    rt = rt_mod.ServerRuntime(
        tacacs_host="127.0.0.1",
        tacacs_port=port,
        radius_host="127.0.0.1",
        radius_port=_free_port(),
        handler_tacacs=handler,
        max_concurrency_tcp=2,
        max_concurrency_udp=1,
        tcp_idle_timeout_sec=0.5,
        tcp_read_timeout_sec=0.5,
    )
    await rt.start()
    try:
        # Send one of each TACACS packet type: 1=auth, 2=author, 3=acct
        for t in (1, 2, 3):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            frm = _tacacs_frame_with_type(b"X", t)
            w.write(frm); await w.drain()
            _ = await asyncio.wait_for(r.readexactly(len(frm)), timeout=1.0)
            w.close(); await w.wait_closed()
    finally:
        await rt.stop()

    # Verify per-type counters incremented for ok status
    seen_types = {dict(k).get("type") for k in by_type.counts}
    assert {"1", "2", "3"}.issubset(seen_types)
    ok_keys = [k for k in by_type.counts if dict(k).get("status") == "ok"]
    assert any(dict(k).get("type") == "1" for k in ok_keys)
    assert any(dict(k).get("type") == "2" for k in ok_keys)
    assert any(dict(k).get("type") == "3" for k in ok_keys)
