from __future__ import annotations

import asyncio
import threading

import pytest

from tacacs_server.adapters import TacacsAdapter, RadiusAdapter


@pytest.mark.asyncio
async def test_tacacs_adapter_uses_executor(monkeypatch):
    called = {
        "thread": None,
        "args": None,
    }

    adapter = TacacsAdapter()

    def fake_sync(frame: bytes, peer) -> bytes:  # noqa: ARG001
        called["thread"] = threading.current_thread().name
        called["args"] = frame
        # reflect back the frame to verify return plumbing
        return frame

    monkeypatch.setattr(adapter, "authenticate_sync", fake_sync)

    frame = b"test-frame"
    out = await adapter.authenticate(frame, ("127.0.0.1", 12345))

    assert out == frame
    # In most environments, default executor threads are named like "ThreadPoolExecutor-0_0"
    # We assert it did not run on the main event loop thread.
    assert called["thread"] is not None
    assert "ThreadPoolExecutor" in called["thread"] or called["thread"] != threading.current_thread().name
    assert called["args"] == frame


@pytest.mark.asyncio
async def test_radius_adapter_uses_executor(monkeypatch):
    called = {
        "thread": None,
        "args": None,
    }

    adapter = RadiusAdapter()

    def fake_sync(pkt: bytes, addr):
        called["thread"] = threading.current_thread().name
        called["args"] = (pkt, addr)
        # No response case (None)
        return None

    monkeypatch.setattr(adapter, "handle_sync", fake_sync)

    pkt = b"radius"
    out = await adapter.handle(pkt, ("127.0.0.1", 9999))

    assert out is None
    assert called["thread"] is not None
    assert "ThreadPoolExecutor" in called["thread"] or called["thread"] != threading.current_thread().name
    assert called["args"][0] == pkt
