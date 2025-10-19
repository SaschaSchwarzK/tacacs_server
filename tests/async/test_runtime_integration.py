from __future__ import annotations

import asyncio
import socket

import pytest

from tacacs_server.runtime import ServerRuntime, TACACS_HEADER_LEN


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _tacacs_frame(body: bytes) -> bytes:
    # Build minimal TACACS header: version=0xc0, type=0x01, seq=1, flags=0
    # session_id=1, length=len(body) (big-endian)
    ver = bytes([0xC0])
    typ = bytes([0x01])
    seq = bytes([0x01])
    flg = bytes([0x00])
    sess = (1).to_bytes(4, "big")
    length = len(body).to_bytes(4, "big")
    hdr = ver + typ + seq + flg + sess + length
    assert len(hdr) == TACACS_HEADER_LEN
    return hdr + body


@pytest.mark.asyncio
async def test_tcp_echo_roundtrip():
    tac_port = _free_port()
    rad_port = _free_port()

    async def echo_tacacs(frame: bytes, _peer) -> bytes:
        return frame

    async def no_radius(_data: bytes, _addr):
        return None

    rt = ServerRuntime(
        tacacs_host="127.0.0.1",
        tacacs_port=tac_port,
        radius_host="127.0.0.1",
        radius_port=rad_port,
        handler_tacacs=echo_tacacs,
        handler_radius=no_radius,
        max_concurrency_tcp=10,
        max_concurrency_udp=10,
        tcp_read_timeout_sec=1.0,
        tcp_idle_timeout_sec=2.0,
    )
    await rt.start()

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", tac_port)
        body = b"hello"
        frame = _tacacs_frame(body)
        writer.write(frame)
        await writer.drain()
        # Read back exactly what we sent (echo)
        data = await asyncio.wait_for(reader.readexactly(len(frame)), timeout=2.0)
        assert data == frame
        writer.close()
        await writer.wait_closed()
    finally:
        await rt.stop()

    # After stop, port should be free to bind again (no address in use)
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", tac_port))
    finally:
        s.close()


@pytest.mark.asyncio
async def test_udp_no_response():
    tac_port = _free_port()
    rad_port = _free_port()

    async def no_radius(_data: bytes, _addr):
        return None

    rt = ServerRuntime(
        tacacs_host="127.0.0.1",
        tacacs_port=tac_port,
        radius_host="127.0.0.1",
        radius_port=rad_port,
        handler_radius=no_radius,
        max_concurrency_tcp=2,
        max_concurrency_udp=2,
    )
    await rt.start()

    try:
        loop = asyncio.get_running_loop()
        on_resp = asyncio.Future()

        class ClientProto(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
                transport.sendto(b"hi", ("127.0.0.1", rad_port))

            def datagram_received(self, data, addr):
                if not on_resp.done():
                    on_resp.set_result((data, addr))

        transport, _ = await loop.create_datagram_endpoint(
            lambda: ClientProto(), local_addr=("127.0.0.1", 0)
        )
        try:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(on_resp, timeout=0.5)
        finally:
            transport.close()
    finally:
        await rt.stop()


@pytest.mark.asyncio
async def test_graceful_shutdown_closes_sockets_and_tasks():
    tac_port = _free_port()
    rad_port = _free_port()

    # Slow handler to keep a task in flight briefly
    async def slow_tacacs(frame: bytes, _peer) -> bytes:
        await asyncio.sleep(0.2)
        return frame

    rt = ServerRuntime(
        tacacs_host="127.0.0.1",
        tacacs_port=tac_port,
        radius_host="127.0.0.1",
        radius_port=rad_port,
        handler_tacacs=slow_tacacs,
        max_concurrency_tcp=1,
        max_concurrency_udp=1,
    )
    await rt.start()

    # Open a connection, then stop
    reader, writer = await asyncio.open_connection("127.0.0.1", tac_port)
    try:
        await rt.stop()
        # New connections should fail now
        with pytest.raises((ConnectionRefusedError, OSError)):
            await asyncio.open_connection("127.0.0.1", tac_port)

        # Internal task set should be empty
        assert len(rt._tasks) == 0
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
