from __future__ import annotations

import asyncio
import logging
from contextlib import AsyncExitStack
from typing import Awaitable, Callable, Optional, Set, Tuple
from time import perf_counter
from tacacs_server.utils import metrics as _metrics

log = logging.getLogger(__name__)

# ----- Handler type aliases -----
TacacsHandler = Callable[[bytes, Tuple[str, int] | None], Awaitable[bytes]]
RadiusHandler = Callable[[bytes, Tuple[str, int]], Awaitable[Optional[bytes]]]

# TACACS+ header is fixed 12 bytes:
# version(1), type(1), seq(1), flags(1), session_id(4), length(4)
TACACS_HEADER_LEN = 12


def _tacacs_body_len_from_header(hdr: bytes) -> int:
    """Extract packet body length from bytes 8..12 (big-endian)."""
    return int.from_bytes(hdr[8:12], byteorder="big", signed=False)


class ServerRuntime:
    """
    Owns TACACS+ (TCP) and RADIUS (UDP) listeners and all spawned tasks.
    Provides deterministic start()/stop() for tests and container shutdown.

    Key features:
      - TCP framing loop with idle + body read timeouts
      - Per-request backpressure via semaphore (not per connection)
      - UDP bounded queue + fixed-size worker pool (no unbounded tasks)
      - Tracked tasks so stop() cancels in-flight work
      - Configurable size caps for TACACS frames and UDP packets
    """

    def __init__(
        self,
        tacacs_host: str = "0.0.0.0",
        tacacs_port: int = 49,
        radius_host: str = "0.0.0.0",
        radius_port: int = 1812,
        # timeouts
        tcp_idle_timeout_sec: float = 15.0,     # waiting for next TACACS frame header
        tcp_read_timeout_sec: float = 5.0,      # reading a TACACS frame body
        # backpressure / concurrency
        max_concurrency_tcp: int = 200,         # simultaneous TACACS requests processed
        max_concurrency_udp: int = 200,         # UDP workers (and queue factor below)
        # bounds / sanity caps
        tacacs_max_body_len: int = 262_144,     # 256 KiB max TACACS body
        udp_max_packet_len: int = 4096,         # drop UDP packets larger than this
        # handlers
        handler_tacacs: TacacsHandler | None = None,
        handler_radius: RadiusHandler | None = None,
    ):
        self.tacacs_host = tacacs_host
        self.tacacs_port = tacacs_port
        self.radius_host = radius_host
        self.radius_port = radius_port

        self.tcp_idle_timeout_sec = tcp_idle_timeout_sec
        self.tcp_read_timeout_sec = tcp_read_timeout_sec

        self.tacacs_max_body_len = tacacs_max_body_len
        self.udp_max_packet_len = udp_max_packet_len

        self.handler_tacacs: TacacsHandler = handler_tacacs or self._default_tacacs_handler
        self.handler_radius: RadiusHandler = handler_radius or self._default_radius_handler

        # Lifecycle / tracking
        self._exit: AsyncExitStack | None = None
        self._tasks: Set[asyncio.Task] = set()
        self._tcp_srv: asyncio.AbstractServer | None = None
        self._udp_transport: asyncio.transports.DatagramTransport | None = None

        # Backpressure
        self._sem_tcp = asyncio.Semaphore(max_concurrency_tcp)

        # UDP bounded queue + fixed worker pool (no per-packet create_task storms)
        self._udp_worker_count = max(1, max_concurrency_udp)
        self._udp_queue: asyncio.Queue[tuple[bytes, Tuple[str, int]]] = asyncio.Queue(
            maxsize=self._udp_worker_count * 2
        )
        self._udp_workers: Set[asyncio.Task] = set()

        # --- runtime counters ---
        self._start_monotonic = perf_counter()
        self._conn_active = 0
        self._conn_total = 0
        self._tac_ok = 0
        self._tac_err = 0
        self._tac_auth_ok = 0
        self._tac_auth_err = 0
        self._tac_author_ok = 0
        self._tac_author_err = 0
        self._tac_acct_ok = 0
        self._tac_acct_err = 0
        self._rad_ok = 0
        self._rad_err = 0
        self._udp_drop_oversized = 0
        self._udp_drop_queue = 0
        self._udp_drop_invalid = 0
        # Optional UDP precheck hook: (data: bytes, addr: Tuple[str,int]) -> bool
        # If set and returns False, the datagram will be dropped early.
        self._udp_precheck = None  # type: ignore[var-annotated]

    # ---------- lifecycle ----------

    async def start(self) -> None:
        """Start TCP (TACACS+) and UDP (RADIUS) listeners and spawn UDP workers."""
        self._exit = AsyncExitStack()
        await self._exit.__aenter__()
        loop = asyncio.get_running_loop()

        # TACACS+ TCP
        self._tcp_srv = await asyncio.start_server(
            self._tcp_client_loop, self.tacacs_host, self.tacacs_port, start_serving=True
        )
        log.info("TACACS+ listening on %s:%d", self.tacacs_host, self.tacacs_port)

        # RADIUS UDP
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _RadiusProtocol(self._udp_queue, self.udp_max_packet_len),
            local_addr=(self.radius_host, self.radius_port),
        )
        log.info("RADIUS listening on %s:%d (UDP)", self.radius_host, self.radius_port)

        # Tag queue with owner so protocol can bump drop counters
        try:
            setattr(self._udp_queue, "_owner", self)
        except Exception:
            pass

        # Spawn fixed UDP worker pool
        for _ in range(self._udp_worker_count):
            t = asyncio.create_task(self._udp_worker())
            self._udp_workers.add(t)

    # ---------- stats surface ----------

    def get_stats(self) -> dict:
        """Return a snapshot of runtime counters for the monitoring UI."""
        try:
            uptime = max(0.0, perf_counter() - self._start_monotonic)
        except Exception:
            uptime = 0.0
        return {
            "connections_active": self._conn_active,
            "connections_total": self._conn_total,
            "tacacs_ok": self._tac_ok,
            "tacacs_err": self._tac_err,
            "tacacs_auth_ok": self._tac_auth_ok,
            "tacacs_auth_err": self._tac_auth_err,
            "tacacs_author_ok": self._tac_author_ok,
            "tacacs_author_err": self._tac_author_err,
            "tacacs_acct_ok": self._tac_acct_ok,
            "tacacs_acct_err": self._tac_acct_err,
            "radius_ok": self._rad_ok,
            "radius_err": self._rad_err,
            "udp_drops": {
                "oversized": self._udp_drop_oversized,
                "queue_full": self._udp_drop_queue,
                "invalid": self._udp_drop_invalid,
            },
            "uptime_seconds": int(uptime),
        }

    async def stop(self) -> None:
        """Graceful stop: close listeners, stop workers, cancel remaining tasks, close resources."""
        # Stop new work
        if self._tcp_srv:
            self._tcp_srv.close()
            await self._tcp_srv.wait_closed()
            self._tcp_srv = None

        if self._udp_transport:
            self._udp_transport.close()
            self._udp_transport = None

        # Tell UDP workers to exit (enqueue sentinels)
        for _ in range(len(self._udp_workers)):
            try:
                self._udp_queue.put_nowait((b"", ("0.0.0.0", 0)))  # sentinel
            except asyncio.QueueFull:
                # If queue is full, workers will drain it soon; we'll also cancel below
                pass

        # Cancel worker tasks (in case any are blocked on queue.get)
        if self._udp_workers:
            for t in self._udp_workers:
                t.cancel()
            await asyncio.gather(*self._udp_workers, return_exceptions=True)
            self._udp_workers.clear()

        # Cancel in-flight per-connection/per-request tasks
        for t in list(self._tasks):
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        # Close remaining resources
        if self._exit:
            await self._exit.aclose()
            self._exit = None

        log.info("ServerRuntime stopped")

    # ---------- TACACS+ (TCP) ----------

    async def _tcp_client_loop(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Process multiple framed TACACS+ requests on a single TCP connection."""
        task = asyncio.current_task()
        if task:
            self._tasks.add(task)
        peer = writer.get_extra_info("peername") or "<unknown>"
        try:
            # track connection lifecycle
            self._conn_active += 1
            self._conn_total += 1
            while True:
                # Idle timeout waiting for next header
                try:
                    hdr = await asyncio.wait_for(
                        reader.readexactly(TACACS_HEADER_LEN),
                        timeout=self.tcp_idle_timeout_sec,
                    )
                except asyncio.IncompleteReadError:
                    # client closed before header; end connection
                    break
                except asyncio.TimeoutError:
                    # idle timeout
                    log.debug("TACACS idle timeout from %s", peer)
                    break

                body_len = _tacacs_body_len_from_header(hdr)
                if body_len < 0 or body_len > self.tacacs_max_body_len:
                    log.warning("Invalid TACACS body length %s from %s", body_len, peer)
                    break

                try:
                    body = await asyncio.wait_for(
                        reader.readexactly(body_len),
                        timeout=self.tcp_read_timeout_sec,
                    )
                except asyncio.IncompleteReadError:
                    log.debug("TACACS body truncated from %s", peer)
                    break
                except asyncio.TimeoutError:
                    log.debug("TACACS body timeout from %s", peer)
                    break

                frame = hdr + body
                pkt_type = frame[1] if len(frame) >= 2 else 0

                # Per-request backpressure (do not hold a slot for the entire connection)
                async with self._sem_tcp:
                    try:
                        t0 = perf_counter()
                        resp = await self.handler_tacacs(frame, peer)
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        log.exception("TACACS handler error from %s: %s", peer, e)
                        try:
                            _metrics.tacacs_requests_total.labels(status="err").inc()
                            # per-path labeled counter
                            _metrics.tacacs_requests_by_type_total.labels(
                                type=str(pkt_type), status="err"
                            ).inc()
                        except Exception:
                            pass
                        self._tac_err += 1
                        if pkt_type == 0x01:
                            self._tac_auth_err += 1
                        elif pkt_type == 0x02:
                            self._tac_author_err += 1
                        elif pkt_type == 0x03:
                            self._tac_acct_err += 1
                        break
                    finally:
                        try:
                            dt = max(0.0, perf_counter() - t0)
                            _metrics.tacacs_latency_seconds.observe(dt)
                            _metrics.tacacs_latency_by_type_seconds.labels(type=str(pkt_type)).observe(dt)
                        except Exception:
                            pass

                    try:
                        writer.write(resp)
                        try:
                            await writer.drain()
                        except asyncio.CancelledError:
                            # shutdown during flush
                            raise
                    except ConnectionError:
                        break
                    try:
                        _metrics.tacacs_requests_total.labels(status="ok").inc()
                        _metrics.tacacs_requests_by_type_total.labels(
                            type=str(pkt_type), status="ok"
                        ).inc()
                    except Exception:
                        pass
                    self._tac_ok += 1
                    if pkt_type == 0x01:
                        self._tac_auth_ok += 1
                    elif pkt_type == 0x02:
                        self._tac_author_ok += 1
                    elif pkt_type == 0x03:
                        self._tac_acct_ok += 1
        except asyncio.CancelledError:
            # shutdown path
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            # decrement active connections counter
            if self._conn_active > 0:
                self._conn_active -= 1
            if task:
                self._tasks.discard(task)

    # ---------- RADIUS (UDP) ----------

    async def _udp_worker(self) -> None:
        """Fixed-size worker pool processing UDP packets from a bounded queue."""
        task = asyncio.current_task()
        if task:
            self._tasks.add(task)
        try:
            while True:
                data, addr = await self._udp_queue.get()
                # sentinel for shutdown
                if not data and addr == ("0.0.0.0", 0):
                    return

                try:
                    t0 = perf_counter()
                    resp = await self.handler_radius(data, addr)
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    log.exception("RADIUS handler error from %s: %s", addr, e)
                    try:
                        _metrics.radius_requests_total.labels(status="err").inc()
                    except Exception:
                        pass
                    self._rad_err += 1
                    continue
                finally:
                    try:
                        _metrics.radius_latency_seconds.observe(max(0.0, perf_counter() - t0))
                    except Exception:
                        pass

                if resp and self._udp_transport:
                    try:
                        self._udp_transport.sendto(resp, addr)
                    except Exception as e:
                        log.debug("RADIUS sendto error to %s: %s", addr, e)
                try:
                    _metrics.radius_requests_total.labels(status="ok").inc()
                except Exception:
                    pass
                self._rad_ok += 1
        finally:
            if task:
                self._tasks.discard(task)

    # ---------- defaults ----------

    async def _default_tacacs_handler(self, frame: bytes) -> bytes:
        # Echo by default (replace with your real implementation)
        return frame

    async def _default_radius_handler(self, packet: bytes, addr: Tuple[str, int]) -> Optional[bytes]:
        # No reply by default (replace with your real implementation)
        return None


class _RadiusProtocol(asyncio.DatagramProtocol):
    """Protocol that enqueues datagrams into a bounded queue; drops when full or oversized."""

    def __init__(self, queue: asyncio.Queue[tuple[bytes, Tuple[str, int]]], max_len: int):
        self.queue = queue
        self.max_len = max_len

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        # quick size sanity
        if len(data) > self.max_len:
            # drop oversized silently; add metric hook here if desired
            try:
                _metrics.udp_drops_total.labels(reason="oversized").inc()
            except Exception:
                pass
            # opportunistically bump runtime counter if available via queue owner
            try:
                # queue is owned by ServerRuntime; reach back to increment counter
                owner = getattr(self.queue, "_owner", None)
                if owner is not None:
                    owner._udp_drop_oversized += 1
            except Exception:
                pass
            return
        # optional precheck (e.g., Message-Authenticator validation)
        try:
            owner = getattr(self.queue, "_owner", None)
            pre = getattr(owner, "_udp_precheck", None)
            if callable(pre):
                ok = False
                try:
                    ok = bool(pre(data, addr))
                except Exception:
                    ok = False
                if not ok:
                    try:
                        _metrics.udp_drops_total.labels(reason="invalid").inc()
                    except Exception:
                        pass
                    try:
                        if owner is not None:
                            owner._udp_drop_invalid += 1
                    except Exception:
                        pass
                    return
        except Exception:
            pass
        try:
            self.queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            # queue full: drop packet (metric hook could go here)
            try:
                _metrics.udp_drops_total.labels(reason="queue_full").inc()
            except Exception:
                pass
            try:
                owner = getattr(self.queue, "_owner", None)
                if owner is not None:
                    owner._udp_drop_queue += 1
            except Exception:
                pass

    # helper to set owner on queue for back-reference (set by runtime.start)
