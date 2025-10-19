from __future__ import annotations

import struct

from tacacs_server.adapters import TacacsAdapter
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.tacacs.constants import (
    TAC_PLUS_VERSION,
    TAC_PLUS_PACKET_TYPE,
)


class _AAAErr:
    # Minimal helpers used by adapter on encryption policy failure
    def _mk(self, pkt: TacacsPacket, body: bytes) -> TacacsPacket:
        return TacacsPacket(
            version=pkt.version,
            packet_type=pkt.packet_type,
            seq_no=pkt.seq_no,
            flags=pkt.flags,
            session_id=pkt.session_id,
            length=len(body),
            body=body,
        )

    def _create_auth_response(self, pkt: TacacsPacket, status):  # noqa: ARG002
        # Return non-empty body to differentiate from echo path
        return self._mk(pkt, b"ERR")

    def _create_author_response(self, pkt: TacacsPacket, status):  # noqa: ARG002
        return self._mk(pkt, b"ERR")

    def _create_acct_response(self, pkt: TacacsPacket, status):  # noqa: ARG002
        return self._mk(pkt, b"ERR")


def _unencrypted_frame(session_id: int, seq: int, body: bytes) -> bytes:
    pkt = TacacsPacket(
        version=TAC_PLUS_VERSION,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=seq,
        flags=0,  # not marking unencrypted, so adapter will require a secret
        session_id=session_id,
        body=body,
    )
    hdr = struct.pack("!BBBBLL", pkt.version, pkt.packet_type, pkt.seq_no, pkt.flags, pkt.session_id, len(body))
    return hdr + body


def test_encryption_required_missing_secret_returns_error():
    class Deps:
        pass

    deps = Deps()
    deps.device_service = None  # no secret resolvable
    deps.aaa_handlers = _AAAErr()
    deps.encryption_required = True
    deps.max_len = 1024

    adapter = TacacsAdapter(deps=deps)
    frame = _unencrypted_frame(0x11111111, 1, b"abc")
    out = adapter.authenticate_sync(frame, ("127.0.0.1", 1))

    # Should produce a response frame with body from _AAAErr helpers
    hdr = TacacsPacket.unpack_header(out[:12], max_length=1024)
    body = out[12 : 12 + hdr.length]
    assert body == b"ERR"
