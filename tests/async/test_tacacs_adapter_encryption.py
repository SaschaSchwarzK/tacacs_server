from __future__ import annotations

import struct

from tacacs_server.adapters import TacacsAdapter
from tacacs_server.devices.store import DeviceStore
from tacacs_server.devices.service import DeviceService
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.tacacs.constants import (
    TAC_PLUS_VERSION,
    TAC_PLUS_PACKET_TYPE,
    TAC_PLUS_FLAGS,
)


class _AAA:
    def handle_authentication(self, pkt: TacacsPacket, device=None) -> TacacsPacket:
        # Return a response packet echoing the request body, bumping seq
        resp = TacacsPacket(
            version=pkt.version,
            packet_type=pkt.packet_type,
            seq_no=pkt.seq_no,
            flags=pkt.flags,
            session_id=pkt.session_id,
            length=len(pkt.body),
            body=pkt.body,
        )
        return resp


def _make_frame(session_id: int, seq: int, body: bytes, secret: str) -> bytes:
    pkt = TacacsPacket(
        version=TAC_PLUS_VERSION,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
        seq_no=seq,
        flags=0,
        session_id=session_id,
        body=body,
    )
    enc = pkt.encrypt_body(secret)
    hdr = struct.pack("!BBBBLL", pkt.version, pkt.packet_type, pkt.seq_no, pkt.flags, pkt.session_id, len(enc))
    return hdr + enc


def test_adapter_decrypts_and_encrypts_roundtrip(tmp_path):
    # Prepare DeviceStore/Service with a group secret and device for 127.0.0.1/32
    db = tmp_path / "devices.db"
    store = DeviceStore(str(db))
    svc = DeviceService(store)
    group = store.ensure_group("g1", description="test")
    # Update group metadata to include tacacs_secret via service API
    svc.update_group(group.id, tacacs_secret="shhh")
    store.ensure_device("local", "127.0.0.1/32", group=group.name)

    class Deps:
        pass

    deps = Deps()
    deps.device_service = svc
    deps.aaa_handlers = _AAA()
    deps.encryption_required = True
    deps.max_len = 1024

    adapter = TacacsAdapter(deps=deps)

    body = b"hello-auth"
    frame = _make_frame(session_id=0x01020304, seq=1, body=body, secret="shhh")

    out = adapter.authenticate_sync(frame, ("127.0.0.1", 12345))

    # Out should be a valid TACACS frame. Decrypt and compare body == echo
    resp_hdr = TacacsPacket.unpack_header(out[:12], max_length=1024)
    enc_body = out[12 : 12 + resp_hdr.length]
    dec_body = resp_hdr.decrypt_body("shhh", enc_body)
    assert dec_body == body
