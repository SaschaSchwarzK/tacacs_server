"""
Typed helpers for TACACS+ request/response bodies.

These helpers provide minimal, safe struct parsing for TACACS+ AAA payloads
and return simple dictionaries so callers remain decoupled from wire formats.
"""

from __future__ import annotations

import struct
from typing import Any


def _extract_string(buf: bytes, offset: int, length: int) -> tuple[str, int]:
    if length <= 0:
        return "", offset
    end = offset + length
    if offset < 0 or end > len(buf) or length > 65535:
        return "", offset
    return buf[offset:end].decode("utf-8", errors="replace"), end


def parse_authen_start(body: bytes) -> dict[str, Any]:
    """Parse TACACS+ authentication START (seq==1) payload.

    Returns dict with keys: action, priv_lvl, authen_type, service,
    user, port, rem_addr, data.
    """
    if len(body) < 8:
        raise ValueError("authen body too short")
    action, priv_lvl, authen_type, service, ulen, plen, rlen, dlen = struct.unpack(
        "!BBBBBBBB", body[:8]
    )
    off = 8
    user, off = _extract_string(body, off, ulen)
    port, off = _extract_string(body, off, plen)
    rem_addr, off = _extract_string(body, off, rlen)
    data = body[off : off + dlen] if dlen > 0 and off + dlen <= len(body) else b""
    return {
        "action": action,
        "priv_lvl": priv_lvl,
        "authen_type": authen_type,
        "service": service,
        "user": user,
        "port": port,
        "rem_addr": rem_addr,
        "data": data,
    }


def parse_author_request(body: bytes) -> dict[str, Any]:
    """Parse TACACS+ authorization REQUEST payload.

    Returns dict with keys: authen_method, priv_lvl, authen_type, authen_service,
    user, port, rem_addr, args (dict[str,str]).
    """
    if len(body) < 8:
        raise ValueError("author body too short")
    (
        authen_method,
        priv_lvl,
        authen_type,
        authen_service,
        ulen,
        plen,
        rlen,
        argc,
    ) = struct.unpack("!BBBBBBBB", body[:8])
    off = 8
    user, off = _extract_string(body, off, ulen)
    port, off = _extract_string(body, off, plen)
    rem_addr, off = _extract_string(body, off, rlen)
    arg_lens: list[int] = []
    for _ in range(argc):
        if off >= len(body):
            break
        arg_lens.append(body[off])
        off += 1
    args: dict[str, str] = {}
    for al in arg_lens:
        if off + al > len(body):
            break
        s, off = _extract_string(body, off, al)
        if "=" in s:
            k, v = s.split("=", 1)
            args[k] = v
        else:
            args[s] = ""
    return {
        "authen_method": authen_method,
        "priv_lvl": priv_lvl,
        "authen_type": authen_type,
        "authen_service": authen_service,
        "user": user,
        "port": port,
        "rem_addr": rem_addr,
        "args": args,
    }


def parse_acct_request(body: bytes) -> dict[str, Any]:
    """Parse TACACS+ accounting REQUEST payload.

    Returns dict with keys: flags, authen_method, priv_lvl, authen_type,
    authen_service, user, port, rem_addr, args (dict[str,str]).
    """
    if len(body) < 9:
        raise ValueError("acct body too short")
    (
        flags,
        authen_method,
        priv_lvl,
        authen_type,
        authen_service,
        ulen,
        plen,
        rlen,
        argc,
    ) = struct.unpack("!BBBBBBBBB", body[:9])
    off = 9
    arg_lens: list[int] = []
    for _ in range(argc):
        if off >= len(body):
            break
        arg_lens.append(body[off])
        off += 1
    user, off = _extract_string(body, off, ulen)
    port, off = _extract_string(body, off, plen)
    rem_addr, off = _extract_string(body, off, rlen)
    args: dict[str, str] = {}
    for al in arg_lens:
        if off + al > len(body):
            break
        s, off = _extract_string(body, off, al)
        if "=" in s:
            k, v = s.split("=", 1)
            args[k] = v
        else:
            args[s] = ""
    return {
        "flags": flags,
        "authen_method": authen_method,
        "priv_lvl": priv_lvl,
        "authen_type": authen_type,
        "authen_service": authen_service,
        "user": user,
        "port": port,
        "rem_addr": rem_addr,
        "args": args,
    }
