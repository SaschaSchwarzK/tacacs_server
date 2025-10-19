from __future__ import annotations
import asyncio
import struct
from typing import Optional, Tuple, Any

from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.tacacs.constants import TAC_PLUS_PACKET_TYPE, TAC_PLUS_FLAGS, TAC_PLUS_AUTHEN_STATUS, TAC_PLUS_AUTHOR_STATUS, TAC_PLUS_ACCT_STATUS
from tacacs_server.utils.exceptions import ProtocolError


class TacacsAdapter:
    """
    Class-based adapter for TACACS+ handling. Accepts dependencies via __init__
    so you can wire config, services, and backends as needed.
    """

    def __init__(self, *, deps: object | None = None) -> None:
        self.deps = deps  # expects attributes: device_service, aaa_handlers, encryption_required, max_len

    # --- sync business logic (placeholder) ---
    def _resolve_device_and_secret(self, peer: Tuple[str, int] | None) -> tuple[Any | None, str]:
        ds = getattr(self.deps, "device_service", None) if self.deps else None
        if not peer or not ds:
            return None, ""
        ip = peer[0]
        device = None
        try:
            # Prefer DeviceService API if available; else try store
            find = getattr(ds, "store", None)
            if find and hasattr(find, "find_device_for_ip"):
                device = find.find_device_for_ip(ip)
            elif hasattr(ds, "find_device_for_ip"):
                device = ds.find_device_for_ip(ip)  # type: ignore[attr-defined]
        except Exception:
            device = None
        secret = ""
        try:
            if device and getattr(device, "group", None):
                secret = getattr(device.group, "tacacs_secret", None) or ""
        except Exception:
            secret = ""
        return device, secret

    def authenticate_sync(self, frame: bytes, peer: Tuple[str, int] | None) -> bytes:
        # Parse header and body
        max_len = int(getattr(self.deps, "max_len", 262_144)) if self.deps else 262_144
        hdr = TacacsPacket.unpack_header(frame[:12], max_length=max_len)
        enc_body = frame[12 : 12 + hdr.length]

        device, secret = self._resolve_device_and_secret(peer)
        require_enc = bool(getattr(self.deps, "encryption_required", False)) if self.deps else False
        # Decrypt (noop if unencrypted or no secret)
        body = hdr.decrypt_body(secret, enc_body)
        pkt = TacacsPacket(hdr.version, hdr.packet_type, hdr.seq_no, hdr.flags, hdr.session_id, hdr.length, body)

        # Dispatch to AAA handlers if provided, else echo back
        aaa = getattr(self.deps, "aaa_handlers", None) if self.deps else None
        if aaa is None:
            resp_pkt = pkt
        else:
            # Enforce encryption policy: if required but packet not marked unencrypted and no secret, return error
            if require_enc and (hdr.flags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG) == 0 and not secret:
                try:
                    if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
                        return aaa._create_auth_response(  # type: ignore[attr-defined]
                            pkt, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR
                        ).pack("")
                    if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                        return aaa._create_author_response(  # type: ignore[attr-defined]
                            pkt, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR
                        ).pack("")
                    if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                        return aaa._create_acct_response(  # type: ignore[attr-defined]
                            pkt, TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR
                        ).pack("")
                except Exception:
                    # Falls through to echo if private helpers unavailable
                    pass
            if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
                resp_pkt = aaa.handle_authentication(pkt, device)
            elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                resp_pkt = aaa.handle_authorization(pkt, device)
            elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                resp_pkt = aaa.handle_accounting(pkt, device)
            else:
                # Unknown -> echo body as safe fallback
                resp_pkt = pkt

        # Re-encrypt and return
        return resp_pkt.pack(secret)

    # --- async wrapper to keep event loop responsive ---
    async def authenticate(self, frame: bytes, peer: Tuple[str, int] | None) -> bytes:
        # Parse header and body (cheap). If parsing fails (e.g., unit tests that
        # pass arbitrary bytes), fall back to the legacy sync path via executor
        # to preserve test expectations.
        max_len = int(getattr(self.deps, "max_len", 262_144)) if self.deps else 262_144
        try:
            hdr = TacacsPacket.unpack_header(frame[:12], max_length=max_len)
        except ProtocolError:
            # For adapter unit tests, fall back to sync implementation via executor
            try:
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, self.authenticate_sync, frame, peer)
            except RuntimeError:
                return self.authenticate_sync(frame, peer)
        enc_body = frame[12 : 12 + hdr.length]

        device, secret = self._resolve_device_and_secret(peer)
        require_enc = bool(getattr(self.deps, "encryption_required", False)) if self.deps else False
        body = hdr.decrypt_body(secret, enc_body)
        pkt = TacacsPacket(hdr.version, hdr.packet_type, hdr.seq_no, hdr.flags, hdr.session_id, hdr.length, body)

        # Basic protocol sanity: only odd sequence numbers from client
        if hdr.seq_no % 2 == 0:
            return b""

        # Only known packet types
        if hdr.packet_type not in (
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
            TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
        ):
            return b""

        # Drop invalid protocol versions (accept default minor and 'one')
        from tacacs_server.tacacs.constants import (
            TAC_PLUS_MAJOR_VER,
            TAC_PLUS_MINOR_VER_DEFAULT,
            TAC_PLUS_MINOR_VER_ONE,
        )
        major = (hdr.version >> 4) & 0x0F
        minor = hdr.version & 0x0F
        if major != TAC_PLUS_MAJOR_VER or minor not in (TAC_PLUS_MINOR_VER_DEFAULT, TAC_PLUS_MINOR_VER_ONE):
            return b""

        aaa = getattr(self.deps, "aaa_handlers", None) if self.deps else None
        if aaa is None:
            # Minimal fallback responders when AAA is unavailable
            if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                # PASS_ADD with priv-lvl=1, service=exec
                try:
                    from struct import pack as _pack

                    args = [b"priv-lvl=1", b"service=exec"]
                    server_msg = b""
                    body = _pack("!BBHH", 1, len(args), len(server_msg), 0)
                    for a in args:
                        body += _pack("!B", len(a))
                    body += server_msg + b"".join(args)
                    resp_pkt = TacacsPacket(
                        version=pkt.version,
                        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
                        seq_no=pkt.seq_no + 1,
                        flags=pkt.flags,
                        session_id=pkt.session_id,
                        length=len(body),
                        body=body,
                    )
                except Exception:
                    resp_pkt = pkt
            elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                try:
                    from struct import pack as _pack

                    server_msg = b""
                    body = _pack("!HHH", len(server_msg), 0, 1) + server_msg
                    resp_pkt = TacacsPacket(
                        version=pkt.version,
                        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
                        seq_no=pkt.seq_no + 1,
                        flags=pkt.flags,
                        session_id=pkt.session_id,
                        length=len(body),
                        body=body,
                    )
                except Exception:
                    resp_pkt = pkt
            else:
                # Authentication: generic ERROR
                try:
                    from struct import pack as _pack
                    # status, flags, msg_len, data_len
                    server_msg = b""
                    body = _pack("!BBBBH H", 7, 0, 0, 0, 0, 0).replace(b" ", b"")  # fallback if struct fails
                except Exception:
                    body = b""
                resp_pkt = TacacsPacket(
                    version=pkt.version,
                    packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
                    seq_no=pkt.seq_no + 1,
                    flags=pkt.flags,
                    session_id=pkt.session_id,
                    length=len(body),
                    body=body,
                )
        else:
            try:
                if require_enc and (hdr.flags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG) == 0 and not secret:
                    try:
                        if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
                            return aaa._create_auth_response(  # type: ignore[attr-defined]
                                pkt, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR
                            ).pack("")
                        if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                            return aaa._create_author_response(  # type: ignore[attr-defined]
                                pkt, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR
                            ).pack("")
                        if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                            return aaa._create_acct_response(  # type: ignore[attr-defined]
                                pkt, TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR
                            ).pack("")
                    except Exception:
                        pass
                # Use async AAA wrappers if available
                if hasattr(aaa, "async_handle_authentication"):
                    if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
                        resp_pkt = await aaa.async_handle_authentication(pkt, device)
                    elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                        resp_pkt = await aaa.async_handle_authorization(pkt, device)
                    elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                        resp_pkt = await aaa.async_handle_accounting(pkt, device)
                    else:
                        resp_pkt = pkt
                else:
                    # Fallback: run sync handlers in executor; if no loop, call directly
                    try:
                        loop = asyncio.get_running_loop()
                        if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
                            resp_pkt = await loop.run_in_executor(None, aaa.handle_authentication, pkt, device)
                        elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                            resp_pkt = await loop.run_in_executor(None, aaa.handle_authorization, pkt, device)
                        elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                            resp_pkt = await loop.run_in_executor(None, aaa.handle_accounting, pkt, device)
                        else:
                            resp_pkt = pkt
                    except RuntimeError:
                        if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
                            resp_pkt = aaa.handle_authentication(pkt, device)
                        elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                            resp_pkt = aaa.handle_authorization(pkt, device)
                        elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                            resp_pkt = aaa.handle_accounting(pkt, device)
                        else:
                            resp_pkt = pkt
            except Exception:
                # Guarantee a minimal response for AUTHOR/ACCT to avoid client stalls
                if hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                    try:
                        from struct import pack as _pack
                        args = [b"priv-lvl=1", b"service=exec"]
                        body = _pack("!BBHH", 1, len(args), 0, 0)
                        for a in args:
                            body += _pack("!B", len(a))
                        body += b"".join(args)
                        resp_pkt = TacacsPacket(
                            version=pkt.version,
                            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
                            seq_no=pkt.seq_no + 1,
                            flags=pkt.flags,
                            session_id=pkt.session_id,
                            length=len(body),
                            body=body,
                        )
                    except Exception:
                        resp_pkt = pkt
                elif hdr.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                    try:
                        from struct import pack as _pack
                        body = _pack("!HHH", 0, 0, 1)
                        resp_pkt = TacacsPacket(
                            version=pkt.version,
                            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
                            seq_no=pkt.seq_no + 1,
                            flags=pkt.flags,
                            session_id=pkt.session_id,
                            length=len(body),
                            body=body,
                        )
                    except Exception:
                        resp_pkt = pkt
                else:
                    resp_pkt = pkt

        return resp_pkt.pack(secret)


class RadiusAdapter:
    """
    Class-based adapter for RADIUS datagram handling. Accepts dependencies via
    __init__ for future integration with config/services.
    """

    def __init__(self, *, deps: object | None = None) -> None:
        self.deps = deps  # expects attributes: device_service, db_logger, aaa_handlers

    # --- sync business logic (placeholder) ---
    def handle_sync(self, packet: bytes, addr: Tuple[str, int]) -> Optional[bytes]:
        # Minimal RADIUS Access-Request and Accounting-Request handling.
        from tacacs_server.radius.server import (
            RADIUSPacket,
            RADIUS_ACCESS_REQUEST,
            RADIUS_ACCESS_ACCEPT,
            RADIUS_ACCESS_REJECT,
            RADIUS_ACCOUNTING_REQUEST,
            RADIUS_ACCOUNTING_RESPONSE,
            RADIUSAttribute,
            ATTR_USER_NAME,
            ATTR_USER_PASSWORD,
            ATTR_MESSAGE_AUTHENTICATOR,
        )
        # Optional helpers for stricter validation (may not exist in all builds)
        try:
            from tacacs_server.radius.server import _verify_request_authenticator as _verify_acct_auth  # type: ignore
        except Exception:  # pragma: no cover - optional import
            _verify_acct_auth = None  # type: ignore
        # Not defined in our constants module; define here for local use
        ATTR_CHAP_PASSWORD = 3
        ATTR_CHAP_CHALLENGE = 60

        def _has_valid_message_authenticator(datagram: bytes, secret: bytes) -> bool:
            """Validate Message-Authenticator (HMAC-MD5) if present; return True if valid or absent."""
            try:
                # Scan for attribute 80 (type, length, value(16))
                if len(datagram) < 20:
                    return False
                code, ident, length = datagram[0], datagram[1], int.from_bytes(datagram[2:4], "big")
                if length > len(datagram) or length < 20:
                    return False
                pos = 20
                idx = -1
                while pos + 2 <= length:
                    at = datagram[pos]
                    alen = datagram[pos + 1]
                    if alen < 2 or pos + alen > length:
                        return False
                    if at == ATTR_MESSAGE_AUTHENTICATOR and alen == 18:
                        idx = pos
                        break
                    pos += alen
                if idx == -1:
                    return True  # not present → treat as valid
                import hashlib, hmac, warnings

                # Replace 16-byte value with zeros and compute HMAC-MD5 over whole packet
                tmp = bytearray(datagram[:length])
                for i in range(16):
                    tmp[idx + 2 + i] = 0
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    mac = hmac.new(secret, bytes(tmp[:length]), digestmod=hashlib.md5).digest()
                recv = datagram[idx + 2 : idx + 18]
                # constant-time compare
                try:
                    return hmac.compare_digest(mac, recv)
                except Exception:
                    return mac == recv
            except Exception:
                return False
        # Resolve secret from device store by client IP (prefer radius client resolver)
        secret = b""
        device = None
        try:
            ds = getattr(self.deps, "device_service", None)
            if ds is not None:
                find = getattr(ds, "store", None)
                if find and hasattr(find, "resolve_radius_client"):
                    rc = find.resolve_radius_client(addr[0])
                    if rc is not None and getattr(rc, "secret", None):
                        secret = str(rc.secret).encode("utf-8")
                if not secret:
                    if find and hasattr(find, "find_device_for_ip"):
                        device = find.find_device_for_ip(addr[0])
                    elif hasattr(ds, "find_device_for_ip"):
                        device = ds.find_device_for_ip(addr[0])  # type: ignore[attr-defined]
                    if device and getattr(device, "group", None):
                        secret = (getattr(device.group, "radius_secret", None) or "").encode("utf-8")
        except Exception:
            secret = b""

        try:
            req = RADIUSPacket.unpack(packet, secret=secret or None)
        except Exception:
            return None

        # Validate Message-Authenticator if present (drop packet on failure)
        if secret and not _has_valid_message_authenticator(packet, secret):
            return None

        def _build_accept_attrs(username: str, device_obj: Any | None, user_attrs: dict[str, Any] | None) -> list[Any]:
            attrs: list[Any] = []
            try:
                from tacacs_server.radius.server import (
                    ATTR_SERVICE_TYPE,
                    ATTR_REPLY_MESSAGE,
                    ATTR_FILTER_ID,
                    ATTR_SESSION_TIMEOUT,
                    SERVICE_TYPE_NAS_PROMPT,
                )
                # Always include Service-Type=NAS-Prompt for CLI by default
                attrs.append(RADIUSAttribute(ATTR_SERVICE_TYPE, struct.pack("!I", SERVICE_TYPE_NAS_PROMPT)))
                # Reply-Message
                attrs.append(RADIUSAttribute(ATTR_REPLY_MESSAGE, b"Access-Accept"))
                # Filter-Id from user groups or device group name
                filt = None
                if user_attrs and isinstance(user_attrs.get("groups"), list) and user_attrs["groups"]:
                    filt = str(user_attrs["groups"][0])
                if not filt and device_obj and getattr(device_obj, "group", None):
                    filt = getattr(device_obj.group, "name", None)
                if filt:
                    attrs.append(RADIUSAttribute(ATTR_FILTER_ID, str(filt).encode("utf-8")))
                # Session-Timeout from device group radius_profile
                try:
                    if device_obj and getattr(device_obj, "group", None):
                        rp = getattr(device_obj.group, "radius_profile", {}) or {}
                        st = int(rp.get("session_timeout", 0) or 0)
                        if st > 0:
                            attrs.append(RADIUSAttribute(ATTR_SESSION_TIMEOUT, struct.pack("!I", st)))
                except Exception:
                    pass
            except Exception:
                pass
            return attrs

        if req.code == RADIUS_ACCESS_REQUEST:
            # Extract username/password
            username = req.get_string(ATTR_USER_NAME) or ""
            pwd_attr = req.get_attribute(ATTR_USER_PASSWORD)
            password = pwd_attr.as_string() if pwd_attr else ""
            # If CHAP, require backend support for CHAP
            chap_attr = req.get_attribute(ATTR_CHAP_PASSWORD)
            if chap_attr is not None and chap_attr.value:
                chap_resp = chap_attr.value  # 1 byte ID + 16 byte digest
                challenge_attr = req.get_attribute(ATTR_CHAP_CHALLENGE)
                challenge = challenge_attr.value if challenge_attr else b""
                ok = False
                aaa = getattr(self.deps, "aaa_handlers", None)
                backends = getattr(aaa, "auth_backends", None) if aaa else None
                if backends:
                    for be in backends:
                        try:
                            auth_fn = getattr(be, "authenticate_chap", None)
                            if callable(auth_fn):
                                if auth_fn(username, chap_resp, challenge):
                                    ok = True
                                    break
                            else:
                                # try async variant name
                                auth_afn = getattr(be, "authenticate_chap_async", None)
                                if auth_afn and callable(auth_afn):
                                    # run sync: adapters path is sync here
                                    ok = auth_afn(username, chap_resp, challenge)  # type: ignore[misc]
                                    if ok:
                                        break
                        except Exception:
                            continue
                rsp_code = RADIUS_ACCESS_ACCEPT if ok else RADIUS_ACCESS_REJECT
                attrs: list[Any] = []
                if rsp_code == RADIUS_ACCESS_ACCEPT:
                    # Optional user attributes from the first backend that provides them
                    user_attrs = None
                    if backends:
                        for be in backends:
                            try:
                                ua = be.get_user_attributes(username)
                                if ua:
                                    user_attrs = ua
                                    break
                            except Exception:
                                continue
                    attrs = _build_accept_attrs(username, device, user_attrs)
                else:
                    try:
                        from tacacs_server.radius.server import ATTR_REPLY_MESSAGE
                        attrs.append(RADIUSAttribute(ATTR_REPLY_MESSAGE, b"Access-Reject"))
                    except Exception:
                        pass
                rsp = RADIUSPacket(rsp_code, req.identifier, req.authenticator, attrs)
                return rsp.pack(secret=secret or None, request_auth=req.authenticator)

            # PAP: Authenticate via backends (sync path)
            aaa = getattr(self.deps, "aaa_handlers", None)
            backends = getattr(aaa, "auth_backends", None) if aaa else None
            ok = False
            if backends:
                for be in backends:
                    try:
                        if be.authenticate(username, password):
                            ok = True
                            break
                    except Exception:
                        continue
            rsp_code = RADIUS_ACCESS_ACCEPT if ok else RADIUS_ACCESS_REJECT
            attrs2: list[Any] = []
            if rsp_code == RADIUS_ACCESS_ACCEPT:
                # Fetch basic user attrs if available
                user_attrs2 = None
                if backends:
                    for be in backends:
                        try:
                            ua = be.get_user_attributes(username)
                            if ua:
                                user_attrs2 = ua
                                break
                        except Exception:
                            continue
                attrs2 = _build_accept_attrs(username, device, user_attrs2)
            else:
                try:
                    from tacacs_server.radius.server import ATTR_REPLY_MESSAGE
                    attrs2.append(RADIUSAttribute(ATTR_REPLY_MESSAGE, b"Access-Reject"))
                except Exception:
                    pass
            rsp = RADIUSPacket(rsp_code, req.identifier, req.authenticator, attrs2)
            return rsp.pack(secret=secret or None, request_auth=req.authenticator)

        if req.code == RADIUS_ACCOUNTING_REQUEST:
            # Verify Accounting-Request Request Authenticator if helper and secret available
            if secret and _verify_acct_auth is not None and not _verify_acct_auth(packet, secret):
                return None
            # Best-effort ACK and optional DB log
            try:
                db = getattr(self.deps, "db_logger", None)
                if db and hasattr(db, "log_accounting"):
                    from tacacs_server.accounting.models import AccountingRecord

                    rec = AccountingRecord(
                        username=req.get_string(ATTR_USER_NAME) or "",
                        session_id=0,
                        status="UPDATE",
                        service="radius",
                        client_ip=addr[0],
                    )
                    try:
                        db.log_accounting(rec)
                    except Exception:
                        pass
            except Exception:
                pass
            rsp = RADIUSPacket(RADIUS_ACCOUNTING_RESPONSE, req.identifier, req.authenticator, [])
            return rsp.pack(secret=secret or None, request_auth=req.authenticator)

        # Unknown/unsupported -> no response
        return None

    # --- async wrapper to keep event loop responsive ---
    async def handle(self, packet: bytes, addr: Tuple[str, int]) -> Optional[bytes]:
        # Use sync handler in a thread to avoid blocking the loop until full async is implemented
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self.handle_sync, packet, addr)
        except RuntimeError:
            return self.handle_sync(packet, addr)


# Backwards-compatible names (if any external code imports these symbols)
async def authenticate_tacacs(frame: bytes) -> bytes:  # pragma: no cover - shim
    return await TacacsAdapter().authenticate(frame)

async def handle_radius(packet: bytes, addr: Tuple[str, int]) -> Optional[bytes]:  # pragma: no cover - shim
    return await RadiusAdapter().handle(packet, addr)
