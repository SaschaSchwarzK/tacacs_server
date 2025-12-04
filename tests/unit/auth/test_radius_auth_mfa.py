from tacacs_server.auth.radius_auth import RADIUSAuthBackend


def test_parse_mfa_suffix_otp():
    backend = RADIUSAuthBackend(
        {
            "radius_server": "localhost",
            "radius_secret": "secret",
            "mfa_enabled": True,
            "mfa_otp_digits": 6,
        }
    )

    base, otp, push = backend._parse_mfa_suffix("mypass123456")
    assert base == "mypass"
    assert otp == "123456"
    assert not push


def test_parse_mfa_suffix_push():
    backend = RADIUSAuthBackend(
        {
            "radius_server": "localhost",
            "radius_secret": "secret",
            "mfa_enabled": True,
            "mfa_push_keyword": "push",
        }
    )

    base, otp, push = backend._parse_mfa_suffix("mypasspush")
    assert base == "mypass"
    assert otp is None
    assert push


def test_parse_mfa_suffix_disabled():
    backend = RADIUSAuthBackend(
        {"radius_server": "localhost", "radius_secret": "secret", "mfa_enabled": False}
    )

    base, otp, push = backend._parse_mfa_suffix("mypass123456")
    assert base == "mypass123456"  # Not parsed
    assert otp is None
    assert not push


def test_global_mfa_settings_are_overridable():
    # Simulate merged config: global MFA keyword + backend override
    merged = {
        "mfa_enabled": True,
        "radius_server": "localhost",
        "radius_secret": "secret",
        # Backend override should win
        "mfa_push_keyword": "local",
    }
    backend = RADIUSAuthBackend(merged)

    base, otp, push = backend._parse_mfa_suffix("pwlocal")
    assert base == "pw"
    assert otp is None
    assert push is True


def test_mfa_challenge_flow_accepts_otp_and_caches_groups():
    """End-to-end challenge handling: Access-Challenge then Access-Accept with groups."""
    import hashlib
    import socket
    import struct
    import threading

    secret = b"secret123"
    expected_password = "pass"
    expected_otp = "123456"

    def _attr(attr_type: int, value: bytes) -> bytes:
        return struct.pack("!BB", attr_type, 2 + len(value)) + value

    def _decrypt_pw(enc: bytes, request_auth: bytes) -> str:
        out = b""
        prev = request_auth
        for i in range(0, len(enc), 16):
            block = enc[i : i + 16]
            md5 = hashlib.md5(secret + prev, usedforsecurity=False).digest()
            out += bytes(a ^ b for a, b in zip(block, md5))
            prev = block
        return out.rstrip(b"\x00").decode("utf-8", errors="ignore")

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(1.0)
    host, port = srv.getsockname()
    stop = threading.Event()

    def _serve():
        state_val = b"xyz123"
        challenge_sent = False
        while not stop.is_set():
            try:
                data, addr = srv.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if len(data) < 20:
                continue
            identifier = data[1]
            request_auth = data[4:20]
            # Parse attributes
            attrs: dict[int, list[bytes]] = {}
            offset = 20
            while offset + 2 <= len(data):
                at = data[offset]
                alen = data[offset + 1]
                if alen < 2 or offset + alen > len(data):
                    break
                val = data[offset + 2 : offset + alen]
                attrs.setdefault(at, []).append(val)
                offset += alen

            # First leg: issue Access-Challenge demanding OTP
            if not challenge_sent:
                challenge_sent = True
                attrs_out = _attr(24, state_val)
                length = 20 + len(attrs_out)
                header = struct.pack("!BBH", 11, identifier, length)
                resp_auth = hashlib.md5(
                    header + request_auth + attrs_out + secret,
                    usedforsecurity=False,
                ).digest()
                packet = header + resp_auth + attrs_out
                srv.sendto(packet, addr)
                continue

            # Second leg: verify state + OTP, then accept with groups
            state_in = b"".join(attrs.get(24, []))
            if state_in != state_val:
                continue
            pw = ""
            if 2 in attrs:
                pw = _decrypt_pw(attrs[2][0], request_auth)
            if pw != expected_otp:
                continue

            attrs_out = _attr(11, b"netops") + _attr(25, b"group:ops")
            length = 20 + len(attrs_out)
            header = struct.pack("!BBH", 2, identifier, length)
            resp_auth = hashlib.md5(
                header + request_auth + attrs_out + secret,
                usedforsecurity=False,
            ).digest()
            packet = header + resp_auth + attrs_out
            srv.sendto(packet, addr)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()

    backend = RADIUSAuthBackend(
        {
            "radius_server": host,
            "radius_port": port,
            "radius_secret": secret.decode(),
            "radius_timeout": 1,
            "radius_retries": 2,
            "mfa_enabled": True,
            "mfa_otp_digits": 6,
        }
    )

    try:
        assert backend.authenticate("alice", expected_password + expected_otp)
        groups = backend.get_user_attributes("alice").get("groups", [])
        assert set(groups) == {"netops", "ops"}
    finally:
        stop.set()
        try:
            srv.close()
        except Exception:
            pass
        t.join(timeout=2)
