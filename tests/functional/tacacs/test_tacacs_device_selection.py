"""
TACACS Device Selection Tests

Verify device selection by longest-prefix match using real TACACS server.
"""


def _dump_diag(server, session=None, base: str | None = None, note: str = "") -> None:
    try:
        print("\n=== TACACS DIAGNOSTICS START", note, "===")
        try:
            logs = server.get_logs()
            print("-- server.log tail --\n", logs[-1200:])
        except Exception as e:
            print("Failed to read server logs:", e)
        if session and base:
            try:
                r = session.get(f"{base}/api/devices?limit=1000", timeout=5)
                print("-- /api/devices status:", r.status_code)
                if r.ok:
                    print("devices:", [d.get("name") for d in r.json()])
                else:
                    print("body:", r.text)
            except Exception as e:
                print("Failed to query /api/devices:", e)
        print("=== TACACS DIAGNOSTICS END ===\n")
    except Exception:
        pass


def test_tacacs_device_most_specific_wins(server_factory):
    """With /32, /24, /16 present, only /32 secret succeeds."""
    server = server_factory(
        config={"auth_backends": "local", "devices": {"auto_register": "false"}},
        enable_tacacs=True,
        enable_admin_api=True,
    )

    with server:
        from tacacs_server.auth.local_user_service import LocalUserService
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        LocalUserService(str(server.auth_db)).create_user(
            "alice", password="PassWord123", privilege_level=15
        )

        session = server.login_admin()
        base = server.get_base_url()

        g_specs = {"g16": "Secret16AA!", "g24": "Secret24BB!", "g32": "Secret32CC!"}
        group_ids: dict[str, int] = {}
        for name, secret in g_specs.items():
            r = session.post(
                f"{base}/api/device-groups",
                json={"name": name, "tacacs_secret": secret},
                timeout=5,
            )
            assert r.status_code in (201, 409), r.text
            if r.status_code == 201:
                group_ids[name] = r.json()["id"]
        if len(group_ids) < len(g_specs):
            gr = session.get(f"{base}/api/device-groups?limit=1000", timeout=5)
            assert gr.status_code == 200, gr.text
            for item in gr.json():
                nm = item.get("name")
                if nm in g_specs and nm not in group_ids:
                    group_ids[nm] = item.get("id")

        for name, ip, group in (
            ("dev-16", "127.0.0.0/16", "g16"),
            ("dev-24", "127.0.0.0/24", "g24"),
            ("dev-32", "127.0.0.1", "g32"),
        ):
            r = session.post(
                f"{base}/api/devices",
                json={
                    "name": name,
                    "ip_address": ip,
                    "device_group_id": int(group_ids[group]),
                },
                timeout=5,
            )
            assert r.status_code in (201, 409), r.text

        ok32, msg32 = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, g_specs["g32"], "alice", "PassWord123"
        )
        if not ok32:
            _dump_diag(server, session, base, note="/32 should succeed")
        assert ok32, f"Expected /32 auth success, got: {msg32}"

        ok24, msg24 = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, g_specs["g24"], "alice", "PassWord123"
        )
        ok16, msg16 = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, g_specs["g16"], "alice", "PassWord123"
        )
        if ok24 or ok16:
            _dump_diag(server, session, base, note="Unexpected broader match accepted")
        assert not ok24, f"/24 secret should fail when /32 present (msg={msg24})"
        assert not ok16, f"/16 secret should fail when /32 present (msg={msg16})"


def test_tacacs_device_prefers_narrower_when_no_host(server_factory):
    """With only /24 and /16 present, /24 secret succeeds and /16 fails."""
    server = server_factory(
        config={"auth_backends": "local"},
        enable_tacacs=True,
        enable_admin_api=True,
    )

    with server:
        import time as _time
        from tacacs_server.auth.local_user_service import LocalUserService
        from tests.functional.tacacs.test_tacacs_basic import tacacs_authenticate

        LocalUserService(str(server.auth_db)).create_user(
            "alice", password="PassWord123", privilege_level=15
        )

        session = server.login_admin()
        base = server.get_base_url()

        # Ensure auto_register disabled at runtime and remove any auto- devices
        cfg = session.get(f"{base}/api/admin/config/devices", timeout=5)
        assert cfg.status_code == 200, cfg.text
        vals = cfg.json().get("values", {})
        ar = str(vals.get("auto_register", "true")).lower()
        if ar != "false":
            upd = session.put(
                f"{base}/api/admin/config/devices",
                json={"section": "devices", "updates": {"auto_register": "false"}},
                timeout=5,
            )
            assert upd.status_code == 200, upd.text
            _time.sleep(0.2)

        devs = session.get(f"{base}/api/devices?limit=1000", timeout=5)
        assert devs.status_code == 200, devs.text
        for item in devs.json():
            if str(item.get("name", "")).startswith("auto-127.0.0.1"):
                session.delete(f"{base}/api/devices/{item['id']}", timeout=5)
        _time.sleep(0.1)

        g_specs = {"g16": "NetSecret16!A", "g24": "NetSecret24!B"}
        group_ids: dict[str, int] = {}
        for name, secret in g_specs.items():
            r = session.post(
                f"{base}/api/device-groups",
                json={"name": name, "tacacs_secret": secret},
                timeout=5,
            )
            assert r.status_code in (201, 409), r.text
            if r.status_code == 201:
                group_ids[name] = r.json()["id"]
        if len(group_ids) < len(g_specs):
            gr = session.get(f"{base}/api/device-groups?limit=1000", timeout=5)
            assert gr.status_code == 200, gr.text
            for item in gr.json():
                nm = item.get("name")
                if nm in g_specs and nm not in group_ids:
                    group_ids[nm] = item.get("id")

        created = {}
        for name, ip, group in (
            ("dev-16", "127.0.0.0/16", "g16"),
            ("dev-24", "127.0.0.0/24", "g24"),
        ):
            r = session.post(
                f"{base}/api/devices",
                json={
                    "name": name,
                    "ip_address": ip,
                    "device_group_id": int(group_ids[group]),
                },
                timeout=5,
            )
            assert r.status_code in (201, 409), r.text
            if r.status_code == 201:
                created[name] = r.json()["id"]

        # Wait until devices are visible
        names_needed = {"dev-16", "dev-24"}
        for _ in range(10):
            lr = session.get(f"{base}/api/devices?limit=1000", timeout=5)
            assert lr.status_code == 200, lr.text
            got = {item.get("name") for item in lr.json()}
            if names_needed.issubset(got):
                break
            _time.sleep(0.1)

        _time.sleep(0.3)

        ok24 = False
        for _ in range(5):
            ok24, msg24 = tacacs_authenticate(
                "127.0.0.1", server.tacacs_port, g_specs["g24"], "alice", "PassWord123"
            )
            if ok24:
                break
            _time.sleep(0.2)
        if not ok24:
            _dump_diag(server, session, base, note="/24 should succeed (no /32)")
        assert ok24, f"/24 secret should succeed without /32 (msg={msg24})"

        ok16, msg16 = tacacs_authenticate(
            "127.0.0.1", server.tacacs_port, g_specs["g16"], "alice", "PassWord123"
        )
        if ok16:
            _dump_diag(server, session, base, note="/16 should fail when /24 present")
        assert not ok16, f"/16 secret should fail when /24 present (msg={msg16})"

