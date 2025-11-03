"""
RADIUS Device Selection Tests

Verify client selection by longest-prefix match using real RADIUS server.
Includes lightweight diagnostics to help troubleshoot flakiness.
"""

import time as _time


def _wait_devices(session, base: str, names: set[str], timeout_s: float = 2.0) -> None:
    end = _time.time() + timeout_s
    while _time.time() < end:
        r = session.get(f"{base}/api/devices?limit=1000", timeout=5)
        assert r.status_code == 200, r.text
        got = {item.get("name") for item in r.json()}
        if names.issubset(got):
            return
        _time.sleep(0.1)
    raise AssertionError(f"Devices {names} not visible via API")


def _dump_radius_diag(server, session=None, base: str | None = None, note: str = "") -> None:
    try:
        print("\n=== RADIUS DIAGNOSTICS START", note, "===")
        try:
            logs = server.get_logs()
            print("-- server.log tail --\n", logs[-1500:])
        except Exception as e:
            print("Failed to read server logs:", e)
        if session and base:
            try:
                r = session.get(f"{base}/api/devices?limit=1000", timeout=5)
                print("-- /api/devices status:", r.status_code)
                if r.ok:
                    names = [d.get("name") for d in r.json()]
                    print("devices:", names)
                else:
                    print("body:", r.text)
            except Exception as e:
                print("Failed to query /api/devices:", e)
        print("=== RADIUS DIAGNOSTICS END ===\n")
    except Exception:
        pass


def test_radius_client_most_specific_wins(server_factory):
    """When /32, /24 and /16 exist, /32 client's secret must be accepted."""
    server = server_factory(
        config={
            "auth_backends": "local",
            "radius_share_backends": "true",
            "devices": {"auto_register": "false"},
        },
        enable_radius=True,
        enable_admin_api=True,
    )

    # Pre-provision users, groups, and devices BEFORE starting the server so
    # RADIUS loads initial clients from the device store at setup.
    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore
    LocalUserService(str(server.auth_db)).create_user(
        "alice", password="PassWord123", privilege_level=15
    )
    store = DeviceStore(str(server.devices_db))
    g_specs = {"g16": "R16SecretAA!", "g24": "R24SecretBB!", "g32": "R32SecretCC!"}
    for name, secret in g_specs.items():
        store.ensure_group(name, metadata={"radius_secret": secret})
    store.ensure_device("rad-16", "127.0.0.0/16", group="g16")
    store.ensure_device("rad-24", "127.0.0.0/24", group="g24")
    store.ensure_device("rad-32", "127.0.0.1", group="g32")

    from tests.functional.radius.test_radius_basic import radius_authenticate
    with server:
        _time.sleep(0.3)
        ok32 = False
        msg32 = ""
        for _ in range(6):
            ok32, msg32 = radius_authenticate(
                "127.0.0.1", server.radius_auth_port, g_specs["g32"], "alice", "PassWord123"
            )
            if ok32:
                break
            _time.sleep(0.2)
        if not ok32:
            _dump_radius_diag(server, None, None, note="/32 should succeed (pre-provisioned)")
        assert ok32, f"/32 secret should succeed: {msg32}"
        ok24, msg24 = radius_authenticate(
            "127.0.0.1", server.radius_auth_port, g_specs["g24"], "alice", "PassWord123"
        )
        ok16, msg16 = radius_authenticate(
            "127.0.0.1", server.radius_auth_port, g_specs["g16"], "alice", "PassWord123"
        )
        assert not ok24, f"/24 secret should fail when /32 exists (msg={msg24})"
        assert not ok16, f"/16 secret should fail when /32 exists (msg={msg16})"


def test_radius_client_prefers_narrower_when_no_host(server_factory):
    """With only /24 and /16 present, /24 secret should be accepted."""
    server = server_factory(
        config={
            "auth_backends": "local",
            "radius_share_backends": "true",
            "devices": {"auto_register": "false"},
        },
        enable_radius=True,
        enable_admin_api=True,
    )

    from tacacs_server.auth.local_user_service import LocalUserService
    from tacacs_server.devices.store import DeviceStore
    LocalUserService(str(server.auth_db)).create_user(
        "carol", password="PassWord123", privilege_level=15
    )
    store = DeviceStore(str(server.devices_db))
    g_specs = {"g16": "R16SecretDD!", "g24": "R24SecretEE!"}
    for name, secret in g_specs.items():
        store.ensure_group(name, metadata={"radius_secret": secret})
    store.ensure_device("rad-16", "127.0.0.0/16", group="g16")
    store.ensure_device("rad-24", "127.0.0.0/24", group="g24")

    from tests.functional.radius.test_radius_basic import radius_authenticate
    with server:
        _time.sleep(0.3)
        ok24 = False
        msg24 = ""
        for _ in range(6):
            ok24, msg24 = radius_authenticate(
                "127.0.0.1", server.radius_auth_port, g_specs["g24"], "carol", "PassWord123"
            )
            if ok24:
                break
            _time.sleep(0.2)
        if not ok24:
            _dump_radius_diag(server, None, None, note="/24 should succeed (pre-provisioned)")
        assert ok24, f"/24 secret should succeed without /32 (msg={msg24})"
        ok16, msg16 = radius_authenticate(
            "127.0.0.1", server.radius_auth_port, g_specs["g16"], "carol", "PassWord123"
        )
        assert not ok16, f"/16 secret should fail when /24 exists (msg={msg16})"
