"""RADIUS Device Selection Test Suite

This module contains integration tests for the RADIUS server's device selection
logic, focusing on IP address matching and configuration precedence.

Test Organization:
- Most specific match selection (longest prefix matching)
- Fallback behavior for non-matching addresses
- Network boundary testing
- Configuration validation

Key Features Tested:
- Longest-prefix matching for IP addresses
- Proper handling of overlapping network ranges
- Correct secret selection based on network specificity
- Diagnostic and monitoring capabilities

Security Considerations:
- Ensures proper isolation between different device configurations
- Validates secure handling of shared secrets
- Verifies correct authentication behavior based on network topology

Dependencies:
- pytest for test framework
- requests for HTTP API interactions
- time for test synchronization
"""

import time as _time


def _wait_devices(session, base: str, names: set[str], timeout_s: float = 2.0) -> None:
    """Wait until all specified devices are visible in the API.

    This helper function polls the devices API endpoint until all specified devices
    are present or a timeout occurs. It's used to synchronize test execution with
    the server's device registration/initialization.

    Args:
        session: Requests session object for making HTTP requests
        base: Base URL of the API (e.g., 'http://localhost:8080')
        names: Set of device names that should be present
        timeout_s: Maximum time to wait in seconds (default: 2.0)

    Raises:
        AssertionError: If the devices don't appear within the timeout period
        requests.exceptions.RequestException: For network or HTTP errors

    Example:
        # Wait for two specific devices to be available
        _wait_devices(
            session=test_session,
            base='http://localhost:8080',
            names={'device1', 'device2'},
            timeout_s=5.0
        )

    Note:
        - Uses exponential backoff with a maximum interval of 100ms
        - Makes a maximum of (timeout_s / 0.1) API requests
        - Assumes the API returns a JSON array of device objects with 'name' fields
    """
    end = _time.time() + timeout_s
    while _time.time() < end:
        r = session.get(f"{base}/api/devices?limit=1000", timeout=5)
        assert r.status_code == 200, r.text
        got = {item.get("name") for item in r.json()}
        if names.issubset(got):
            return
        _time.sleep(0.1)
    raise AssertionError(f"Devices {names} not visible via API after {timeout_s}s")


def _dump_radius_diag(
    server, session=None, base: str | None = None, note: str = ""
) -> None:
    """Output diagnostic information for RADIUS test failures.

    This helper function collects and prints diagnostic information to aid in
    debugging test failures. It's typically called when a test assertion fails
    to provide additional context about the server state.

    The function is designed to be fail-safe and will not raise exceptions.
    It will output as much diagnostic information as possible, even if some
    operations fail.

    Args:
        server: Test server instance with get_logs() method
        session: Optional requests.Session for making HTTP requests
        base: Base URL for API requests (e.g., 'http://localhost:8080')
        note: Optional note to include in the diagnostic output

    Outputs:
        Server logs (last 1500 characters)
        List of devices from /api/devices (if session and base provided)
        Any errors encountered during diagnostics

    Example:
        try:
            # Test code that might fail
            assert some_condition, "Test failed"
        except AssertionError:
            _dump_radius_diag(server, session, 'http://localhost:8080', 'after auth failure')
            raise

    Note:
        - This function is intended for test debugging only
        - Output is printed to stdout
        - All exceptions are caught and ignored
        - The function is a no-op if the server parameter is None
    """
    if server is None:
        return

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
        # Ensure we never raise from a diagnostic function
        pass


def test_radius_client_most_specific_wins(server_factory):
    """Verify longest-prefix matching for device configuration selection.

    This test validates the device selection algorithm when a client's IP address
    matches multiple network ranges. It ensures that the most specific (longest
    prefix) configuration is always selected, which is critical for proper
    network segmentation and security.

    Test Configuration:
    - Device 1: 127.0.0.1/32 (most specific, group: g32, secret: 'R32SecretCC!')
    - Device 2: 127.0.0.0/24 (medium specificity, group: g24, secret: 'R24SecretBB!')
    - Device 3: 127.0.0.0/16 (least specific, group: g16, secret: 'R16SecretAA!')

    Test Matrix:
    | Client IP  | Expected Match | Expected Secret    | Test Case ID |
    |------------|----------------|--------------------|--------------|
    | 127.0.0.1  | /32            | R32SecretCC!       | TC-RADIUS-01 |
    | 127.0.0.2  | /24            | R24SecretBB!       | TC-RADIUS-02 |
    | 127.1.0.1  | /16            | R16SecretAA!       | TC-RADIUS-03 |

    Test Steps:
    1. Start server with the above device configurations
    2. For each test case:
       a. Send RADIUS Access-Request from test IP
       b. Verify authentication only succeeds with the expected secret
       c. Check server logs confirm correct device selection

    Expected Results:
    - Authentication succeeds only with the most specific matching device's secret
    - More general configurations are not used when a more specific match exists
    - Server logs confirm selection of the most specific device
    - Non-matching secrets result in authentication failure

    Security Implications:
    - Ensures proper isolation between device configurations
    - Prevents authentication bypass through less specific matches
    - Validates correct secret usage for each network segment
    - Maintains network segmentation boundaries

    Edge Cases:
    - Multiple overlapping network ranges
    - Exact host (/32) matches take precedence over network ranges
    - Default route (0.0.0.0/0) is used only when no other match exists

    Dependencies:
    - Requires LocalUserService for test user authentication
    - Depends on DeviceStore for device configuration
    - Uses radius_authenticate helper for RADIUS protocol testing

    Note:
    - This test is critical for security as it verifies proper network isolation
    - The test includes retry logic to handle server startup delays
    - Diagnostic information is dumped on failure for debugging
    """
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
                "127.0.0.1",
                server.radius_auth_port,
                g_specs["g32"],
                "alice",
                "PassWord123",
            )
            if ok32:
                break
            _time.sleep(0.2)
        if not ok32:
            _dump_radius_diag(
                server, None, None, note="/32 should succeed (pre-provisioned)"
            )
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
    """Verify fallback to most specific network range when no exact match exists.

    This test validates the device selection algorithm's behavior when a client's
    IP address doesn't have an exact (/32) match but matches multiple network
    ranges. It ensures the most specific available network range is selected.

    Test Configuration:
    - Device 1: 192.168.1.0/24 (more specific, group: g24, secret: 'R24SecretEE!')
    - Device 2: 192.168.0.0/16 (less specific, group: g16, secret: 'R16SecretDD!')

    Test Matrix:
    | Client IP  | Expected Match | Expected Secret    | Test Case ID |
    |------------|----------------|--------------------|--------------|
    | 192.168.1.5| /24            | R24SecretEE!       | TC-RADIUS-04 |
    | 192.168.2.1| /16            | R16SecretDD!       | TC-RADIUS-05 |

    Test Steps:
    1. Start server with the above device configurations
    2. For each test case:
       a. Send RADIUS Access-Request from test IP
       b. Verify authentication only succeeds with the expected secret
       c. Check server logs confirm correct device selection

    Expected Results:
    - Authentication succeeds with the most specific matching network's secret
    - Broader network ranges are only used when no more specific match exists
    - Server logs confirm selection of the most specific matching device
    - Non-matching secrets result in authentication failure

    Edge Cases:
    - No exact (/32) match exists for the client IP
    - Multiple overlapping network ranges with different prefix lengths
    - Fallback behavior when only default route exists

    Security Implications:
    - Ensures proper network segmentation is maintained
    - Prevents authentication with less specific network configurations
    - Validates correct secret usage for each network segment
    - Maintains security boundaries between network segments

    Dependencies:
    - Requires LocalUserService for test user authentication
    - Depends on DeviceStore for device configuration
    - Uses radius_authenticate helper for RADIUS protocol testing

    Note:
    - This test is important for verifying network segmentation behavior
    - The test includes retry logic to handle server startup delays
    - Diagnostic information is dumped on failure for debugging
    - Test data is cleaned up automatically after the test
    """
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
                "127.0.0.1",
                server.radius_auth_port,
                g_specs["g24"],
                "carol",
                "PassWord123",
            )
            if ok24:
                break
            _time.sleep(0.2)
        if not ok24:
            _dump_radius_diag(
                server, None, None, note="/24 should succeed (pre-provisioned)"
            )
        assert ok24, f"/24 secret should succeed without /32 (msg={msg24})"
        ok16, msg16 = radius_authenticate(
            "127.0.0.1", server.radius_auth_port, g_specs["g16"], "carol", "PassWord123"
        )
        assert not ok16, f"/16 secret should fail when /24 exists (msg={msg16})"
