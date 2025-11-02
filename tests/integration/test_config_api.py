import pytest


@pytest.mark.integration
def test_config_api_full_workflow(server_factory):
    """Test the full configuration API workflow with proper authentication."""
    # Create a server instance with admin API enabled
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )

    with server:
        # Get base URL and create an authenticated session
        base = server.get_base_url()
        session = server.login_admin()

        # List sections - this should now be authenticated
        response = session.get(f"{base}/api/admin/config/sections", timeout=5)
        assert response.status_code == 200, (
            f"Expected status 200, got {response.status_code}: {response.text}"
        )

        sections = response.json().get("sections", [])
        assert "server" in sections, f"Expected 'server' in sections, got: {sections}"

        # Get server section with overridden_keys indicator
        response = session.get(f"{base}/api/admin/config/server", timeout=5)
        assert response.status_code == 200, (
            f"Failed to get server config: {response.text}"
        )

        # Validate change via validate endpoint (invalid backend)
        response = session.post(
            f"{base}/api/admin/config/validate",
            params={"section": "auth", "key": "backends", "value": "unknown"},
            timeout=5,
        )
        assert response.status_code == 200, (
            f"Validation request failed: {response.text}"
        )
        assert response.json().get("valid") is False, (
            "Expected validation to fail for unknown backend"
        )

        # Invalid update via API should raise 400 with validation errors
        bad_update = {
            "section": "auth",
            "updates": {"backends": "unknown"},
            "reason": "bad change",
        }
        response = session.put(
            f"{base}/api/admin/config/auth", json=bad_update, timeout=5
        )
        assert response.status_code == 400, (
            f"Expected 400 for invalid update, got {response.status_code}"
        )
        assert "validation_errors" in (response.json().get("detail") or {}), (
            "Expected validation errors in response"
        )

        # Accessing an unknown section should 404; updating unknown should 400
        response = session.get(f"{base}/api/admin/config/doesnotexist", timeout=5)
        assert response.status_code == 404, (
            f"Expected 404 for non-existent section, got {response.status_code}"
        )

        response = session.put(
            f"{base}/api/admin/config/doesnotexist",
            json={"section": "doesnotexist", "updates": {"x": 1}},
            timeout=5,
        )
        assert response.status_code == 400, (
            f"Expected 400 for invalid section, got {response.status_code}"
        )

        # Test versioning
        response = session.get(f"{base}/api/admin/config/versions", timeout=5)
        assert response.status_code == 200, f"Failed to get versions: {response.text}"
        versions = response.json().get("versions", [])
        assert isinstance(versions, list), (
            f"Expected versions list, got {type(versions)}"
        )

        # Test history
        response = session.get(
            f"{base}/api/admin/config/history", params={"limit": 5}, timeout=5
        )
        assert response.status_code == 200, f"Failed to get history: {response.text}"
        history = response.json().get("history", [])
        assert isinstance(history, list), f"Expected history list, got {type(history)}"

        # Test drift detection
        response = session.get(f"{base}/api/admin/config/drift", timeout=5)
        assert response.status_code == 200, f"Failed to get drift: {response.text}"
        drift = response.json().get("drift", [])
        assert isinstance(drift, list), f"Expected drift list, got {type(drift)}"

        # Test export/import
        response = session.get(f"{base}/api/admin/config/export", timeout=5)
        assert response.status_code == 200, f"Failed to export config: {response.text}"
        exported = response.json()
        assert "config" in exported, "Expected 'config' in export response"
        assert "version" in exported, "Expected 'version' in export response"

        # Test import
        response = session.post(
            f"{base}/api/admin/config/import",
            json={"config": exported["config"], "version": exported["version"]},
            timeout=5,
        )
        assert response.status_code == 200, f"Import failed: {response.text}"

        # Apply a valid override via API (server.port)
        # Capture versions before update
        response = session.get(f"{base}/api/admin/config/versions", timeout=5)
        assert response.status_code == 200, f"Failed to get versions: {response.text}"
        versions0 = response.json().get("versions") or []
        count0 = len(versions0)
        upd = {
            "section": "server",
            "updates": {"port": 5050},
            "reason": "test change",
        }
        response = session.put(f"{base}/api/admin/config/server", json=upd, timeout=5)
        assert response.status_code == 200, (
            f"Failed to update server config: {response.text}"
        )

        # Fetch server section again and verify overridden key
        response = session.get(f"{base}/api/admin/config/server", timeout=5)
        assert response.status_code == 200, (
            f"Failed to get server config: {response.text}"
        )
        overridden = set(response.json().get("overridden_keys") or [])
        assert "port" in overridden, "Expected 'port' in overridden keys"

        # History endpoint should include recent change
        response = session.get(f"{base}/api/admin/config/history", timeout=5)
        assert response.status_code == 200, f"Failed to get history: {response.text}"
        hist = response.json().get("history") or []
        assert any(h.get("section") == "server" for h in hist), (
            "Expected history to include recent change"
        )

        # Versions endpoint should list versions
        response = session.get(f"{base}/api/admin/config/versions", timeout=5)
        assert response.status_code == 200, f"Failed to get versions: {response.text}"
        versions = response.json().get("versions") or []
        assert isinstance(versions, list), (
            f"Expected versions list, got {type(versions)}"
        )
        assert len(versions) >= count0, "Version list unexpectedly shrank"
        # In many environments a new version is created after change
        assert len(versions) >= count0 + 1, (
            "Expected at least one new version after update"
        )

        # Drift detection should report differences when overrides exist
        response = session.get(f"{base}/api/admin/config/drift", timeout=5)
        assert response.status_code == 200, f"Failed to get drift info: {response.text}"
        drift = response.json().get("drift") or {}
        assert "server" in drift and "port" in drift.get("server", {})

        # Restore most recent version (if any)
        if versions:
            latest_ver = versions[0]["version_number"]
            rr = session.post(
                f"{base}/api/admin/config/versions/{latest_ver}/restore", timeout=5
            )
            assert rr.status_code == 200
