import time

import pytest


@pytest.mark.integration
def test_config_api_full_workflow(server_factory):
    server = server_factory(enable_tacacs=True, enable_admin_api=True, enable_admin_web=True)
    with server:
        sess = server.login_admin()
        base = server.get_base_url()

        # List sections
        r = sess.get(f"{base}/api/admin/config/sections", timeout=5)
        assert r.status_code == 200
        sections = r.json().get("sections")
        assert "server" in sections

        # Get server section with overridden_keys indicator
        r = sess.get(f"{base}/api/admin/config/server", timeout=5)
        assert r.status_code == 200

        # Validate change via validate endpoint (invalid backend)
        rv = sess.post(
            f"{base}/api/admin/config/validate",
            params={"section": "auth", "key": "backends", "value": "unknown"},
            timeout=5,
        )
        assert rv.status_code == 200
        assert rv.json().get("valid") is False

        # Invalid update via API should raise 400 with validation errors
        bad = {
            "section": "auth",
            "updates": {"backends": "unknown"},
            "reason": "bad change",
        }
        rb = sess.put(f"{base}/api/admin/config/auth", json=bad, timeout=5)
        assert rb.status_code == 400
        assert "validation_errors" in (rb.json().get("detail") or {})

        # Accessing an unknown section should 404; updating unknown should 400
        r404 = sess.get(f"{base}/api/admin/config/doesnotexist", timeout=5)
        assert r404.status_code == 404
        r400 = sess.put(
            f"{base}/api/admin/config/doesnotexist",
            json={"section": "doesnotexist", "updates": {"x": 1}},
            timeout=5,
        )
        assert r400.status_code == 400

        # Apply a valid override via API (server.port)
        # Capture versions before update
        rvlist0 = sess.get(f"{base}/api/admin/config/versions", timeout=5)
        assert rvlist0.status_code == 200
        versions0 = rvlist0.json().get("versions") or []
        count0 = len(versions0)
        upd = {
            "section": "server",
            "updates": {"port": 5050},
            "reason": "test change",
        }
        ru = sess.put(f"{base}/api/admin/config/server", json=upd, timeout=5)
        assert ru.status_code == 200

        # Fetch server section again and verify overridden key
        r2 = sess.get(f"{base}/api/admin/config/server", timeout=5)
        assert r2.status_code == 200
        overridden = set(r2.json().get("overridden_keys") or [])
        assert "port" in overridden

        # History endpoint should include recent change
        rh = sess.get(f"{base}/api/admin/config/history", timeout=5)
        assert rh.status_code == 200
        hist = rh.json().get("history") or []
        assert any(h.get("section") == "server" for h in hist)

        # Versions endpoint should list versions
        rvlist = sess.get(f"{base}/api/admin/config/versions", timeout=5)
        assert rvlist.status_code == 200
        versions = rvlist.json().get("versions") or []
        assert isinstance(versions, list)
        assert len(versions) >= count0, "Version list unexpectedly shrank"
        assert len(versions) >= count0  # ensure type
        # In many environments a new version is created after change
        assert len(versions) >= count0 + 1

        # Drift detection should report differences when overrides exist
        rd = sess.get(f"{base}/api/admin/config/drift", timeout=5)
        assert rd.status_code == 200
        drift = rd.json().get("drift") or {}
        assert "server" in drift and "port" in drift.get("server", {})

        # Restore most recent version (if any)
        if versions:
            latest_ver = versions[0]["version_number"]
            rr = sess.post(f"{base}/api/admin/config/versions/{latest_ver}/restore", timeout=5)
            assert rr.status_code == 200
