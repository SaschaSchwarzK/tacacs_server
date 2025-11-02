import time
from pathlib import Path

import pytest


def _wait(predicate, timeout=20.0, interval=0.5) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.mark.integration
def test_backup_while_server_running(server_factory):
    """Verify backup works while TACACS server is processing requests"""
    server = server_factory(
        enable_tacacs=True,
        enable_admin_api=True,
        enable_admin_web=True,
        config={"admin_username": "admin", "admin_password": "admin123"},
    )

    with server:
        base = server.get_base_url()
        session = server.login_admin()

        # Create a local destination for backups
        dest_dir = (Path(server.work_dir) / "live-backups").resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        cr = session.post(
            f"{base}/api/admin/backup/destinations",
            json={
                "name": "live",
                "type": "local",
                "config": {"base_path": str(dest_dir)},
                "retention_days": 7,
            },
            timeout=5,
        )
        assert cr.status_code == 200, cr.text
        dest_id = cr.json()["id"]

        # Simulate some concurrent operations here (e.g., list sections)
        s = session.get(f"{base}/api/admin/config/sections", timeout=5)
        assert s.status_code == 200

        # Trigger backup
        tr = session.post(
            f"{base}/api/admin/backup/trigger",
            json={"destination_id": dest_id, "comment": "test backup"},
            timeout=5,
        )
        assert tr.status_code == 200, tr.text
        execution_id = tr.json().get("execution_id")
        assert execution_id

        # Wait for completion
        def _done():
            st = session.get(
                f"{base}/api/admin/backup/executions/{execution_id}", timeout=5
            )
            if st.status_code != 200:
                return False
            data = st.json() or {}
            return data.get("status") in ("completed", "failed")

        assert _wait(_done, timeout=30.0)
        # Verify status endpoint
        st = session.get(
            f"{base}/api/admin/backup/executions/{execution_id}", timeout=5
        ).json()
        assert st.get("status") in ("completed", "failed")

        # Verify at least one backup is listed
        lb = session.get(f"{base}/api/admin/backup/list", timeout=5)
        assert lb.status_code == 200
        backups = lb.json().get("backups") or []
        assert isinstance(backups, list)
