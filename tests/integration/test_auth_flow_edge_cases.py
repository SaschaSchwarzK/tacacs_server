"""Integration-style tests covering authentication edge cases."""

import concurrent.futures
import time

from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.auth.local_user_group_service import LocalUserGroupService
from tacacs_server.auth.local_user_service import LocalUserService


def _setup_local_backend(tmp_path):
    db_path = tmp_path / "auth.db"
    LocalAuthStore(db_path)
    user_service = LocalUserService(db_path)
    group_service = LocalUserGroupService(db_path)
    backend = LocalAuthBackend(str(db_path), cache_ttl_seconds=1)
    # Seed user and group for auth
    user_service.create_user("alice", password="Secret123!", privilege_level=1)
    group_service.create_group("netops", privilege_level=15)
    existing_groups = user_service.get_user("alice").groups or []
    if "netops" not in existing_groups:
        user_service.update_user("alice", groups=existing_groups + ["netops"])
    return backend, user_service, group_service


def test_auth_with_simultaneous_requests(tmp_path):
    """Multiple concurrent auth checks should succeed independently."""
    backend, _, _ = _setup_local_backend(tmp_path)

    def auth_call():
        return backend.authenticate("alice", "Secret123!")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _: auth_call(), range(10)))

    assert all(results)


def test_backend_fallback_behavior(tmp_path, monkeypatch):
    """Backend should fallback to cache miss path when store reloads."""
    backend, user_service, _ = _setup_local_backend(tmp_path)

    # Prime cache
    assert backend.authenticate("alice", "Secret123!")

    # Simulate reload forcing cache invalidation
    backend.invalidate_user_cache()
    user_service.set_password("alice", "Newpass123!", store_hash=True)
    assert backend.authenticate("alice", "Newpass123!")


def test_cache_invalidation_timing(tmp_path):
    """Cached credentials should expire after TTL."""
    backend, _, _ = _setup_local_backend(tmp_path)
    assert backend.authenticate("alice", "Secret123!")
    # Wait past TTL to ensure next auth revalidates
    time.sleep(1.2)
    assert backend.authenticate("alice", "Secret123!")


def test_token_refresh_scenario(tmp_path, monkeypatch):
    """Simulate token refresh by forcing a cache clear mid-auth flow."""
    backend, user_service, _ = _setup_local_backend(tmp_path)

    # Force invalidate before second attempt to mimic token refresh
    assert backend.authenticate("alice", "Secret123!")
    backend.invalidate_user_cache()
    user_service.set_password("alice", "Rotated123!", store_hash=True)
    assert backend.authenticate("alice", "Rotated123!")
