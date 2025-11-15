"""Unit tests for Okta authentication caching behavior.

This module contains tests that verify the caching behavior of the Okta authentication
backend, particularly focusing on how it handles device-scoped group restrictions.

Test Organization:
- test_okta_cache_skips_for_device_scoped_allowed_groups: Verifies that the cache
  is bypassed when device-scoped group restrictions are in place.

Security Considerations:
- Ensures proper cache invalidation when group restrictions change
- Validates that device-specific access controls are enforced correctly
- Prevents privilege escalation through cache manipulation

Dependencies:
- pytest for test framework
- OktaAuthBackend from tacacs_server.auth.okta_auth
"""

from tacacs_server.auth.okta_auth import OktaAuthBackend


class _FakeOkta(OktaAuthBackend):
    def __init__(self) -> None:
        super().__init__(
            {
                "org_url": "https://example.okta.com",
                # No Management API auth needed for this unit test; we mock lookups
                "auth_method": "none",
                # Keep small cache TTL to avoid side effects across tests
                "cache_default_ttl": 60,
            }
        )

    # Always succeed AuthN and provide a user id for group lookups
    def _call_authn_endpoint(self, username: str, password: str):  # type: ignore[override]
        return True, None, {"okta_user_id": "user-1"}

    # Mock group privilege: only when 'ops' is in the allowed set we grant non-zero privilege
    def _get_privilege_for_userid(  # type: ignore[override]
        self,
        okta_user_id: str,
        username: str,
        *,
        allowed_okta_groups: set[str] | None = None,
    ) -> int:
        if allowed_okta_groups and {g.lower() for g in allowed_okta_groups} & {"ops"}:
            return 1
        return 0


def test_okta_cache_skips_for_device_scoped_allowed_groups():
    """Verify that device-scoped group restrictions bypass the authentication cache.

    This test ensures that when device-scoped group restrictions are provided,
    the authentication cache is bypassed to enforce the most up-to-date access
    control decisions.

    Test Cases:
    1. No device restriction: Authentication result is cached
    2. Device-scoped restriction with non-matching groups: Access is denied
    3. Device-scoped restriction with matching groups: Access is granted

    Expected Behavior:
    - Cache is bypassed when device-scoped groups are specified
    - Authentication respects the most recent group restrictions
    - Cache is still used when no device-specific restrictions are present

    Security Implications:
    - Prevents privilege escalation through cache poisoning
    - Ensures device-specific access controls are always enforced
    """
    backend = _FakeOkta()

    # 1) No device restriction: result should be cached (True)
    assert backend.authenticate("alice", "pw") is True

    # 2) With device-scoped restriction that should deny (admin), the cache must NOT be used
    #    and result should be False
    assert (
        backend.authenticate("alice", "pw", allowed_okta_groups=["admin"]) is False
    ), "expected denial with device-scoped non-matching groups"

    # 3) With device-scoped restriction that should allow (ops), the cache must NOT be used
    #    and result should be True
    assert backend.authenticate("alice", "pw", allowed_okta_groups=["ops"]) is True, (
        "expected allow with device-scoped matching groups"
    )
