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
