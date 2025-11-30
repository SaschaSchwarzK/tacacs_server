"""Backend integration behavior for RADIUS server authentication and attributes."""

from tacacs_server.radius.server import RADIUSServer


class StubBackend:
    def __init__(self, name, authenticate_result=True, attrs=None, error=None):
        self.name = name
        self._authenticate_result = authenticate_result
        self._attrs = attrs or {}
        self._error = error

    def authenticate(self, username, password, **kwargs):
        if self._error:
            raise self._error
        return self._authenticate_result

    def get_user_attributes(self, username):
        if self._error:
            raise self._error
        return self._attrs


def test_local_backend_authentication_success():
    srv = RADIUSServer()
    backend = StubBackend("local", authenticate_result=True)
    srv.add_auth_backend(backend)
    ok, detail = srv._authenticate_user("alice", "secret")
    assert ok is True
    assert "backend=local" in detail


def test_multiple_backends_fallback_to_second():
    srv = RADIUSServer()
    first = StubBackend("bad", authenticate_result=False)
    second = StubBackend("ok", authenticate_result=True)
    srv.add_auth_backend(first)
    srv.add_auth_backend(second)
    ok, detail = srv._authenticate_user("bob", "pw")
    assert ok is True
    assert "backend=ok" in detail


def test_backend_error_handling_reports_last_error():
    srv = RADIUSServer()
    err_backend = StubBackend("err", error=RuntimeError("boom"))
    srv.add_auth_backend(err_backend)
    ok, detail = srv._authenticate_user("carol", "pw")
    assert ok is False
    assert "backend=err" in detail
    assert "boom" in detail


def test_attribute_retrieval_uses_first_backend_with_attrs():
    srv = RADIUSServer()
    empty = StubBackend("empty", attrs=None)
    provider = StubBackend("attrs", attrs={"groups": ["netops"], "privilege_level": 15})
    srv.add_auth_backend(empty)
    srv.add_auth_backend(provider)
    attrs = srv._get_user_attributes("dave")
    assert attrs["groups"] == ["netops"]
    assert attrs["privilege_level"] == 15


def test_user_group_retrieval_from_backends():
    srv = RADIUSServer()
    okta = StubBackend("okta", attrs={"groups": ["OktaAdmins"], "privilege_level": 7})
    srv.add_auth_backend(okta)
    attrs = srv._get_user_attributes("erin")
    assert "OktaAdmins" in attrs["groups"]
    assert attrs["privilege_level"] == 7


# Additional backend scenarios
def test_ldap_backend_authentication(monkeypatch):
    srv = RADIUSServer()
    ldap_backend = StubBackend("ldap", authenticate_result=True)
    srv.add_auth_backend(ldap_backend)
    ok, detail = srv._authenticate_user("ldapuser", "pw")
    assert ok is True
    assert "backend=ldap" in detail


def test_okta_backend_with_group_enforcement():
    srv = RADIUSServer()
    okta_backend = StubBackend(
        "okta",
        authenticate_result=True,
        attrs={"groups": ["OktaAdmins"], "privilege_level": 9},
    )
    srv.add_auth_backend(okta_backend)
    attrs = srv._get_user_attributes("oktauser")
    assert "OktaAdmins" in attrs["groups"]
    assert attrs["privilege_level"] == 9


def test_backend_fallback_on_error():
    srv = RADIUSServer()
    err_backend = StubBackend("err", error=RuntimeError("fail"))
    good_backend = StubBackend("good", authenticate_result=True)
    srv.add_auth_backend(err_backend)
    srv.add_auth_backend(good_backend)
    ok, detail = srv._authenticate_user("user", "pw")
    assert ok is True
    assert "backend=good" in detail


def test_backend_attribute_retrieval():
    srv = RADIUSServer()
    backend = StubBackend("attrs", attrs={"groups": ["netops"], "privilege_level": 5})
    srv.add_auth_backend(backend)
    attrs = srv._get_user_attributes("bob")
    assert attrs["groups"] == ["netops"]
    assert attrs["privilege_level"] == 5
