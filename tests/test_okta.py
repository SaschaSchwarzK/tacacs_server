import base64
import json
import time

import requests

from tacacs_server.auth.okta_auth import OktaAuthBackend


def _make_jwt_with_exp(seconds_from_now: int) -> str:
    payload = {"exp": int(time.time()) + seconds_from_now}
    b = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    return "h." + b.decode("ascii") + ".s"


def _build_cfg(
    org_url="https://integrator-xxxx.okta.com/",
    client_id="xxxxx",
    api_token="00pmLQ0dxxxxxxx2V-_cnxxxxx3C",
    cache_default_ttl="60",
    verify_tls="False",
    require_group=False,
):
    cfg = {
        "org_url": org_url,
        "client_id": client_id,
        "api_token": api_token,
        "cache_default_ttl": cache_default_ttl,
        "verify_tls": verify_tls,
    }
    if require_group:
        cfg["require_group_for_auth"] = "True"
    return cfg


def test_okta_authentication_and_authorization_caching(monkeypatch):
    okta_cfg = _build_cfg()

    class FakeAuthnResp:
        status_code = 200

        def __init__(self):
            self._data = {
                "status": "SUCCESS",
                "sessionToken": "dummy",
                "_embedded": {"user": {"id": "okta-sub-123"}},
            }

        def json(self):
            return self._data

    class FakeUserinfoResp:
        status_code = 200

        def __init__(self):
            self._data = {"sub": "okta-sub-123", "preferred_username": "admin"}

        def json(self):
            return self._data

    class FakeGroupsResp:
        status_code = 200

        def __init__(self, groups):
            self._data = groups

        def json(self):
            return self._data

    calls = {"post": 0, "get": 0}

    def fake_post(url, headers=None, data=None, json=None, verify=True, timeout=10):
        calls["post"] += 1
        if "/api/v1/authn" in url:
            return FakeAuthnResp()
        # fallback legacy
        return FakeAuthnResp()

    def fake_get(url, headers=None, verify=True, timeout=10):
        calls["get"] += 1
        if url.endswith("/groups") or "/groups" in url:
            return FakeGroupsResp([{"profile": {"name": "Admins"}}])
        return FakeGroupsResp([])

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", fake_get)
    backend = OktaAuthBackend(okta_cfg)
    assert backend.authenticate("admin", "password") is True
    assert calls["post"] == 1
    assert calls["get"] >= 1
    attrs = backend.get_user_attributes("admin")
    assert isinstance(attrs, dict)
    assert "okta_user_id" in attrs
    assert backend.authenticate("admin", "password") is True
    assert calls["post"] == 1


def test_okta_require_group_for_auth_fails_when_no_group(monkeypatch):
    okta_cfg = _build_cfg(require_group=True)

    class FakeAuthnResp2:
        status_code = 200

        def __init__(self):
            self._data = {
                "status": "SUCCESS",
                "sessionToken": "dummy2",
                "_embedded": {"user": {"id": "okta-sub-321"}},
            }

        def json(self):
            return self._data

    class FakeGroupsResp:
        status_code = 200

        def __init__(self, groups):
            self._data = groups

        def json(self):
            return self._data

    def fake_post(url, headers=None, data=None, json=None, verify=True, timeout=10):
        return FakeAuthnResp2()

    def fake_get(url, headers=None, verify=True, timeout=10):
        return FakeGroupsResp([{"profile": {"name": "Guests"}}])

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", fake_get)
    backend = OktaAuthBackend(okta_cfg)
    assert backend.authenticate("userX", "password") is False
    attrs = backend.get_user_attributes("userX")
    assert isinstance(attrs, dict)
