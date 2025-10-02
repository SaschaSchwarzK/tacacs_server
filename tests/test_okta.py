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
    group_map=None,
    require_group=False,
):
    cfg = {
        "org_url": org_url,
        "client_id": client_id,
        "api_token": api_token,
        "cache_default_ttl": cache_default_ttl,
        "verify_tls": verify_tls,
    }
    if group_map is not None:
        cfg["group_privilege_map"] = json.dumps(group_map)
    if require_group:
        cfg["require_group_for_auth"] = "True"
    return cfg


def test_okta_authentication_and_authorization_caching(monkeypatch):
    group_map = {"Admins": 15, "Ops": 7}
    okta_cfg = _build_cfg(group_map=group_map)
    jwt = _make_jwt_with_exp(120)

    class FakeTokenResp:
        status_code = 200

        def __init__(self):
            self._data = {
                "access_token": jwt,
                "expires_in": 120,
                "id_token": jwt,
                "token_type": "Bearer",
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
        return FakeTokenResp()

    def fake_get(url, headers=None, verify=True, timeout=10):
        calls["get"] += 1
        if url.endswith("/userinfo"):
            return FakeUserinfoResp()
        if url.endswith("/groups") or "/groups" in url:
            return FakeGroupsResp([{"profile": {"name": "Admins"}}])
        return FakeUserinfoResp()

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", fake_get)
    backend = OktaAuthBackend(okta_cfg)
    assert backend.authenticate("admin", "password") is True
    assert calls["post"] == 1
    assert calls["get"] >= 2
    attrs = backend.get_user_attributes("admin")
    assert isinstance(attrs, dict)
    assert "token_response" in attrs or "access_token" in attrs
    assert attrs.get("privilege", 0) == 15
    assert backend.authenticate("admin", "password") is True
    assert calls["post"] == 1


def test_okta_require_group_for_auth_fails_when_no_group(monkeypatch):
    group_map = {"Admins": 15}
    okta_cfg = _build_cfg(group_map=group_map, require_group=True)
    jwt = _make_jwt_with_exp(60)

    class FakeTokenResp:
        status_code = 200

        def __init__(self):
            self._data = {"access_token": jwt, "expires_in": 60}

        def json(self):
            return self._data

    class FakeUserinfoResp:
        status_code = 200

        def __init__(self):
            self._data = {"sub": "okta-sub-321", "preferred_username": "userX"}

        def json(self):
            return self._data

    class FakeGroupsResp:
        status_code = 200

        def __init__(self, groups):
            self._data = groups

        def json(self):
            return self._data

    def fake_post(url, headers=None, data=None, json=None, verify=True, timeout=10):
        return FakeTokenResp()

    def fake_get(url, headers=None, verify=True, timeout=10):
        if url.endswith("/userinfo"):
            return FakeUserinfoResp()
        return FakeGroupsResp([{"profile": {"name": "Guests"}}])

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", fake_get)
    backend = OktaAuthBackend(okta_cfg)
    assert backend.authenticate("userX", "password") is False
    attrs = backend.get_user_attributes("userX")
    assert isinstance(attrs, dict)
