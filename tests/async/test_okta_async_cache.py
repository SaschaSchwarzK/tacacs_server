from __future__ import annotations

import asyncio

import pytest


class _Resp:
    def __init__(self, status_code=200, json_payload=None):
        self.status_code = status_code
        self._json = json_payload or {}

    def json(self):
        return self._json


class _AsyncClient:
    def __init__(self, *args, **kwargs):
        self._args = args
        self._kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, data=None, headers=None):
        # Simulate token endpoint
        return _Resp(200, {"access_token": "tok123", "expires_in": 3600})

    async def get(self, url, headers=None):
        # Simulate userinfo endpoint
        return _Resp(200, {"name": "Okta User", "email": "okta@example.com"})


@pytest.mark.asyncio
async def test_okta_async_token_and_userinfo(monkeypatch):
    from tacacs_server.auth.okta_auth import OktaAuthBackend

    # Monkeypatch httpx.AsyncClient to our stub
    import tacacs_server.auth.okta_auth as okta_mod

    monkeypatch.setitem(okta_mod.__dict__, "httpx", type("_M", (), {"AsyncClient": _AsyncClient, "Timeout": lambda *a, **k: 1}))

    cfg = {
        "org_url": "https://dev.example.com",
        "client_id": "cid",
        "ropc_enabled": True,
        "trust_env": False,
    }
    b = OktaAuthBackend(cfg)
    ok = await b.authenticate_async("user", "pass")
    assert ok is True
    attrs = await b.get_user_attributes_async("user")
    assert isinstance(attrs, dict)
    assert attrs.get("full_name") == "Okta User"
