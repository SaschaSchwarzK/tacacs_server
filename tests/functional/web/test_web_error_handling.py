"""Functional-style tests for web error handling."""

import concurrent.futures

from fastapi import Body, HTTPException, status
from fastapi.testclient import TestClient
from pydantic import BaseModel

from tacacs_server.web import app_setup


class Payload(BaseModel):
    name: str


def _build_app():
    app = app_setup.create_app()

    @app.get("/ok")
    async def ok():
        return {"status": "ok"}

    @app.get("/boom")
    async def boom():
        raise RuntimeError("boom")

    @app.post("/echo")
    async def echo(payload: Payload = Body(...)):
        return payload

    @app.get("/auth-required")
    async def auth_required():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing auth"
        )

    return app


def test_not_found_and_internal_errors():
    """Verify 404 and 500 responses are formatted as expected."""
    client = TestClient(_build_app(), raise_server_exceptions=False)
    not_found = client.get("/nope")
    assert not_found.status_code == 404
    assert not_found.json()["detail"] == "Not Found"

    server_error = client.get("/boom")
    assert server_error.status_code == 500
    payload = server_error.json()
    assert payload["error"] == "Internal server error"
    assert payload["details"] == "An unexpected error occurred"


def test_invalid_json_payloads_return_validation_error():
    """Invalid JSON produces structured validation response."""
    client = TestClient(_build_app(), raise_server_exceptions=False)
    resp = client.post("/echo", data="not-json", headers={"Content-Type": "application/json"})
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"] == "Validation failed"
    assert body["validation_errors"]


def test_missing_auth_headers_return_unauthorized():
    """Auth guard responses surface proper status and detail."""
    client = TestClient(_build_app(), raise_server_exceptions=False)
    resp = client.get("/auth-required")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Missing auth"


def test_concurrent_requests_handled():
    """Multiple simultaneous requests succeed."""
    client = TestClient(_build_app(), raise_server_exceptions=False)

    def _hit():
        r = client.get("/ok")
        return r.status_code, r.json().get("status")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _: _hit(), range(10)))

    assert all(status_code == 200 for status_code, _ in results)
    assert all(body == "ok" for _, body in results)
