# Structured Logging Guide (log.v1)

This project emits newline‑delimited JSON logs using a stable internal schema (`schema: "log.v1"`). Logs are machine‑parseable and safe for production ingestion while remaining readable during development.

## Quick Example

```json
{
  "schema": "log.v1",
  "ts": "2025-11-01T08:40:23.689198Z",
  "t_monotonic_ms": 1112863375,
  "level": "INFO",
  "event": "service.start",
  "message": "TACACS server listening",
  "service": "tacacs",
  "env": "dev",
  "host": "node-123",
  "instance_id": "a1b2c3d4e5f6",
  "instance_name": "tacacs-node-123",
  "trace_id": "",
  "span_id": "",
  "correlation_id": "e4b7a540-8aa7-4b3a-9f8a-1f6e2f8b2b7e",
  "auth": {"backend": "local", "result": "success"},
  "client": {"ip": "10.1.2.xxx"}
}
```

## Core Concepts

- Newline‑delimited JSON to stdout (and optional file/syslog via config).
- Stable schema tagged with `schema: "log.v1"` for compatibility and validation.
- Redaction and safe defaults to avoid leaking secrets by default.
- Correlation across requests and connections (HTTP + TACACS).

## Schema (log.v1)

Required top‑level fields (see `docs/logging.json` for full JSON Schema):

- `schema`: constant string `log.v1`
- `ts`: RFC3339 UTC timestamp
- `t_monotonic_ms`: monotonic time in milliseconds (for precise durations)
- `level`: one of `TRACE, DEBUG, INFO, WARN, ERROR, FATAL`
- `event`: short machine‑friendly event name (e.g., `service.start`, `auth.success`)
- `message`: short, human‑scannable description
- `service`: logical service name (`tacacs`, `radius`, `web`, `tacacs_server` for generic)
- `env`: `dev | staging | prod | test`
- `host`: machine/container hostname (DNS‑free; see Identity below)
- `trace_id`, `span_id`: reserved for tracing integrations
- `correlation_id`: per request/connection correlation token

Common nested structures:

- `client`: `{ ip, port?, user_agent? }`
- `auth`: `{ backend: okta|ldap|local|radius|none, mfa?, result: success|failure|denied|error }`
- `policy`: `{ id?, rule?, decision? }`

Additional fields like `instance_id`, `instance_name`, `device_id`, `user_ref`, `duration_ms`, etc., may be included as needed.

## Levels

- `TRACE`: deep diagnostic spans
- `DEBUG`: development troubleshooting
- `INFO`: normal operation (service start/stop, successful auth)
- `WARN`: handled but unexpected conditions (rate limit, degraded mode)
- `ERROR`: failures or denied actions due to errors/policy
- `FATAL`: process unusable

## Correlation

- HTTP: middleware binds `correlation_id` per request
  - Uses `X-Correlation-ID` header if provided; else generates UUIDv4
  - Added to every log on that request and cleared after response
- TACACS: per‑connection `correlation_id` (generated UUIDv4) bound at accept time
  - Auth logs also include `session` as hex (e.g., `0x001234ab`)
- `t_monotonic_ms` is provided for precise interval math (`end - start`) without wall‑clock drift

## Identity (Host and Instance)

- `host` resolution avoids DNS to stay fast and resilient:
  1. `HOSTNAME` env
  2. `/etc/hostname`
  3. `socket.gethostname()`
- `instance_id` and `instance_name` are bound from the configuration store on startup and included in logs to uniquely identify the running node.

## Security & Redaction

- Sensitive keys (case‑insensitive): `password, pass, passwd, secret, api_key, token, authorization, private_key, client_secret, radius_secret, tacacs_key, otp, mfa_code` should never appear in cleartext.
- Pattern redactions (see `docs/logging.json`) are applied in producers as needed (e.g., masking JWTs or PEM keys).
- Do not log request/response bodies for auth endpoints. Log minimal headers only.

## Common Events

- `service.start` / `service.stop` — lifecycle
- `auth.request` / `auth.success` / `auth.failure` — authentication
- `command_auth.*` — command authorization API
- `tacacs.request` / `tacacs.reply` and `radius.request` / `radius.reply` (where applicable)

## RADIUS Logging

RADIUS logs follow the same `log.v1` schema. Lifecycle events use `service=radius`.

Per‑packet correlation: because RADIUS is UDP (no connection), the server generates a `correlation_id` for each received packet and binds it for the duration of handling that packet. This allows grouping of request/response and any errors.

Example (authentication accept):

```json
{
  "schema": "log.v1",
  "ts": "2025-11-01T08:55:12.123456Z",
  "t_monotonic_ms": 1114000123,
  "level": "INFO",
  "event": "service.start",
  "message": "RADIUS server listening",
  "service": "radius",
  "env": "prod",
  "host": "node-456",
  "auth_port": 1812,
  "acct_port": 1813
}
{
  "schema": "log.v1",
  "ts": "2025-11-01T08:55:18.222222Z",
  "t_monotonic_ms": 1114006789,
  "level": "INFO",
  "event": "auth.success",
  "message": "RADIUS authentication success",
  "service": "radius",
  "host": "node-456",
  "correlation_id": "b2d1e7f3-0a1b-41e0-8b8d-2f49c6b8c0a1",
  "auth": {"backend": "local", "result": "success"},
  "client": {"ip": "10.1.2.xxx"},
  "user_ref": "alice",
  "device": "branch-router"
}
```

Detailed (DEBUG) request/reply traces:

```json
{
  "schema": "log.v1",
  "ts": "2025-11-01T08:55:18.220000Z",
  "t_monotonic_ms": 1114006700,
  "level": "DEBUG",
  "event": "radius.request",
  "message": "RADIUS request",
  "service": "radius",
  "client": {"ip": "10.1.2.3", "port": 54321},
  "code": 1,
  "nas_ip": "10.9.0.1",
  "nas_port": 1,
  "client_group": "edge-routers"
}
{
  "schema": "log.v1",
  "ts": "2025-11-01T08:55:18.223000Z",
  "t_monotonic_ms": 1114006790,
  "level": "DEBUG",
  "event": "radius.reply",
  "message": "RADIUS response",
  "service": "radius",
  "client": {"ip": "10.1.2.3", "port": 54321},
  "code": 2,
  "status": "accept"
}
```

## Usage Patterns

In code, prefer structured logs via the shared logger:

```python
from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)

logger.info(
    "TACACS server listening",
    event="service.start",
    service="tacacs",
    host=bind_host,
    port=self.port,
)

logger.debug(
    "HTTP request",
    event="http.request",
    service="web",
    method=request.method,
    path=str(request.url.path),
    client={"ip": request.client.host},
)
```

## Configuration

- Log level, rotation, and optional syslog sink are configured via the `[logging]` section of `config/tacacs.conf`.
- Format is always structured JSON; custom text formats are ignored by design to preserve machine‑readability.

## Validation

- The formal schema and guidelines live in `docs/logging.json`.
- You can validate logs by sampling a few lines and checking required fields are present (`schema, ts, level, event, message, service, env, host, correlation_id`).

## Troubleshooting

- Missing `correlation_id` on early startup logs is expected (binding occurs after the web or TACACS subsystems initialize). Subsequent request/connection logs include it.
- If `host` looks generic, ensure `HOSTNAME` is set or `/etc/hostname` is populated in your container image.
