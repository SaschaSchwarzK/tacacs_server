# TACACS+ Server API Documentation

This document provides comprehensive documentation for all API endpoints available in the TACACS+ server.

## Table of Contents
- [Base URL](#base-url)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)
- [API Endpoints](#api-endpoints)
  - [Server Management](#server-management)
  - [Device Management](#device-management)
  - [Device Groups](#device-groups)
  - [User Management](#user-management)
  - [Authentication](#authentication-1)
  - [Logging & Monitoring](#logging--monitoring)
  - [Backup & Restore](#backup--restore)
- [OpenAPI Documentation](#openapi-documentation)
- [Examples](#examples)

## Base URL

The HTTP interface exposes:

- Admin UI (HTML): `/admin`
- JSON/REST API: `/api`

Typical base URL for API clients:

```
Base URL: http://localhost:8080/api
```

## Authentication

### Login (Admin UI / JSON)
```http
POST /admin/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your-password"
}
```

**Response:**
```json
{
  "success": true
}
```

### Using API Tokens
For non‑browser clients, configure an API token (via `API_TOKEN` env) and send it on `/api/*` requests:

- Header: `X-API-Token: <token>`
- Or: `Authorization: Bearer <token>`

The middleware accepts either a valid `admin_session` cookie **or** a matching API token for all `/api/*` paths except `/api/health` and `/api/status`.

## Rate Limiting

The HTTP admin/API layer currently does **not** emit `X-RateLimit-*` headers and does not enforce a dedicated per‑endpoint HTTP request budget.

Rate limiting is implemented at the TACACS+/RADIUS layer:
- A token‑bucket limiter (`RateLimiter`) is used for RADIUS/TACACS request flows (default 60 requests per IP per 60 seconds).
- An authentication limiter (`AuthRateLimiter`) caps TACACS authentication attempts per IP (default 5 attempts per 300 seconds).

These controls are implemented in `tacacs_server.utils.rate_limiter`, `tacacs_server.tacacs.limiter` and `tacacs_server.utils.security` and operate independently of the HTTP admin API.

## Error Handling

### Common Error Responses

**400 Bad Request**
```json
{
  "error": "validation_error",
  "message": "Invalid input data",
  "details": {
    "field_name": ["Error message"]
  }
}
```

**401 Unauthorized**
```json
{
  "error": "unauthorized",
  "message": "Authentication required"
}
```

**403 Forbidden**
```json
{
  "error": "forbidden",
  "message": "Insufficient permissions"
}
```

**404 Not Found**
```json
{
  "error": "not_found",
  "message": "Resource not found"
}
```

## API Endpoints

### Server Management

#### Get Server Status
```
GET /api/status
```

#### Reload Configuration
```
POST /api/admin/config/reload
```

### Device Management

#### List Devices
```
GET /api/devices
```

#### Create Device
```
POST /api/devices
```

#### Get Device
```
GET /api/devices/{id}
```

#### Update Device
```
PUT /api/devices/{id}
```

#### Delete Device
```
DELETE /api/devices/{id}
```

### Device Groups

#### List Device Groups
```
GET /api/device-groups
```

#### Create Device Group
```
POST /api/device-groups
```

#### Get Device Group
```
GET /api/device-groups/{id}
```

#### Update Device Group
```
PUT /api/device-groups/{id}
```

#### Delete Device Group
```
DELETE /api/device-groups/{id}
```

### User Management

#### List Users
```
GET /api/users
```

#### Create User
```
POST /api/users
```

#### Get User
```
GET /api/users/{username}
```

#### Update User
```
PUT /api/users/{username}
```

#### Delete User
```
DELETE /api/users/{username}
```

### Authentication

#### Login
```
POST /admin/login
```

#### Logout
```
POST /admin/logout
```

### Logging & Monitoring

#### Get Logs
```
GET /api/server/logs
```

### Backup & Restore

### Devices Configuration

- Section: `devices`
- Keys:
  - `auto_register` (boolean, default `false`): When enabled, unknown devices contacting TACACS+ are automatically added as single-host entries and assigned to `default_group`. Defaults to `false` for stricter security; enable explicitly when needed.
  - `default_group` (string, default `default`): Group name used for auto-registered devices.
  - `identity_cache_ttl_seconds` (int, optional): Cache TTL for device identity lookups.
  - `identity_cache_size` (int, optional): Max entries for device identity cache.

Notes:
- Auto-registration applies to both TACACS+ and RADIUS.
- For RADIUS, ensure the `default_group` defines a RADIUS shared secret so newly created clients can authenticate.

Update via Admin API:

PUT `/api/admin/config/devices`

Body:

```
{ "updates": { "auto_register": true, "default_group": "default" } }
```

Or batch update multiple sections:

PUT `/api/admin/config`

Body:

```
{ "devices": { "auto_register": "false", "default_group": "Strict" } }
```

### Backup & Restore

Backup/admin endpoints are exposed under:

```
Base path: /api/admin/backup
```

For detailed, field‑level documentation of all backup endpoints (destinations, executions, schedules, uploads/downloads), see `docs/api/backup.md`. This file is kept in sync with the implementation in `tacacs_server/web/api/backup.py`.

## OpenAPI Documentation

The complete API specification is available via OpenAPI:
- **Swagger UI**: `/api/docs`
- **ReDoc**: `/api/redoc`

## Examples

### Create a New Device
```http
POST /api/devices
Content-Type: application/json
X-API-Token: your-token

{
  "name": "core-switch-01",
  "ip_address": "192.168.1.1",
  "description": "Core network switch",
  "enabled": true
}
```

### Update Device Group
```http
PUT /api/device-groups/1
Content-Type: application/json
X-API-Token: your-token

{
  "name": "Core-Devices",
  "description": "Updated description",
  "enabled": true
}
```

### Get Server Logs
```http
GET /api/server/logs?limit=100&level=error
X-API-Token: your-token
```

### Update Device Group

`PUT /api/device-groups/{id}`

Request body (partial updates allowed):

```json
{
  "proxy_network": "10.10.0.0/16",
  "description": "Updated"
}
```

Response body includes:

- `id`: integer
- `name`: string
- `description`: string | null
- `proxy_network`: string | null
- `tacacs_secret_set`: boolean
- `radius_secret_set`: boolean
- `allowed_user_groups`: list
- `device_count`: integer

## TACACS+ Extensions/Deviations

- Per-device-group secrets: The server selects TACACS+ shared secrets from the device group rather than a global secret.
- Sequence checks: The server enforces odd sequence numbers and monotonic progression, with a tolerant reset window for client restarts.
- Max packet length: Configurable `max_packet_length` (default 4096). Packets exceeding this are rejected.
- Minimal authorization: If no command is requested and user attributes are missing, the server grants a minimal service profile to satisfy certain device behaviors.
- Command authorization hook: Optional pluggable policy engine can evaluate `cmd` requests with group and privilege context.
- Accounting: Persisted to SQLite with materialized daily aggregates for reporting.

These behaviors are implemented to balance interoperability and security, and are called out in code comments and logs where relevant.
