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

All API endpoints are prefixed with `/admin` and require authentication.

```
Base URL: http://localhost:8080/admin
```

## Authentication

### Login
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
  "success": true,
  "token": "your-jwt-token"
}
```

### Using API Tokens
Include the token in the `Authorization` header:
```
Authorization: Bearer your-jwt-token
```

## Rate Limiting
- 100 requests per minute per IP address
- 10 login attempts per minute per IP
- Headers included in responses:
  - `X-RateLimit-Limit`: Request limit
  - `X-RateLimit-Remaining`: Remaining requests
  - `X-RateLimit-Reset`: Time when limit resets (UTC timestamp)

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
GET /admin/server/status
```

#### Reload Configuration
```
POST /admin/server/reload-config
```

### Device Management

#### List Devices
```
GET /admin/devices
```

#### Create Device
```
POST /admin/devices
```

#### Get Device
```
GET /admin/devices/{id}
```

#### Update Device
```
PUT /admin/devices/{id}
```

#### Delete Device
```
DELETE /admin/devices/{id}
```

### Device Groups

#### List Device Groups
```
GET /admin/device-groups
```

#### Create Device Group
```
POST /admin/device-groups
```

#### Get Device Group
```
GET /admin/device-groups/{id}
```

#### Update Device Group
```
PUT /admin/device-groups/{id}
```

#### Delete Device Group
```
DELETE /admin/device-groups/{id}
```

### User Management

#### List Users
```
GET /admin/users
```

#### Create User
```
POST /admin/users
```

#### Get User
```
GET /admin/users/{id}
```

#### Update User
```
PUT /admin/users/{id}
```

#### Delete User
```
DELETE /admin/users/{id}
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
GET /admin/logs
```

### Backup & Restore

### Devices Configuration

- Section: `devices`
- Keys:
  - `auto_register` (boolean, default `true`): When enabled, unknown devices contacting TACACS+ are automatically added as single-host entries and assigned to `default_group`.
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

#### Create Backup
```
POST /admin/backup
```

#### List Backups
```
GET /admin/backup
```

#### Restore Backup
```
POST /admin/backup/restore
```

## OpenAPI Documentation

The complete API specification is available via OpenAPI:
- **Swagger UI**: `/docs`
- **ReDoc**: `/redoc`

## Examples

### Create a New Device
```http
POST /admin/devices
Content-Type: application/json
Authorization: Bearer your-jwt-token

{
  "name": "core-switch-01",
  "ip_address": "192.168.1.1",
  "description": "Core network switch",
  "enabled": true
}
```

### Update Device Group
```http
PUT /admin/device-groups/1
Content-Type: application/json
Authorization: Bearer your-jwt-token

{
  "name": "Core-Devices",
  "description": "Updated description",
  "enabled": true
}
```

### Get Server Logs
```http
GET /admin/logs?limit=100&level=error
Authorization: Bearer your-jwt-token
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
