# API Reference

This document provides a complete reference for all REST API endpoints available in the TACACS+ server.

## Base URL

```
http://localhost:8080/api
```

## Authentication

All API endpoints require authentication via API token:

```bash
# Set API token
export API_TOKEN="your-strong-token"

# Use in requests
curl -H "X-API-Token: $API_TOKEN" http://localhost:8080/api/status
# OR
curl -H "Authorization: Bearer $API_TOKEN" http://localhost:8080/api/status
```

## Status & Health Endpoints

### GET /api/status
Get server status and basic statistics.

**Response:**
```json
{
  "status": "running",
  "uptime": 3600,
  "version": "1.0.0",
  "auth_backends": ["local", "ldap"],
  "connections": {
    "active": 5,
    "total": 1250
  }
}
```

### GET /api/health
Health check endpoint for monitoring systems.

**Response:**
```json
{
  "status": "healthy",
  "checks": {
    "database": "ok",
    "auth_backends": "ok",
    "memory_usage": "ok"
  }
}
```

## Device Management

### GET /api/devices
List all devices with optional filtering.

**Query Parameters:**
- `search` - Filter by device name or IP
- `group` - Filter by device group
- `enabled` - Filter by enabled status

**Response:**
```json
{
  "devices": [
    {
      "id": 1,
      "name": "core-switch-01",
      "network": "192.168.1.1/32",
      "group": "core-devices",
      "enabled": true,
      "created_at": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

### POST /api/devices
Create a new device.

**Request Body:**
```json
{
  "name": "new-device",
  "network": "192.168.1.10/32",
  "group": "default",
  "description": "New network device",
  "enabled": true
}
```

### GET /api/devices/{id}
Get device details by ID.

### PUT /api/devices/{id}
Update device configuration.

### DELETE /api/devices/{id}
Delete a device.

## Device Groups

### GET /api/device-groups
List all device groups.

### POST /api/device-groups
Create a new device group.

**Request Body:**
```json
{
  "name": "new-group",
  "description": "New device group",
  "tacacs_secret": "secret123",
  "radius_secret": "radius123",
  "proxy_network": "10.0.0.0/8"
}
```

## User Management

### GET /api/users
List local users.

### POST /api/users
Create a new local user.

**Request Body:**
```json
{
  "username": "newuser",
  "password": "password123",
  "groups": ["operators"],
  "enabled": true
}
```

## Administrative Endpoints

### POST /api/admin/reload-config
Reload server configuration.

### GET /api/admin/logs
Get recent log entries.

**Query Parameters:**
- `limit` - Number of entries (default: 100)
- `level` - Log level filter

For complete API documentation with interactive examples, visit:
- Swagger UI: http://localhost:8080/docs
- ReDoc: http://localhost:8080/redoc