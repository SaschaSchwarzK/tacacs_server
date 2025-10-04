# TACACS+ Server API Reference

This document provides comprehensive documentation for all API endpoints available in the TACACS+ server admin interface.

## Base URL

All API endpoints are prefixed with `/admin` and require authentication.

```
Base URL: http://localhost:8080/admin
```

## Authentication

All API endpoints require authentication via session cookie or JSON login.

### Login
```http
POST /admin/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

**Response:**
```json
{
  "success": true
}
```

### Logout
```http
POST /admin/logout
```

## Server Control Endpoints

### Reload Configuration
Reload the server configuration without restarting.

```http
POST /admin/server/reload-config
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration reloaded"
}
```

### Reset Statistics
Reset all server statistics counters.

```http
POST /admin/server/reset-stats
```

**Response:**
```json
{
  "success": true,
  "message": "Statistics reset"
}
```

### Get Server Logs
Retrieve recent server log entries.

```http
GET /admin/server/logs?lines=100
```

**Response:**
```json
{
  "logs": [
    "2024-01-01 12:00:00 - INFO - Server started",
    "2024-01-01 12:01:00 - INFO - User authenticated"
  ],
  "count": 2
}
```

### Get Server Status
Get detailed server status including TACACS+ and RADIUS statistics.

```http
GET /admin/server/status
```

**Response:**
```json
{
  "tacacs": {
    "running": true,
    "uptime_seconds": 3600,
    "connections": {
      "active": 5,
      "total": 100
    },
    "authentication": {
      "requests": 50,
      "successes": 45,
      "failures": 5
    }
  },
  "radius": {
    "enabled": true,
    "running": true,
    "authentication": {
      "requests": 10,
      "accepts": 8,
      "rejects": 2
    }
  }
}
```

## Device Management

### List Devices
Get all configured devices.

```http
GET /admin/devices
Accept: application/json
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "router1",
    "network": "192.168.1.0/24",
    "group": "routers",
    "group_radius_secret": true,
    "group_tacacs_secret": true
  }
]
```

### Create Device
Create a new device.

```http
POST /admin/devices
Content-Type: application/json

{
  "name": "router1",
  "network": "192.168.1.0/24",
  "group": "routers"
}
```

**Response:**
```json
{
  "id": 1
}
```

### Get Device
Get a specific device by ID.

```http
GET /admin/devices/1
```

**Response:**
```json
{
  "id": 1,
  "name": "router1",
  "network": "192.168.1.0/24",
  "group": "routers"
}
```

### Update Device
Update an existing device.

```http
PUT /admin/devices/1
Content-Type: application/json

{
  "name": "router1-updated",
  "network": "192.168.1.0/24",
  "group": "routers"
}
```

**Response:**
```json
{
  "id": 1
}
```

### Delete Device
Delete a device.

```http
DELETE /admin/devices/1
```

**Response:** `204 No Content`

## Device Group Management

### List Device Groups
Get all device groups.

```http
GET /admin/groups
Accept: application/json
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "routers",
    "description": "Router group",
    "metadata": {},
    "radius_secret": true,
    "tacacs_secret": true,
    "device_config": null,
    "allowed_user_groups": ["admins", "operators"]
  }
]
```

### Create Device Group
Create a new device group.

```http
POST /admin/groups
Content-Type: application/json

{
  "name": "routers",
  "description": "Router group",
  "tacacs_secret": "tacacs_secret123",
  "radius_secret": "radius_secret123",
  "allowed_user_groups": ["admins", "operators"]
}
```

**Response:**
```json
{
  "id": 1
}
```

### Get Device Group
Get a specific device group by ID.

```http
GET /admin/groups/1
```

**Response:**
```json
{
  "id": 1,
  "name": "routers",
  "description": "Router group",
  "metadata": {},
  "radius_secret": "radius_secret123",
  "tacacs_secret": "tacacs_secret123",
  "device_config": null,
  "allowed_user_groups": ["admins", "operators"]
}
```

### Update Device Group
Update an existing device group.

```http
PUT /admin/groups/1
Content-Type: application/json

{
  "description": "Updated router group",
  "allowed_user_groups": ["admins"]
}
```

**Response:**
```json
{
  "id": 1
}
```

### Delete Device Group
Delete a device group.

```http
DELETE /admin/groups/1?cascade=false
```

**Response:** `204 No Content`

### Get Group Devices
Get all devices in a specific group.

```http
GET /admin/groups/1/devices
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "router1",
    "network": "192.168.1.0/24",
    "group_id": 1
  }
]
```

## User Management

### List Users
Get all local users.

```http
GET /admin/users
Accept: application/json
```

**Response:**
```json
[
  {
    "username": "testuser",
    "privilege_level": 1,
    "service": "exec",
    "shell_command": ["show"],
    "groups": ["users"],
    "enabled": true,
    "description": null
  }
]
```

### Create User
Create a new local user.

```http
POST /admin/users
Content-Type: application/json

{
  "username": "testuser",
  "password": "Password123",
  "privilege_level": 1,
  "service": "exec",
  "shell_command": ["show"],
  "groups": ["users"],
  "enabled": true,
  "description": "Test user"
}
```

**Response:**
```json
{
  "username": "testuser"
}
```

### Get User
Get a specific user by username.

```http
GET /admin/users/testuser
```

**Response:**
```json
{
  "username": "testuser",
  "privilege_level": 1,
  "service": "exec",
  "shell_command": ["show"],
  "groups": ["users"],
  "enabled": true,
  "description": "Test user"
}
```

### Update User
Update an existing user.

```http
PUT /admin/users/testuser
Content-Type: application/json

{
  "privilege_level": 15,
  "groups": ["admins"],
  "description": "Updated user"
}
```

**Response:**
```json
{
  "username": "testuser"
}
```

### Set User Password
Update a user's password.

```http
POST /admin/users/testuser/password
Content-Type: application/json

{
  "password": "NewPassword123"
}
```

**Response:**
```json
{
  "username": "testuser"
}
```

### Delete User
Delete a user.

```http
DELETE /admin/users/testuser
```

**Response:** `204 No Content`

## User Group Management

### List User Groups
Get all user groups.

```http
GET /admin/user-groups
Accept: application/json
```

**Response:**
```json
[
  {
    "name": "admins",
    "description": "Administrator group",
    "metadata": {},
    "ldap_group": "cn=admins,ou=groups,dc=example,dc=com",
    "okta_group": "admins",
    "privilege_level": 15
  }
]
```

### Create User Group
Create a new user group.

```http
POST /admin/user-groups
Content-Type: application/json

{
  "name": "admins",
  "description": "Administrator group",
  "privilege_level": 15,
  "ldap_group": "cn=admins,ou=groups,dc=example,dc=com",
  "okta_group": "admins"
}
```

**Response:**
```json
{
  "name": "admins"
}
```

### Get User Group
Get a specific user group by name.

```http
GET /admin/user-groups/admins
```

**Response:**
```json
{
  "name": "admins",
  "description": "Administrator group",
  "metadata": {},
  "ldap_group": "cn=admins,ou=groups,dc=example,dc=com",
  "okta_group": "admins",
  "privilege_level": 15
}
```

### Update User Group
Update an existing user group.

```http
PUT /admin/user-groups/admins
Content-Type: application/json

{
  "description": "Updated administrator group",
  "privilege_level": 15
}
```

**Response:**
```json
{
  "name": "admins"
}
```

### Delete User Group
Delete a user group.

```http
DELETE /admin/user-groups/admins
```

**Response:** `204 No Content`

## Configuration Management

### View Configuration
Get the current server configuration.

```http
GET /admin/config
Accept: application/json
```

**Response:**
```json
{
  "source": "config/tacacs.conf",
  "configuration": {
    "server": {
      "host": "0.0.0.0",
      "port": "49",
      "secret_key": "[redacted len=10]"
    },
    "auth": {
      "backends": "local",
      "local_auth_db": "data/local_auth.db"
    }
  }
}
```

### Update Configuration
Update server configuration sections.

```http
PUT /admin/config
Content-Type: application/json

{
  "server": {
    "host": "0.0.0.0",
    "port": "49"
  },
  "auth": {
    "backends": "local,ldap"
  },
  "ldap": {
    "server": "ldap://localhost:389",
    "base_dn": "dc=example,dc=com"
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated"
}
```

## Monitoring and Statistics

### Get Detailed Statistics
Get comprehensive server statistics.

```http
GET /admin/stats
```

**Response:**
```json
{
  "server": {
    "running": true,
    "uptime_seconds": 3600,
    "memory_usage": {
      "rss_mb": 128,
      "percent": 2.5
    },
    "connections": {
      "active": 5,
      "total": 100
    },
    "authentication": {
      "requests": 50,
      "successes": 45,
      "failures": 5
    }
  },
  "backends": [
    {
      "name": "local",
      "type": "LocalAuthBackend",
      "available": true,
      "stats": {}
    }
  ],
  "database": {
    "total_records": 1000,
    "unique_users": 50
  },
  "sessions": {
    "active_count": 3,
    "sessions": []
  }
}
```

### Get Authentication Backends
Get status of all authentication backends.

```http
GET /admin/backends
```

**Response:**
```json
[
  {
    "name": "local",
    "type": "LocalAuthBackend",
    "available": true,
    "stats": {}
  },
  {
    "name": "ldap",
    "type": "LDAPAuthBackend",
    "available": false,
    "stats": {}
  }
]
```

### Get Accounting Records
Get recent accounting records.

```http
GET /admin/accounting/records?hours=24&limit=100
```

**Response:**
```json
{
  "records": [
    {
      "username": "testuser",
      "session_id": 12345,
      "status": "START",
      "service": "exec",
      "command": "show version",
      "client_ip": "192.168.1.100",
      "timestamp": "2024-01-01T12:00:00Z"
    }
  ],
  "count": 1,
  "period_hours": 24
}
```

### Get Active Sessions
Get currently active TACACS+ sessions.

```http
GET /admin/sessions/active
```

**Response:**
```json
{
  "sessions": [
    {
      "session_id": 12345,
      "username": "testuser",
      "client_ip": "192.168.1.100",
      "start_time": "2024-01-01T12:00:00Z",
      "service": "exec"
    }
  ],
  "count": 1
}
```

## Error Responses

All endpoints return appropriate HTTP status codes and error messages:

### 400 Bad Request
```json
{
  "detail": "Invalid input data"
}
```

### 401 Unauthorized
```json
{
  "detail": "Invalid credentials"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 409 Conflict
```json
{
  "detail": "Resource already exists"
}
```

### 503 Service Unavailable
```json
{
  "detail": "Service unavailable"
}
```

## Input Validation

All API endpoints perform comprehensive input validation:

- **Usernames**: Alphanumeric + underscore/dot/dash, max 64 characters
- **Passwords**: Minimum 8 characters, complexity requirements
- **Networks**: Valid IP networks (CIDR notation)
- **Privilege Levels**: Integer 0-15
- **Secrets**: Minimum 8 characters for shared secrets
- **JSON**: Depth limiting to prevent DoS attacks

## Security Features

- **Authentication**: Session-based authentication required for all endpoints
- **Input Validation**: Comprehensive validation prevents injection attacks
- **SQL Injection Prevention**: Parameterized queries throughout
- **LDAP Injection Prevention**: Character escaping and filtering
- **Rate Limiting**: Protection against brute force attacks
- **Log Sanitization**: All user input sanitized in logs
- **Secure Defaults**: Safe configuration defaults

## Rate Limits

- Authentication attempts: 5 per IP per 5 minutes
- API requests: No specific limits (controlled by session timeout)

## Examples

### Complete Device Management Workflow

```bash
# 1. Login
curl -X POST http://localhost:8080/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}' \
  -c cookies.txt

# 2. Create device group
curl -X POST http://localhost:8080/admin/groups \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "name": "routers",
    "description": "Router group",
    "tacacs_secret": "router_secret123",
    "allowed_user_groups": ["admins"]
  }'

# 3. Create device
curl -X POST http://localhost:8080/admin/devices \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "name": "router1",
    "network": "192.168.1.0/24",
    "group": "routers"
  }'

# 4. List devices
curl -X GET http://localhost:8080/admin/devices \
  -H "Accept: application/json" \
  -b cookies.txt

# 5. Logout
curl -X POST http://localhost:8080/admin/logout \
  -b cookies.txt
```

This API provides complete programmatic access to all TACACS+ server functionality available through the web interface.