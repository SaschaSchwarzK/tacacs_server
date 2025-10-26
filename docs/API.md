# API and Protocol Notes

## OpenAPI

The REST API is documented via the generated OpenAPI schema. Key categories:
- Status & Health, Devices, Device Groups, Users, User Groups, Authentication, Accounting, RADIUS

To view:
- Swagger UI: `/docs`
- ReDoc: `/redoc`

## Device Groups API (Proxy-aware)

### Create Device Group

`POST /api/device-groups`

Request body:

```json
{
  "name": "Core-Routers",
  "description": "All core network routers",
  "proxy_network": "10.0.0.0/8",
  "tacacs_secret": "TacacsSecret123!",
  "radius_secret": "RadiusSecret123!",
  "allowed_user_groups": [1, 2]
}
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
