# Backup API Reference

Authentication: All endpoints require an authenticated admin session or API token header.

- Header: `X-API-Token: <token>` or `Authorization: Bearer <token>`

Base path: `/api/admin/backup`

## Destinations

### POST /destinations
Create a new backup destination.

Request (JSON):
```
{
  "name": "local_daily",
  "type": "local",
  "config": {"base_path": "/backups/tacacs"},
  "retention_days": 30
}
```

Response 200 (JSON):
```
{ "id": "<uuid>", "name": "local_daily", "type": "local", "connection_test": "passed" }
```

Errors:
- 400 Invalid config/connection test failed
- 401 Unauthorized
- 409 Name conflict (if enforced by DB uniqueness)

### GET /destinations
List all destinations.

Response 200:
```
{ "destinations": [ { "id": "...", "name": "...", "type": "local", "enabled": true, "config": { ... }, ... } ] }
```

### GET /destinations/{id}
Get a destination by ID.
- 404 if not found

### PUT /destinations/{id}
Update destination metadata/config. If `config` is present, a connection test is performed.
- 400 on connection test failed
- 404 if not found

### DELETE /destinations/{id}
Delete a destination.
- 400 if executions/backups exist
- 404 if not found

### POST /destinations/{id}/test
Test connectivity.
Response 200:
```
{ "success": true, "message": "OK", "tested_at": "<ISO8601>" }
```

### PUT /destinations/{id}/retention
Update retention policy for destination.

Request Body (examples):
```
{ "strategy": "simple", "keep_days": 30 }

{ "strategy": "gfs", "keep_daily": 7, "keep_weekly": 4, "keep_monthly": 12, "keep_yearly": 3 }

{ "strategy": "hanoi" }
```

Response 200:
```
{ "success": true, "retention_policy": { ... } }
```

### POST /destinations/{id}/apply-retention
Manually trigger retention enforcement for a destination.

Response 202:
```
{ "success": true, "message": "Retention policy enforcement started in background" }
```

## Backups

### POST /trigger
Trigger a backup asynchronously.

Request:
```
{ "destination_id": "<uuid>", "comment": "optional" }
```
Response 200:
```
{ "execution_id": "<uuid>", "status": "started", "message": "Backup job started in background" }
```

### GET /executions
List executions.
Query: `limit`, `offset`, `status`
Response 200:
```
{ "executions": [ ... ], "limit": 100, "offset": 0 }
```

### GET /executions/{id}
Get an execution with details (manifest parsed if present).
- 404 if not found

### GET /list
List available backups across enabled destinations or a single destination (`destination_id` query param).
Response 200: `{ "backups": [ ... ] }`

### POST /restore
Restore from a backup.

Request:
```
{
  "backup_path": "<path or remote ref>",
  "destination_id": "<uuid | null>",
  "components": ["config","devices","users"],
  "confirm": true
}
```
Responses:
- 200 `{ "success": true, "message": "...", "restart_required": true }`
- 400 confirm not set, bad request
- 404 destination/backup missing
- 500 restore failed

## Scheduler

### GET /schedule
List jobs and scheduler status.

### POST /schedule
Create a job.

Params (query or JSON):
```
destination_id=<uuid>
schedule_type=cron|interval
schedule_value="* * * * *" or "hours:24" / "minutes:15" / "seconds:30"
job_name=optional string
```
Response 200: `{ "job_id": "...", "schedule_type": "...", ... }`

Errors:
- 400 invalid cron/interval
- 404 destination missing
- 503 scheduler unavailable

### DELETE /schedule/{job_id}
Delete job.
- 404 if not found

### POST /schedule/{job_id}/pause
Pause job.
- 404 if not found

### POST /schedule/{job_id}/resume
Resume job.
- 404 if not found

### POST /schedule/{job_id}/trigger
Trigger job now.
Response 200: `{ "execution_id": "<uuid>", "status": "triggered" }`

## Rate Limits

No explicit rate limits are enforced by the API. General server rate limiting (if configured) applies.

## Examples

See the Backup & Restore Guide for step‑by‑step examples.
