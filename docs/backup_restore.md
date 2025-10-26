# Backup and Restore Guide

This guide explains how to configure, operate, and troubleshoot the built‑in backup and restore system.

- Simple local filesystem destinations are supported out of the box.
- Additional destination types (FTP/SFTP/Azure) are pluggable and can be added.
- A scheduler allows periodic backups using cron or intervals.
- A REST API exposes all management and operational functions.

## Overview

Backups capture the following data:
- Configuration (tacacs.conf, merged export JSON)
- Databases: devices, local users, accounting, metrics, audit trail
- A manifest with checksums, record counts and metadata

Each backup is created in a temporary working directory, compressed as a tar.gz archive, then uploaded to the configured destination. Executions are tracked in a local SQLite database for status/history.

Restores validate checksums and can target specific components (config, devices, users, accounting, metrics, audit). A safety backup (emergency) is created before applying a restore.

## Configuration

Defaults for backup live under the `[backup]` section of the server configuration and can also be retrieved via `get_backup_config()`:

- `enabled`: Enable/disable backup capabilities (default: true)
- `create_on_startup`: If true, create a backup at startup (default: false)
- `temp_directory`: Path for temporary work directory (default: `data/backup_temp`)
- `encryption_enabled`: Enable archive encryption (optional; default: false)
- `encryption_passphrase`: Optional passphrase (or set env `BACKUP_ENCRYPTION_PASSPHRASE`)
- `default_retention_days`: Default retention for destinations (default: 30)

If `create_on_startup` is enabled, the first enabled destination is used for a one-time backup at start.

## Destinations

Currently implemented destination types:
- `local`: Write backups to a local filesystem directory

Pluggable (to be added):
- `ftp`, `sftp`, `azure`

Destination objects are stored in the backup execution database with a JSON configuration and last-known status. Connection tests can be run before saving.

## Scheduling

A persistent scheduler (APScheduler) manages jobs stored in `data/backup_jobs.db`. Jobs survive restarts. Scheduling options:
- `cron`: a standard 5-field cron string
- `interval`: `unit:value` such as `minutes:15`, `hours:24`, `days:1`

Manual jobs can also be registered; they will not run automatically but can be triggered via the API.

## API Overview

All endpoints require admin access via either an admin session cookie or `X-API-Token`/`Authorization: Bearer` (as configured).

- `POST /api/admin/backup/destinations` — create destination
- `GET /api/admin/backup/destinations` — list destinations
- `GET /api/admin/backup/destinations/{id}` — get destination
- `PUT /api/admin/backup/destinations/{id}` — update destination (connection re-test on config changes)
- `DELETE /api/admin/backup/destinations/{id}` — delete destination (blocked if executions exist)
- `POST /api/admin/backup/destinations/{id}/test` — test connection
- `POST /api/admin/backup/trigger` — trigger manual backup (background)
- `GET /api/admin/backup/executions` — list backup executions
- `GET /api/admin/backup/executions/{id}` — get execution details
- `GET /api/admin/backup/list` — list available backups
- `POST /api/admin/backup/restore` — restore from backup (requires `confirm: true`)
- `GET /api/admin/backup/schedule` — list scheduled jobs
- `POST /api/admin/backup/schedule` — create scheduled job (cron/interval)
- `DELETE /api/admin/backup/schedule/{job_id}` — delete job
- `POST /api/admin/backup/schedule/{job_id}/pause` — pause job
- `POST /api/admin/backup/schedule/{job_id}/resume` — resume job
- `POST /api/admin/backup/schedule/{job_id}/trigger` — trigger job immediately

## Examples

```bash
# Create local backup destination
curl -X POST http://localhost:8080/api/admin/backup/destinations \
  -H "X-API-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "local_daily",
    "type": "local",
    "config": {"base_path": "/backups/tacacs"},
    "retention_days": 30
  }'

# Trigger manual backup
curl -X POST http://localhost:8080/api/admin/backup/trigger \
  -H "X-API-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"destination_id": "abc123", "comment": "Pre-upgrade backup"}'

# List available backups
curl http://localhost:8080/api/admin/backup/list \
  -H "X-API-Token: $TOKEN"

# Restore from backup
curl -X POST http://localhost:8080/api/admin/backup/restore \
  -H "X-API-Token: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "backup_path": "prod-tacacs-01/daily/backup-...",
    "destination_id": "abc123",
    "confirm": true
  }'
```

## Restore Safety

- The system attempts a safety (emergency) backup before restoring.
- Verify compatibility of backups across versions and environments when restoring.
- After restore, a server restart is recommended (or required) to reload components.

## Troubleshooting

- "Destination not found": Verify destination ID and that it is enabled.
- Connection test failed: Check network/credentials/permissions for the destination.
- No backups listed: Ensure the destination base path is correct and accessible.
- Restore failed: Inspect execution logs and manifest; verify checksums and available components.
- Scheduler unavailable: Confirm the server has write access to `data/backup_jobs.db` and that the scheduler initialized.

## Notes

- Encryption support is optional and can be enabled via `BACKUP_ENCRYPTION_PASSPHRASE` or the `backup` section.
- Retention policy is applied at the destination and can be invoked after uploads.
- The backup/restore APIs are intended for administrative automation and CI/CD workflows.

