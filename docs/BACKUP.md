# Backup and Restore Guide

This guide covers the backup and restore functionality of the TACACS+ server, including configuration, scheduling, and troubleshooting.

## Table of Contents
- [Overview](#overview)
- [Configuration](#configuration)
- [Backup Destinations](#backup-destinations)
- [Scheduling](#scheduling)
- [Encryption](#encryption)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)

## Overview

The backup system provides:
- Scheduled or on-demand backups
- Multiple storage destinations
- Encryption support
- Retention policies
- Comprehensive API

Backups include:
- Server configuration
- Authentication databases
- Accounting data
- Audit logs
- System metrics

## Configuration

### Server Configuration
Add to `tacacs.conf`:

```ini
[backup]
# Enable/disable backup functionality
enabled = true

# Create backup on server startup
create_on_startup = false

; Temporary directory is managed internally by the server and not configurable

# Default retention period in days
default_retention_days = 30

# Compression level (1-9, higher = better compression but slower)
compression_level = 6
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `BACKUP_ENCRYPTION_PASSPHRASE` | Encryption passphrase | `your-secure-passphrase` |
| `BACKUP_ROOT` | Fixed backup root for local destination | `/data/backups` |

## Backup Destinations

### Local Filesystem
```ini
[backup.destinations.local_daily]
type = local
; base_path is ignored — local destination writes under BACKUP_ROOT (/data/backups)
retention_days = 30
```

> Note: The backup system writes persistent artifacts under `/data/backups` (override with `BACKUP_ROOT`).
> The temporary working directory is fixed and managed internally by the server.

### SFTP (Recommended for Remote)

```ini
[backup.destinations.remote_sftp]
type = sftp
host = backup.example.com
port = 22
username = tacacs-backup
private_key = /path/to/ssh_key
base_path = /backups/tacacs
retention_days = 90
```

### Path & Filename Safety

To protect against path traversal and unsafe names, the backup system validates and sanitizes all path components before writing or uploading files. Keep these rules in mind when configuring destinations or interpreting generated names:

- Allowed characters in user-controlled segments: letters, digits, underscore, hyphen, and (for filenames only) dot.
- Disallowed: directory separators (`/` and `\`), NUL bytes, and dot-only segments (`.` or `..`).
- Length limits: instance names up to 64 chars; backup types up to 32 chars; filenames up to 128 chars.
- Local/Azure/FTP destinations: the system will join only sanitized segments; any invalid value will raise a validation error.

Generated archive names follow this format:

```
backup-{instance_name}-{YYYYMMDD-HHMMSS}-{backup_type}.tar.gz[.enc]
```

Where `instance_name` and `backup_type` are sanitized per the rules above. For Azure, any configured `base_path` is split into segments and each segment is validated before being used as a blob key prefix.

## Scheduling

### Using Crontab
```bash
# Daily backup at 2 AM
0 2 * * * /usr/bin/curl -X POST -H "X-API-Token: YOUR_TOKEN" http://localhost:8080/api/admin/backup/trigger
```

### Using Built-in Scheduler

While initial schedules can be defined in `tacacs.conf`, the primary method for managing backup jobs is via the API, which provides full control to create, delete, pause, and resume schedules dynamically.

```ini
[backup.schedules.daily]
destination = local_daily
schedule = "0 2 * * *"  # 2 AM daily
retention_days = 30
```

## Encryption

### Enabling Encryption
1. Set a strong passphrase in environment:
   ```bash
   export BACKUP_ENCRYPTION_PASSPHRASE="your-strong-passphrase"
   ```

2. Enable in config:
   ```ini
   [backup]
   encryption_enabled = true
   ```

### Important Notes
- The passphrase is required for restore
- Store it securely (e.g., password manager)
- No recovery if passphrase is lost
- Consider using a secret manager for production

## API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/admin/backup/trigger` | Start a new manual backup |
| `GET`  | `/api/admin/backup/backups` | List available backups from a destination |
| `GET`  | `/api/admin/backup/executions` | List all backup job executions |
| `GET`  | `/api/admin/backup/executions/{exec_id}` | Get the status of a specific backup execution |
| `POST` | `/api/admin/backup/backups/restore` | Restore from a specific backup |
| `GET`  | `/api/admin/backup/schedules` | List all configured backup schedules |
| `POST` | `/api/admin/backup/schedules` | Create a new backup schedule |

> **Note:** For detailed API documentation including all available endpoints, parameters, and response formats, see the [Backup API Reference](../api/backup.md).

### Example: Trigger Backup
```bash
curl -X POST http://localhost:8080/api/admin/backup/trigger \
  -H "X-API-Token: YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"comment": "Scheduled nightly backup"}'
```

## Troubleshooting

### Common Issues

**Backup Fails**
- Check disk space in temp directory
- Verify destination permissions
- Check logs: `journalctl -u tacacs-server`

**Restore Fails**
- Verify backup file integrity
- Check version compatibility
- Ensure all services are stopped during restore

**Performance Issues**
- Increase temp directory space
- Lower compression level
- Schedule during off-peak hours

### Logs
Check logs for detailed error messages:
```bash
# System logs
journalctl -u tacacs-server --since "1 hour ago"

# Application logs
tail -f /var/log/tacacs/backup.log
```

## Best Practices

1. **Regular Testing**
   - Test restores periodically
   - Verify backup integrity
   - Document restore procedures

2. **Security**
   - Use encryption for sensitive data
   - Restrict backup file permissions
   - Rotate encryption keys

3. **Monitoring**
   - Monitor backup success/failure
   - Set up alerts for missed backups
   - Log all backup activities
