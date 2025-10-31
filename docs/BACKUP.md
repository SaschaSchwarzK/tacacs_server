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

# Temporary directory for backup processing
temp_directory = data/backup_temp

# Default retention period in days
default_retention_days = 30

# Compression level (1-9, higher = better compression but slower)
compression_level = 6
```

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `BACKUP_ENCRYPTION_PASSPHRASE` | Encryption passphrase | `your-secure-passphrase` |
| `BACKUP_TEMP_DIR` | Override temp directory | `/tmp/backup_work` |

## Backup Destinations

### Local Filesystem
```ini
[backup.destinations.local_daily]
type = local
base_path = /var/backups/tacacs
retention_days = 30
```

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

## Scheduling

### Using Crontab
```bash
# Daily backup at 2 AM
0 2 * * * /usr/bin/curl -X POST -H "X-API-Token: YOUR_TOKEN" http://localhost:8080/api/admin/backup/trigger
```

### Using Built-in Scheduler
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
| `POST` | `/api/admin/backup/trigger` | Start a new backup |
| `GET`  | `/api/admin/backup/list` | List available backups |
| `POST` | `/api/admin/backup/restore` | Restore from backup |
| `GET`  | `/api/admin/backup/status` | Get backup status |

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
