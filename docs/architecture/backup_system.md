# Backup System Architecture

This document describes the backup system components, data flows, persistence, and extension points. For user-facing documentation, see [Backup and Restore Guide](../BACKUP.md).

> **Related Documentation**
> - [Configuration Management](../CONFIGURATION.md) - How configuration is loaded and managed
> - [Backup and Restore Guide](../BACKUP.md) - User guide for backup operations
> - [API Documentation](../API.md#backup--restore) - API reference for backup operations

## Components

- BackupService
  - Orchestrates export, manifest creation, archiving, upload, execution tracking
  - Provides restore workflow with checksum verification and component selection
  - Exposes convenience methods for manual triggers and status
- BackupExecutionStore (SQLite)
  - Persists destinations and backup execution records
  - Stores metadata fields like status, sizes, files_included, error_message
- BackupScheduler (APScheduler)
  - Persists jobs to SQLite jobstore (`data/backup_jobs.db`)
  - Supports cron/interval/manual jobs
  - Tracks job metadata (status/failures/last_run) in sidecar JSON
- Destinations
  - Pluggable strategy for upload/download/list/delete
  - Implemented: Local filesystem
  - Placeholders for FTP/SFTP/Azure

## Data Flow: Backup

1. API schedules or triggers a backup for a destination
2. BackupService creates a temp workspace and exports content:
   - Databases (SQLite backup API)
   - File configuration (when not URL-based)
   - JSON export of merged configuration
3. Creates manifest.json with:
   - Metadata (instance, timestamps, trigger, versions)
   - Checksums and record counts
4. Creates tar.gz archive and (optionally) encrypts per config/env
5. Uploads via destination and records execution in store
6. Applies retention policy best-effort

## Data Flow: Restore

1. API validates request (`confirm=true` required)
2. If destination_id provided, downloads archive to temp
3. Decrypts (if needed), extracts, verifies checksums
4. Creates safety (emergency) backup
5. Restores selected components (config, devices, users, accounting, metrics, audit)
6. Verifies DB integrity and configuration validity
7. Signals restart requirement to reload services

## Database Schemas

- `backup_executions`
  - id (TEXT, PK), destination_id, backup_filename, backup_path
  - triggered_by, started_at, completed_at, status
  - size_bytes, compressed_size_bytes, files_included
  - error_message, manifest_json
- `backup_destinations`
  - id (TEXT, PK), name (UNIQUE), type, enabled
  - config_json, retention_days
  - created_at, created_by
  - last_backup_at, last_backup_status

## Extension Points

- `tacacs_server.backup.destinations.base.BackupDestination`
  - Implement required methods for upload/download/list/delete/test
  - Register in factory (`create_destination`) with a new type string
- Scheduler job hooks
  - Use BackupScheduler.add_job to integrate custom cadence logic
- Encryption
  - Pluggable via `tacacs_server.backup.encryption` or external service

## Security Considerations

- **Access Control**:
  - All backup operations require admin authentication
  - API endpoints are protected via `admin_guard`
  - File operations use `_safe_join` to prevent path traversal attacks

- **Data Protection**:
  - Configuration exports may contain sensitive values
  - Encryption is strongly recommended for off‑box storage
  - Backup files should be stored with restricted permissions (600)
  - Consider using separate credentials for backup destinations

- **Operational Security**:
  - Scheduler persistence should be on secure, durable storage
  - Temporary files are created in a secure directory with restricted permissions
  - Backup operations are logged for audit purposes

## Integration with Configuration System

The backup system works closely with the [configuration management system](../CONFIGURATION.md) to ensure consistent state:

1. **Configuration Backup**:
   - Backs up both file-based and database-stored configuration
   - Preserves configuration history and versioning
   - Maintains relationships between configuration items

2. **Restore Process**:
   - Validates configuration before applying
   - Supports partial restores of configuration components
   - Maintains configuration integrity across restores

3. **Synchronization**:
   - Backup schedules can be configured via the main configuration
   - Configuration changes trigger backup operations when needed
   - Backup status is exposed in the admin interface

