# Backup Service

## Overview
The Backup Service provides comprehensive data protection and recovery capabilities, ensuring the server's configuration, authentication data, and operational state can be reliably backed up and restored. It supports both manual and scheduled backups with encryption, compression, and flexible storage options.

## Key Components

### 1. Backup Engine
- **Database Export/Import**: Handles SQLite database operations with verification
  - Supports multiple database files (config, devices, auth, accounting, metrics, audit)
  - Performs integrity checks before and after operations
  - Uses transactions for safe updates
- **Manifest Generation**: Creates detailed JSON manifest for each backup
  - Includes file checksums and metadata
  - Tracks backup source and configuration
  - Records system and version information
- **Encryption**: AES-256-GCM encryption with configurable keys
  - Optional but recommended for sensitive data
  - Supports key rotation
- **Compression**: gzip compression with streaming support
  - Reduces storage requirements
  - Maintains data integrity with checksums

### 2. Scheduler
- **Flexible Scheduling**:
  - Cron-style expressions for precise timing
  - Interval-based scheduling (e.g., every 24 hours)
  - One-time manual triggers
- **Job Management**:
  - Persistent job store (SQLite)
  - Job metadata and history
  - Failure tracking and retries
- **Retention Policies**:
  - Time-based retention (days)
  - Multiple strategies (simple, advanced)
  - Configurable cleanup schedules

### 3. Execution Store
- **Execution Tracking**:
  - Records all backup/restore operations
  - Tracks status, timing, and results
  - Stores error messages and diagnostics
- **Destination Management**:
  - Supports multiple backup destinations
  - Configurable retention per destination
  - Connection testing and validation

## Runtime Behavior

### Initialization
1. Creates and verifies temporary working directory (`data/backup_temp` by default)
2. Initializes execution store database (`data/backup_executions.db`)
3. Sets up scheduler with persistent job store (`data/backup_jobs.db`)
4. Loads and validates configuration from main server config
5. Registers system jobs (e.g., daily retention enforcement)

### Backup Process
1. **Preparation**:
   - Creates unique execution ID and working directory
   - Validates destination configuration
   - Locks relevant resources to prevent conflicts

2. **Data Collection**:
   - Exports SQLite databases with verification
   - Copies configuration files
   - Captures system state and metadata

3. **Packaging**:
   - Creates detailed manifest with file metadata and checksums
   - Compresses files using gzip
   - Optionally encrypts the backup package
   - Validates the final backup file

4. **Storage**:
   - Transfers backup to configured destinations
   - Updates execution status and metadata
   - Applies retention policies to remove old backups
   - Cleans up temporary files

### Restoration Process
1. **Validation**:
   - Verifies backup integrity and authenticity
   - Checks system compatibility
   - Validates available storage space

2. **Preparation**:
   - Creates pre-restore backup of current state
   - Puts system in maintenance mode
   - Locks relevant services

3. **Execution**:
   - Downloads and decrypts backup if needed
   - Extracts files to temporary location
   - Imports databases with verification
   - Restores configuration files

4. **Verification**:
   - Validates restored data integrity
   - Updates system configuration caches
   - Records restoration details

5. **Completion**:
   - Restarts affected services
   - Updates system state
   - Sends notifications
   - Cleans up temporary files

## Dependencies
- **Core Dependencies**:
  - `apscheduler` for job scheduling
  - `cryptography` for encryption
  - `SQLAlchemy` for database operations
  - `humanize` (optional) for user-friendly output

- **Integration Points**:
  - Configuration Service for settings
  - Authentication Service for credentials
  - Logging Service for audit trails

## Storage Options
- **Local Filesystem**:
  - Simple file-based storage
  - Configurable base directory
  - Supports network mounts

- **S3-Compatible Storage**:
  - AWS S3 and compatible services
  - Configurable bucket and path
  - Supports server-side encryption

- **SFTP/SCP**:
  - Secure file transfer to remote servers
  - SSH key or password authentication
  - Configurable directory structure

- **Plugin System**:
  - Extensible architecture
  - Custom storage backends
  - Standardized interface

## Security Considerations
- **Encryption**:
  - All sensitive data is encrypted at rest
  - Secure key management
  - Support for hardware security modules (HSM)

- **Access Control**:
  - Role-based access to backup operations
  - Audit logging of all operations
  - Secure credential storage

- **Data Protection**:
  - No sensitive data in logs
  - Secure temporary file handling
  - Defense-in-depth approach

## Performance Considerations
- **Incremental Backups**:
  - Only changed data is transferred
  - Efficient storage utilization
  - Faster backup/restore times

- **Parallel Processing**:
  - Concurrent operations where possible
  - Configurable worker threads
  - Resource usage limits

- **Resource Management**:
  - Memory-efficient streaming
  - Configurable timeouts
  - Automatic retries with backoff
