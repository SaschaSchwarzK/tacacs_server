# Accounting Service

## Overview
The Accounting Service is responsible for tracking and logging all TACACS+ accounting events, user sessions, and system activities for auditing and monitoring purposes.

## Key Components

### 1. Event Collection
- **TACACS+ Accounting Records**: Start, stop, and update records
- **Authentication Events**: Successful and failed login attempts
- **Configuration Changes**: Tracks who changed what and when
- **System Events**: Service restarts, errors, and warnings

### 2. Storage Backend
- **SQLite Database**: Primary storage for accounting data
- **Time-series Storage**: For metrics and performance data
- **Rotating Logs**: Text-based logs for quick access

## Runtime Behavior

### Initialization
1. Creates required database tables if they don't exist
2. Sets up database indexes for common queries
3. Initializes background cleanup tasks
4. Configures log rotation

### Event Processing
1. **Receipt**: Accepts accounting records from TACACS+ server
2. **Validation**: Verifies record integrity
3. **Enrichment**: Adds contextual information
4. **Storage**: Writes to database and logs
5. **Notification**: Triggers alerts if configured

## Dependencies
- **Depends On**: Configuration Service, Database Service
- **Required By**: Reporting, Auditing, Monitoring

## Data Retention
- Configurable retention periods
- Automatic cleanup of old records
- Optional archiving to external storage

## Performance Considerations
- Batch processing of accounting records
- Asynchronous write operations
- Database optimization for common queries
