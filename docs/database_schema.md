# TACACS+ Server Database Schema

## Overview

This document describes the database schema for the TACACS+ Server. The schema is designed to support user authentication, device management, command authorization, and accounting.

## Entity Relationship Diagram

```mermaid
erDiagram
    %% User Management
    User ||--o{ UserGroupMember : belongs_to
    User ||--o{ UserSession : has
    User ||--o{ CommandAuthorization : has
    User ||--o{ BackupExecution : created_by
    User {
        int id PK
        string username
        string password_hash
        string email
        int privilege_level
        string service
        bool enabled
        string description
        datetime created_at
        datetime updated_at
    }

    UserGroup ||--o{ UserGroupMember : contains
    UserGroup {
        int id PK
        string name
        string description
        datetime created_at
    }

    UserGroupMember {
        int id PK
        int user_id FK
        int group_id FK
        datetime created_at
    }

    %% Device Management
    Device ||--o{ AccountingRecord : has
    Device ||--o| DeviceGroup : belongs_to
    Device {
        int id PK
        string name
        string ip_address
        int device_group_id FK
        bool enabled
        json metadata
        datetime created_at
        datetime updated_at
        datetime last_seen
    }

    DeviceGroup ||--o{ Device : contains
    DeviceGroup ||--o| Proxy : uses
    DeviceGroup ||--o{ UserGroup : allows
    DeviceGroup {
        int id PK
        string name
        string description
        int proxy_id FK
        string tacacs_secret
        string radius_secret
        int[] allowed_user_groups
        datetime created_at
        datetime updated_at
    }

    %% Command Authorization
    CommandAuthorization {
        int id PK
        int user_id FK
        string command
        bool is_allowed
        string match_type
        datetime created_at
        datetime updated_at
    }

    %% Backup System
    BackupExecution {
        int id PK
        int user_id FK
        string backup_type
        string status
        string destination
        datetime started_at
        datetime completed_at
        string error_message
    }

    BackupDestination {
        int id PK
        string name
        string type
        string config
        bool is_default
        datetime created_at
        datetime updated_at
    }

    %% Accounting
    AccountingRecord {
        int id PK
        string session_id
        string username
        string nas_ip
        string nas_port
        string service
        string protocol
        datetime start_time
        datetime stop_time
        int bytes_in
        int bytes_out
        string status
        string reason
    }
```

## Table Descriptions

### User Management

#### User
Stores user account information.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| username | String | Unique username |
| password_hash | String | Hashed password |
| email | String | User's email address |
| privilege_level | Integer | TACACS+ privilege level (0-15) |
| service | String | Primary service profile |
| enabled | Boolean | Whether the account is enabled |
| description | String | User description |
| created_at | DateTime | When the user was created |
| updated_at | DateTime | When the user was last updated |

#### UserGroup
Groups users for easier permission management.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| name | String | Group name |
| description | String | Group description |
| created_at | DateTime | When the group was created |

#### UserGroupMember
Maps users to groups.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| user_id | Integer | Foreign key to User |
| group_id | Integer | Foreign key to UserGroup |
| created_at | DateTime | When the membership was created |

### Device Management

#### Device
Stores network device information.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| name | String | Device name |
| ip_address | String | Device IP address or CIDR |
| device_group_id | Integer | Reference to device group |
| enabled | Boolean | Whether the device is enabled |
| metadata | JSON | Custom metadata (location, model, etc.) |
| created_at | DateTime | When the device was added |
| updated_at | DateTime | When the device was last updated |
| last_seen | DateTime | When the device was last seen |

#### DeviceGroup
Groups devices and defines authentication settings.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| name | String | Group name |
| description | String | Group description |
| proxy_id | Integer | Optional proxy ID for this group |
| tacacs_secret | String | TACACS+ shared secret |
| radius_secret | String | RADIUS shared secret |
| allowed_user_groups | Integer[] | List of user group IDs with access |
| created_at | DateTime | When the group was created |
| updated_at | DateTime | When the group was last updated |

### Command Authorization

#### CommandAuthorization
Defines command-level authorization rules.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| user_id | Integer | Foreign key to User |
| command | String | Command pattern to match |
| is_allowed | Boolean | Whether the command is allowed |
| match_type | String | Type of matching (exact, prefix, regex) |
| created_at | DateTime | When the rule was created |
| updated_at | DateTime | When the rule was last updated |

### Backup System

#### BackupExecution
Tracks backup operations.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| user_id | Integer | Who initiated the backup |
| backup_type | String | Type of backup (full, config, etc.) |
| status | String | Current status (running, completed, failed) |
| destination | String | Where the backup was stored |
| started_at | DateTime | When the backup started |
| completed_at | DateTime | When the backup completed |
| error_message | String | Error details if backup failed |

### Accounting

#### AccountingRecord
Stores TACACS+ accounting records.

| Column | Type | Description |
|--------|------|-------------|
| id | Integer | Primary key |
| session_id | String | Unique session identifier |
| username | String | Authenticated username |
| nas_ip | String | Network Access Server IP |
| nas_port | String | NAS port number |
| service | String | Service type (shell, ppp, etc.) |
| protocol | String | Protocol used |
| start_time | DateTime | When the session started |
| stop_time | DateTime | When the session ended |
| bytes_in | Integer | Bytes received |
| bytes_out | Integer | Bytes sent |
| status | String | Session status |
| reason | String | Reason for session end |

## Indexes

- `idx_user_username` - On `User(username)` for fast username lookups
- `idx_device_ip` - On `Device(ip_address)` for fast IP lookups
- `idx_session_id` - On `AccountingRecord(session_id)` for session tracking
- `idx_command_auth` - On `CommandAuthorization(user_id, command)` for auth checks

## Notes

- All tables include `created_at` timestamps for auditing
- Soft deletes are implemented using `is_active` flags where appropriate
- Foreign key constraints ensure referential integrity
- Indexes are optimized for common query patterns

## Schema Changes

When making changes to the database schema:

1. Create a new migration file
2. Update this documentation
3. Test the migration on a development database
4. Include rollback instructions in the migration

---

*Last Updated: November 1, 2025*
