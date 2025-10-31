# Advanced Configuration Management

This document covers advanced configuration management features including versioning, drift detection, and automation.

## Table of Contents
- [Configuration Store](#configuration-store)
- [Configuration Versioning](#configuration-versioning)
- [Drift Detection](#drift-detection)
- [Automation & API](#automation--api)
- [Best Practices](#best-practices)

## Configuration Store

The configuration management system uses a SQLite database (`data/config_overrides.db`) with the following schema:

### Database Schema

#### `config_overrides` Table
Stores active configuration overrides.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| section | TEXT | Configuration section |
| key | TEXT | Configuration key |
| value | TEXT | Configuration value |
| created_at | TIMESTAMP | When override was created |
| created_by | TEXT | User/process that created the override |
| comment | TEXT | Optional description |

#### `config_history` Table
Tracks all configuration changes for audit and rollback.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| operation | TEXT | 'CREATE', 'UPDATE', or 'DELETE' |
| section | TEXT | Configuration section |
| key | TEXT | Configuration key |
| old_value | TEXT | Previous value (for updates) |
| new_value | TEXT | New value |
| timestamp | TIMESTAMP | When change occurred |
| user | TEXT | User who made the change |
| comment | TEXT | Change description |
| key | TEXT | Configuration key |
| value | TEXT | Serialized value (JSON for complex types) |
| value_type | TEXT | Type of value ('string', 'integer', 'boolean', 'json', 'list') |
| created_at | TIMESTAMP | When the override was created |
| created_by | TEXT | User who created the override |
| reason | TEXT | Reason for the override |
| is_active | BOOLEAN | Whether the override is currently active |

### 2. `config_history` Table
Maintains an audit trail of all configuration changes.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| section | TEXT | Configuration section |
| key | TEXT | Configuration key |
| old_value | TEXT | Previous value (JSON for complex types) |
| new_value | TEXT | New value (JSON for complex types) |
| changed_at | TIMESTAMP | When the change occurred |
| changed_by | TEXT | User who made the change |
| source_ip | TEXT | IP address of the requester |
| reason | TEXT | Reason for the change |
| version_id | INTEGER | Reference to config_versions.id if part of a bulk update |

### 3. `config_versions` Table
Stores complete configuration snapshots.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| config_json | TEXT | Full JSON configuration |
| config_hash | TEXT | SHA-256 hash of the config |
| created_at | TIMESTAMP | When the version was created |
| created_by | TEXT | User who created the version |
| description | TEXT | Description of the version |
| is_baseline | BOOLEAN | Whether this is a baseline configuration |

### 4. `system_metadata` Table
Stores system-level metadata.

| Column | Type | Description |
|--------|------|-------------|
| key | TEXT | Metadata key |
| value | TEXT | Metadata value |
| updated_at | TIMESTAMP | When the value was last updated |

## Common Operations

### 1. Viewing Current Configuration

```python
# Get all sections
sections = config.config.sections()

# Get all values in a section
server_config = dict(config.config.items('server'))

# Check if a key is overridden
is_overridden = key in config.overridden_keys.get('section_name', set())
```

### 2. Updating Configuration

```python
# Update a single value
config.update_server_config(
    port=5050,
    _change_reason="Increasing port number for load balancer",
    _source_ip="192.168.1.100"
)

# Bulk update multiple values
config.update_auth_config(
    backends="ldap,local",
    cache_ttl=300,
    _change_reason="Enabling LDAP authentication",
    _source_ip="192.168.1.100"
)
```

### 3. Validating Configuration Changes

```python
# Validate a change before applying
is_valid, issues = config.validate_change(
    section="server",
    key="port",
    value=5050
)

if not is_valid:
    print(f"Validation failed: {issues}")
```

### 4. Working with Configuration Versions

```python
# Create a new version
version_id = config.config_store.create_version(
    config_dict=config._export_full_config(),
    created_by="admin@example.com",
    description="Before enabling new feature X"
)

# List all versions
versions = config.config_store.list_versions()

# Restore a previous version
config.config_store.restore_version(
    version_id=42,
    created_by="admin@example.com",
    reason="Rollback due to issue with feature X"
)
```

### 5. Detecting Configuration Drift

```python
# Get all configuration drifts
drift = config.detect_config_drift()

# Example output:
# {
#     'server': {
#         'port': (4949, 5050),  # (base_value, override_value)
#         'log_level': ('INFO', 'DEBUG')
#     },
#     'auth': {
#         'backends': ('local', 'ldap,local')
#     }
# }

# Check for specific section
drift = config.detect_config_drift().get('server', {})
```

## Configuration Versioning

The system maintains a complete history of configuration changes with the following features:

1. **Automatic Versioning**: Every configuration change creates a new version
2. **Baseline Snapshots**: Regular snapshots of the base configuration
3. **Change Tracking**: Who changed what, when, and why
4. **Rollback**: Revert to any previous version

### Version Lifecycle

1. **Create Version**: When configuration changes are made
2. **Tag Version**: Mark important versions (e.g., releases)
3. **Compare Versions**: See differences between versions
4. **Restore Version**: Roll back to a previous state

## Drift Detection

Drift detection helps identify differences between the base configuration and active overrides:

```python
# Get all drifts
drift = config.detect_config_drift()

# Check for specific section
drift = config.detect_config_drift().get('server', {})

# Example response:
# {
#     'port': (4949, 5050),
#     'log_level': ('INFO', 'DEBUG')
# }
```

## Best Practices

### 1. Configuration Changes
- Always provide a meaningful reason for changes
- Use the validation API before applying changes
- Test changes in a non-production environment first
- Consider the impact on running services

### 2. Version Management
- Create versions before major changes
- Use descriptive version messages
- Regularly review and clean up old versions
- Tag important versions (e.g., releases, milestones)

### 3. Security
- Restrict access to configuration management endpoints
- Use HTTPS for URL-based configurations
- Rotate API tokens and credentials regularly
- Review audit logs for suspicious activity

### 4. Performance
- Use bulk updates for multiple changes
- Be mindful of configuration size and complexity
- Monitor the size of the configuration database
- Consider purging old history periodically

### 5. Backup and Recovery
- Regularly back up the configuration database
- Test restore procedures
- Document rollback procedures
- Monitor for configuration drift
