# Configuration Guide

This guide provides comprehensive information about configuring the TACACS+ server for various deployment scenarios.

## Configuration File Structure

The TACACS+ server uses INI-style configuration files with the following sections:

- `[server]` - Core server settings
- `[auth]` - Authentication backend configuration
- `[ldap]` - LDAP integration settings
- `[okta]` - Okta SSO integration
- `[database]` - Database and storage configuration
- `[security]` - Security and rate limiting
- `[logging]` - Logging configuration
- `[admin]` - Admin console settings
- `[devices]` - Device inventory settings
- `[radius]` - RADIUS server configuration
- `[monitoring]` - Monitoring and metrics

## Server Configuration

```ini
[server]
# Bind address (0.0.0.0 for all interfaces)
host = 0.0.0.0

# TACACS+ port (standard is 49)
port = 49

# Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
log_level = INFO

# Maximum concurrent connections
max_connections = 50

# Socket timeout in seconds
socket_timeout = 30
```

### Server Options

| Option | Default | Description |
|--------|---------|-------------|
| `host` | `0.0.0.0` | Server bind address |
| `port` | `49` | TACACS+ listening port |
| `log_level` | `INFO` | Logging verbosity level |
| `max_connections` | `50` | Maximum concurrent connections |
| `socket_timeout` | `30` | Socket timeout in seconds |

## Authentication Configuration

```ini
[auth]
# Comma-separated list of backends (local, ldap, okta)
backends = local,ldap

# Local authentication database path
local_auth_db = data/local_auth.db

# Require all backends to succeed (false = any backend)
require_all_backends = false
```

### Authentication Backends

#### Local Authentication
- **SQLite-based**: User accounts stored in local database
- **Bcrypt hashing**: Secure password storage
- **Group management**: Local user groups with privilege levels
- **Fast performance**: No external dependencies

#### LDAP Authentication
- **Active Directory**: Full AD integration support
- **OpenLDAP**: Standard LDAP directory support
- **Group mapping**: Map LDAP groups to privilege levels
- **TLS support**: Secure LDAP connections

#### Okta Authentication
- **SSO integration**: Single sign-on with Okta
- **API-based**: Uses Okta Authentication API
- **Group sync**: Automatic group membership sync
- **MFA support**: Multi-factor authentication

## LDAP Configuration

```ini
[ldap]
# LDAP server URL
server = ldap://ldap.example.com:389

# Base DN for user searches
base_dn = ou=people,dc=example,dc=com

# User attribute for username matching
user_attribute = uid

# Service account for LDAP binding (optional)
bind_dn = cn=service,dc=example,dc=com
bind_password = service_password

# Use TLS encryption
use_tls = true

# Connection timeout in seconds
timeout = 10

# Additional search filters (optional)
user_filter = (objectClass=person)

# Group membership attribute
group_attribute = memberOf

# Group DN pattern for privilege mapping
group_dn_pattern = cn={group},ou=groups,dc=example,dc=com
```

### LDAP Integration Examples

#### Active Directory
```ini
[ldap]
server = ldap://ad.company.com:389
base_dn = ou=Users,dc=company,dc=com
user_attribute = sAMAccountName
bind_dn = cn=tacacs-service,ou=Service Accounts,dc=company,dc=com
bind_password = ${LDAP_PASSWORD}
use_tls = true
group_attribute = memberOf
```

#### OpenLDAP
```ini
[ldap]
server = ldap://openldap.company.com:389
base_dn = ou=people,dc=company,dc=com
user_attribute = uid
bind_dn = cn=admin,dc=company,dc=com
bind_password = ${LDAP_PASSWORD}
use_tls = true
group_attribute = memberOf
```

## Okta Configuration

```ini
[okta]
# Okta organization URL
org_url = https://company.okta.com

# API token for authentication
token = ${OKTA_API_TOKEN}

# Connection timeout
timeout = 10

# Group filter for authorization
group_filter = tacacs_

# Default privilege level for Okta users
default_privilege = 1
```

## Database Configuration

```ini
[database]
# Main accounting database
accounting_db = data/tacacs_accounting.db

# Cleanup old records after N days
cleanup_days = 90

# Enable automatic cleanup
auto_cleanup = true

# Metrics history database
metrics_history_db = data/metrics_history.db

# Audit trail database
audit_trail_db = data/audit_trail.db

# Metrics retention in days
metrics_retention_days = 30

# Audit log retention in days
audit_retention_days = 90
```

## Security Configuration

```ini
[security]
# Maximum authentication attempts before blocking
max_auth_attempts = 3

# Authentication timeout in seconds
auth_timeout = 300

# Require encrypted connections
encryption_required = true

# Allowed client IP addresses (comma-separated)
allowed_clients = 192.168.1.0/24,10.0.0.0/8

# Denied client IP addresses
denied_clients = 

# Rate limiting: requests per window
rate_limit_requests = 60

# Rate limiting: window size in seconds
rate_limit_window = 60
```

### Security Best Practices

1. **Enable TLS**: Always use encrypted connections
2. **Restrict clients**: Limit access to known network ranges
3. **Rate limiting**: Prevent brute force attacks
4. **Strong secrets**: Use complex shared secrets per device group
5. **Regular rotation**: Rotate secrets periodically
6. **Audit logging**: Enable comprehensive audit trails

## Logging Configuration

```ini
[logging]
# Log file path
log_file = logs/tacacs.log

# Log format (structured JSON recommended)
log_format = %(asctime)s - %(name)s - %(levelname)s - %(message)s

# Enable log rotation
log_rotation = true

# Maximum log file size
max_log_size = 10MB

# Number of backup files to keep
backup_count = 5
```

### Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `DEBUG` | Detailed debugging information | Development, troubleshooting |
| `INFO` | General operational messages | Production monitoring |
| `WARNING` | Warning messages | Production (recommended) |
| `ERROR` | Error conditions | Critical issues only |
| `CRITICAL` | Critical failures | Emergency situations |

## Admin Console Configuration

```ini
[admin]
# Admin username
username = admin

# Bcrypt password hash
password_hash = $2b$12$...

# Session timeout in minutes
session_timeout_minutes = 60

# Enable admin interface
enabled = true

# Admin interface bind address
bind_host = 127.0.0.1

# Admin interface port
bind_port = 8080
```

### Generating Password Hash

```bash
# Using Python
python -c "import bcrypt; print(bcrypt.hashpw(b'your_password', bcrypt.gensalt()).decode())"

# Using the server's utility
poetry run python -c "from tacacs_server.utils.password_hash import hash_password; print(hash_password('your_password'))"
```

## Device Management Configuration

```ini
[devices]
# Device inventory database
database = data/devices.db

# Default device group name
default_group = default

# Auto-create device groups
auto_create_groups = true

# Default TACACS+ secret for new groups
default_tacacs_secret = ${DEFAULT_TACACS_SECRET}

# Default RADIUS secret for new groups
default_radius_secret = ${DEFAULT_RADIUS_SECRET}
```

## RADIUS Server Configuration

```ini
[radius]
# Enable RADIUS server
enabled = true

# RADIUS authentication port
auth_port = 1812

# RADIUS accounting port
acct_port = 1813

# RADIUS server bind address
host = 0.0.0.0

# Share authentication backends with TACACS+
share_backends = true

# Share accounting database with TACACS+
share_accounting = true

# Default RADIUS client secret
default_secret = ${RADIUS_DEFAULT_SECRET}
```

## Monitoring Configuration

```ini
[monitoring]
# Enable web monitoring interface
enabled = true

# Web interface host
web_host = 127.0.0.1

# Web interface port
web_port = 8080

# Enable Prometheus metrics
prometheus_enabled = true

# Dashboard refresh interval in seconds
dashboard_refresh_seconds = 30

# Enable WebSocket real-time updates
websocket_enabled = true
```

## Environment Variables

The server supports environment variable substitution in configuration files:

### Common Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `TACACS_CONFIG` | Configuration file path | `/etc/tacacs/tacacs.conf` |
| `ADMIN_USERNAME` | Admin console username | `admin` |
| `ADMIN_PASSWORD_HASH` | Admin password hash | `$2b$12$...` |
| `LDAP_PASSWORD` | LDAP bind password | `secret123` |
| `OKTA_API_TOKEN` | Okta API token | `00abc...` |
| `DEFAULT_TACACS_SECRET` | Default TACACS+ secret | `tacacs123` |
| `DEFAULT_RADIUS_SECRET` | Default RADIUS secret | `radius123` |

### Using Environment Variables

```ini
# In configuration file
[ldap]
bind_password = ${LDAP_PASSWORD}

[okta]
token = ${OKTA_API_TOKEN}

[admin]
password_hash = ${ADMIN_PASSWORD_HASH}
```

```bash
# In environment
export LDAP_PASSWORD="secure_ldap_password"
export OKTA_API_TOKEN="00abc123def456..."
export ADMIN_PASSWORD_HASH="$2b$12$..."
```

## Configuration Validation

### Pre-deployment Validation

```bash
# Validate configuration file
python scripts/validate_config.py

# Validate specific file
python scripts/validate_config.py /path/to/config.conf

# Quiet mode (errors only)
python scripts/validate_config.py --quiet
```

### Common Validation Errors

1. **Missing required sections**: Ensure all required sections are present
2. **Invalid port numbers**: Ports must be 1-65535
3. **Invalid IP addresses**: Check network addresses and CIDR notation
4. **Missing database directories**: Ensure data directories exist
5. **Invalid log levels**: Use standard Python logging levels
6. **Weak secrets**: Secrets should be at least 8 characters

## Configuration Examples

### Minimal Configuration

```ini
[server]
host = 0.0.0.0
port = 49

[auth]
backends = local
local_auth_db = data/local_auth.db

[admin]
username = admin
password_hash = $2b$12$example_hash
```

### Enterprise Configuration

```ini
[server]
host = 0.0.0.0
port = 49
log_level = INFO
max_connections = 200

[auth]
backends = ldap,local
local_auth_db = data/local_auth.db
require_all_backends = false

[ldap]
server = ldaps://ad.company.com:636
base_dn = ou=Users,dc=company,dc=com
user_attribute = sAMAccountName
bind_dn = cn=tacacs-service,ou=Service Accounts,dc=company,dc=com
bind_password = ${LDAP_PASSWORD}
use_tls = true

[security]
max_auth_attempts = 5
auth_timeout = 300
encryption_required = true
allowed_clients = 10.0.0.0/8,192.168.0.0/16
rate_limit_requests = 100
rate_limit_window = 60

[radius]
enabled = true
auth_port = 1812
acct_port = 1813
share_backends = true
share_accounting = true

[monitoring]
enabled = true
web_host = 0.0.0.0
web_port = 8080
prometheus_enabled = true
```

### High Availability Configuration

```ini
[server]
host = 0.0.0.0
port = 49
max_connections = 500

[database]
accounting_db = /shared/data/tacacs_accounting.db
metrics_history_db = /shared/data/metrics_history.db
audit_trail_db = /shared/data/audit_trail.db

[devices]
database = /shared/data/devices.db

[auth]
backends = ldap
local_auth_db = /shared/data/local_auth.db

[ldap]
server = ldaps://ad1.company.com:636,ldaps://ad2.company.com:636
base_dn = ou=Users,dc=company,dc=com
user_attribute = sAMAccountName
bind_dn = cn=tacacs-service,ou=Service Accounts,dc=company,dc=com
bind_password = ${LDAP_PASSWORD}
use_tls = true
timeout = 5

[security]
max_auth_attempts = 3
rate_limit_requests = 200
rate_limit_window = 60
```

## Configuration Management

### Backup and Restore

```bash
# Create configuration backup
cp config/tacacs.conf config/tacacs.conf.backup.$(date +%Y%m%d_%H%M%S)

# Restore from backup
cp config/tacacs.conf.backup.20231201_143000 config/tacacs.conf
```

### Version Control

```bash
# Initialize git repository for configuration
cd config/
git init
git add tacacs.conf
git commit -m "Initial configuration"

# Track changes
git add tacacs.conf
git commit -m "Updated LDAP configuration"
```

### Configuration Templates

Create configuration templates for different environments:

```bash
# Development
config/tacacs.dev.conf

# Staging
config/tacacs.staging.conf

# Production
config/tacacs.prod.conf
```

## Troubleshooting Configuration

### Common Issues

1. **Server won't start**
   - Check configuration syntax
   - Verify file permissions
   - Ensure required directories exist

2. **Authentication failures**
   - Verify backend configuration
   - Check network connectivity to LDAP/Okta
   - Validate credentials and secrets

3. **Performance issues**
   - Increase max_connections
   - Optimize database settings
   - Enable connection pooling

4. **Security warnings**
   - Use strong secrets
   - Enable TLS encryption
   - Restrict client access

### Debug Configuration

```ini
[server]
log_level = DEBUG

[logging]
log_file = logs/debug.log
```

### Testing Configuration

```bash
# Test TACACS+ connectivity
python scripts/tacacs_client.py localhost 49 secret admin password

# Test RADIUS connectivity
python scripts/radius_client.py localhost 1812 secret admin password

# Batch test credentials
python scripts/tacacs_client.py --batch scripts/example_credentials.csv
```