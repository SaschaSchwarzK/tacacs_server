# Configuration Examples

This document provides practical examples and recipes for common TACACS+ server configurations.

## Table of Contents
- [Basic Server Setup](#basic-server-setup)
- [LDAP Authentication](#ldap-authentication)
- [Command Authorization](#command-authorization)
- [Troubleshooting](#troubleshooting)

## Basic Server Setup

```ini
[server]
# Listen on all interfaces
host = 0.0.0.0

# Standard TACACS+ port
port = 49

# Logging configuration
log_level = INFO
log_file = /var/log/tacacs/tacacs.log

# Security settings
max_connections = 100
client_timeout = 30

[database]
# SQLite database for accounting
accounting_db = /var/lib/tacacs/accounting.db

# Automatic cleanup of old records (days)
cleanup_days = 90

[auth]
# Enable local authentication
backends = local
local_auth_db = /etc/tacacs/local_users.db
```

## LDAP Authentication

```ini
[auth]
backends = ldap
require_all_backends = false

[ldap]
# LDAP server connection
server = ldaps://ldap.example.com:636
base_dn = dc=example,dc=com
user_attribute = sAMAccountName

# Service account for LDAP binds
bind_dn = CN=svc-tacacs,OU=Service Accounts,DC=example,DC=com
bind_password = ${LDAP_BIND_PASSWORD}  # From environment variable

# Search settings
user_search_base = OU=Users,DC=example,DC=com
group_search_base = OU=Groups,DC=example,DC=com

# TLS configuration
use_tls = true
tls_require_cert = demand
tls_ca_cert_file = /etc/ssl/certs/ca-certificates.crt
```

## Command Authorization

```ini
[command_authorization]
# Default action if no rule matches
default_action = deny

# Rules are evaluated in order
rules_json = [
    {
        "name": "Allow show commands",
        "action": "permit",
        "match_type": "prefix",
        "pattern": "show ",
        "min_privilege": 1
    },
    {
        "name": "Restrict config changes",
        "action": "deny",
        "match_type": "regex",
        "pattern": "^conf.*terminal|^write.*mem",
        "message": "This operation is restricted"
    }
]
```

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Check server logs: `journalctl -u tacacs-server`
   - Verify network connectivity to authentication backends
   - Check time synchronization (critical for TACACS+)

2. **Performance Issues**
   - Monitor connection count: `netstat -anp | grep tac_plus`
   - Check database performance: `sqlite3 /var/lib/tacacs/accounting.db "PRAGMA stats"`
   - Review system metrics: `top -b -n 1 | head -n 20`

3. **Configuration Reload**
   ```bash
   # Reload configuration without dropping connections
   pkill -HUP tac_plus
   
   # Check running configuration
   tacplus-ctl config show
   ```

### Debug Logging

```ini
[logging]
log_level = DEBUG
log_file = /var/log/tacacs/debug.log
max_log_size = 100MB
backup_count = 5

# Enable detailed authentication logging
auth_debug = true
packet_debug = true
```

## Next Steps

- [Main Configuration Reference](CONFIGURATION.md)
- [Advanced Configuration Management](CONFIGURATION_ADVANCED.md)
