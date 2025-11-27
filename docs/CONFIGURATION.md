# TACACS+ Server Configuration

This document provides a comprehensive reference for configuring the TACACS+ server.

## Configuration Sources

1. **Primary Configuration File** (`config/tacacs.conf` by default)
   - Contains all default settings
   - Can be version controlled
   - Can be overridden using the `TACACS_CONFIG` environment variable
   - Supports both local files and HTTPS URLs

2. **Runtime Overrides** (`data/config_overrides.db`)
   - SQLite database storing configuration overrides
   - Takes precedence over file-based configuration
   - Maintains history of changes
   - Enables rollback to previous configurations

## Configuration Structure

The TACACS+ server uses INI-style configuration files with the following sections:

### Core Components
- `[server]` - Core server settings (bind address, ports, timeouts)
- `[auth]` - Authentication backends and settings
- `[security]` - Security policies and access controls
- `[logging]` - Logging configuration
- `[database]` - Database and storage configuration

### Authentication & Authorization
- `[ldap]` - LDAP/Active Directory integration
- `[okta]` - Okta SSO integration
- `[command_authorization]` - Command authorization policies

### Network Services
- `[radius]` - RADIUS server configuration
- `[proxy_protocol]` - HAProxy PROXY v2 support (TACACS+ only)
- `[webhooks]` - Webhook notifications

### Administration
- `[admin]` - Admin console settings
- `[monitoring]` - Metrics and monitoring
- `[devices]` - Device inventory management

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TACACS_CONFIG` | Override config file path/URL | `/path/to/config.conf` |
| `ADMIN_USERNAME` | Web admin username | `admin` |
| `ADMIN_PASSWORD_HASH` | Hashed admin password | `$2b$...` |
| `CONFIG_REFRESH_SECONDS` | Config refresh interval | `300` |

## Configuration precedence

**IMPORTANT:** Configuration values are applied in this precedence order (highest wins):

```
1. Runtime / DB overrides (Admin UI or in-memory overrides)
  ↓
2. Configuration file or URL
  ↓
3. Environment variables
  ↓
4. Default values (lowest priority)
```

Notes:
- Runtime overrides made via the Admin UI are stored in the configuration override store (e.g. `data/config_overrides.db`) and are applied on top of other sources.
- When the server reloads configuration (file reload or URL refresh), environment overrides are reapplied and then runtime/DB overrides are reapplied so the precedence above is preserved.

## Next Steps

- [Advanced Configuration Management](CONFIGURATION_ADVANCED.md) - Versioning, drift detection, and advanced features
- [Configuration Examples](CONFIGURATION_EXAMPLES.md) - Practical configuration examples and recipes
# Maximum concurrent connections (default: 50)
max_connections = 50

# Socket timeout in seconds (default: 30)
socket_timeout = 30

# Enable HAProxy PROXY v2 protocol support (default: false)
# Note: Only applicable to TACACS+ (TCP), not RADIUS (UDP)
accept_proxy_protocol = false
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

# Optional: connection pool size for reused TCP sessions (default 5)
pool_size = 5

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
bind_password = ${LDAP_BIND_PASSWORD}
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
bind_password = ${LDAP_BIND_PASSWORD}
use_tls = true
group_attribute = memberOf
```

## Okta Configuration

```ini
[okta]
# Okta organization URL
org_url = https://company.okta.com

# OAuth client credentials (choose one auth_method: client_secret or private_key_jwt)
# auth_method = client_secret
# client_id = ${OKTA_CLIENT_ID}
# client_secret = ${OKTA_CLIENT_SECRET}
# auth_method = private_key_jwt
# client_id = ${OKTA_CLIENT_ID}
# private_key = /path/to/private_key.pem
# private_key_id = <kid>
# token_endpoint = https://company.okta.com/oauth2/v1/token   # optional override

# TLS verification (default true)
verify_tls = true

# Privilege is derived via local user groups and the authorization policy engine.
# No static Okta group -> privilege mapping is required.

# Optional: Require membership in an allowed Okta group (from device group allow‑list) to succeed auth (default false)
require_group_for_auth = false

# Connection and pooling options (defaults used if not set)
request_timeout = 10
connect_timeout = 3
read_timeout = 10
pool_maxsize = 50
max_retries = 2
backoff_factor = 0.3
trust_env = false         # ignore system proxy vars when false

# Group cache controls
group_cache_ttl = 1800
group_cache_maxsize = 50000
group_cache_fail_ttl = 60

# Flow controls
# AuthN API
authn_enabled = true
strict_group_mode = false # raise error at init if require_group_for_auth=true but api_token missing

# Circuit breaker for Okta outages
circuit_failures = 5
circuit_cooldown = 30

# Notes:
# - Management API token scopes: ensure the token has permission to read user groups.
#   Typical scope: okta.groups.read (via API token privileges). Consult Okta docs.
# - /users/{id}/groups results may paginate; the implementation follows Link rel="next".
# - 429 handling: The implementation honors Retry-After on token and groups endpoints.
#   For tokens, Retry-After may open the circuit breaker for a short cooldown; for
#   groups, Retry-After increases the short negative cache TTL to reduce retries.

# Optional: Default Okta Group bootstrap
# If set, provide the Okta group ID (not name). On startup, the server
# ensures a local user group named 'okta-default-group' exists, sets
# its okta_group to the provided Okta group ID, and adds that local
# group to the default device group's allowed_user_groups. If unset,
# no bootstrap occurs.
default_okta_group =
```

## Devices Configuration

```ini
[devices]
database = data/devices.db
default_group = default
auto_register = false
identity_cache_ttl_seconds = 60
identity_cache_size = 10000
```

- `database`: SQLite file where device groups and devices are stored
- `default_group`: Group created on first start if none exists and used for auto‑registered clients
- `auto_register`: When true, unknown TACACS+/RADIUS clients are auto‑registered into the `default_group` (single‑host entries). Defaults to `false` for stricter security and must be enabled explicitly.
- `identity_cache_ttl_seconds`: TTL (seconds) for the in-memory identity lookup cache `(client_ip, proxy_ip) -> device`
- `identity_cache_size`: Maximum entries in the identity cache

### Proxy-aware device groups

Device groups can optionally define a `proxy_network` (CIDR). When set, connections only match devices in that group if the immediate proxy/load balancer IP is within that CIDR (exact match). When not set (NULL), the group acts as a fallback for direct connections (or proxied connections when no exact proxy match exists), preserving backward compatibility.

Lookup order:

1. Exact: `client_ip ∈ device.network` AND `proxy_ip ∈ group.proxy_network` (longest prefix wins)
2. Fallback: `client_ip ∈ device.network` AND `group.proxy_network` is NULL (longest prefix wins)
3. Otherwise: reject

This enables tenant isolation (each tenant’s devices match only through their proxy) while allowing deployments where both proxied and direct connections coexist.

## PROXY Protocol Configuration

When running behind load balancers that send HAProxy PROXY v2 headers, configure the dedicated section:

```ini
[proxy_protocol]
enabled = true                   # Enable proxy-aware mode
accept_proxy_protocol = true     # Consume/use PROXY v2 headers
validate_sources = true          # Require proxy IP to be in configured proxies
reject_invalid = true            # Reject malformed/unsupported PROXY headers
```

Notes
- `accept_proxy_protocol` supersedes the legacy `[server].accept_proxy_protocol` (the server also accepts `accept_headers` as a legacy alias).
- With `reject_invalid=true` (default), connections that present a PROXY signature but contain an invalid header are rejected and logged.

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

# Log format is structured JSON by default at runtime; any configured custom
# format string is ignored to ensure consistency.

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

Important
- The admin web UI is disabled unless an admin password hash is configured. If `password_hash` is empty (and no `ADMIN_PASSWORD_HASH` env var is set), all `/admin/*` pages return `503 Service Unavailable` and the login page displays a banner explaining that admin auth is not configured.
- Only the admin credentials in this section (or the corresponding environment variables) grant access to the admin web UI. The local TACACS+/RADIUS user database does not grant web admin access.
- All `/admin/*` endpoints (including redirects like `/admin` and `/admin/config/`) require authentication.
- Security headers are set by default (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, X-XSS-Protection). The `Server` header is removed by middleware.

## Command Authorization Configuration

```ini
[command_authorization]
default_action = deny            # or permit
# Response mode for allowed decisions when a rule does not specify response_mode
response_mode = pass_add         # or pass_repl

# Optional rules list; can be managed via Admin UI/API
rules_json = [
  {"action":"permit","match_type":"prefix","pattern":"show ","min_privilege":1}
]

# Privilege check enforcement order relative to command policy
# - before (default): deny early if requested priv exceeds user privilege
# - after: evaluate rules first to allow holistic decisions (RFC 8907 intent)
# - none: disable the pre-check; rules fully decide
privilege_check_order = before
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
# SQLite database used by the device inventory
database = data/devices.db

# Name of the default device group that is ensured on startup and used
# when auto-registering unknown RADIUS/TACACS+ clients (see devices.store)
default_group = default

# Enable/disable auto-registration of unknown clients into the default group.
# Defaults to false for stricter security; enable explicitly when required.
auto_register = false

# In‑memory identity cache for (client_ip, proxy_ip) → device lookups
identity_cache_ttl_seconds = 60
identity_cache_size = 10000
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
```

## Webhook Configuration

```ini
[webhooks]
# Comma-separated list of webhook endpoints. Leave empty to disable.
urls = https://hooks.example.com/a,https://hooks.example.com/b

# Optional HTTP headers as JSON (for auth or metadata)
headers_json = {"Authorization": "Bearer <token>", "X-App": "TACACS"}

# Optional payload template as JSON. Use {{placeholders}} to pull values
# from the event payload (e.g., username, client_ip, event, detail).
template_json = {"event": "{{event}}", "user": "{{username}}", "ip": "{{client_ip}}"}

# Request timeout in seconds
timeout = 3

# Failure thresholding: when set (>0), triggers an aggregated webhook event
# once "threshold_count" failures occur within "threshold_window" seconds.
threshold_count = 0
threshold_window = 60
```

- URLs: Provide one or more endpoints; the server sends JSON POST payloads.
- Headers: JSON object applied to each POST (commonly Authorization).
- Template: If provided, shapes the JSON payload using {{placeholders}}.
- Timeout: Per-request timeout in seconds.
- Thresholds: When enabled, the server records failures and emits a consolidated
  alert when the count/window criteria are met.

Admin UI mapping (Admin → Webhooks):
- Webhook URLs → `urls`
- Headers (JSON) → `headers_json`
- Template (JSON) → `template_json`
- Timeout (seconds) → `timeout`
- Failure Threshold Count → `threshold_count`
- Threshold Window (seconds) → `threshold_window`

Notes:
- The admin UI at `/admin/webhooks` edits the live runtime configuration and
  persists changes back to the configuration file via the `/admin/webhooks-config` API.
- Environment variables are also supported for quick setup: `WEBHOOK_URL`,
  `WEBHOOK_URLS`, `WEBHOOK_HEADERS`, `WEBHOOK_TEMPLATE`, `WEBHOOK_TIMEOUT`.

## Command Authorization

Fine‑grained command authorization rules can be configured and managed at runtime. The engine evaluates rules in order and applies a default action when no rule matches.

```ini
[command_authorization]
# Default action when no rule matches: permit or deny
default_action = deny

# Rules are stored as JSON (array of rule objects)
# Each rule fields: action, match_type (exact|prefix|regex|wildcard), pattern,
# min_privilege, max_privilege, optional description, user_groups, device_groups
rules_json = []
```

Examples
- Permit read‑only Cisco commands for users with privilege >= 1:
  - {"action":"permit","match_type":"prefix","pattern":"show ","min_privilege":1}
- Deny reload for any privilege:
  - {"action":"deny","match_type":"wildcard","pattern":"reload*","min_privilege":0,"max_privilege":15}

Admin UI
- Navigate to `/admin/command-authorization`:
  - Default Action toggle (permit/deny)
  - Manage Rules: add/delete rule entries
  - Test Command: check a command against current policy (privilege, groups, device group)

API
- Settings
  - GET `/api/command-authorization/settings` → `{default_action}`
  - PUT `/api/command-authorization/settings` with `{default_action}`
- Rules
  - GET `/api/command-authorization/rules` → list of rules
  - POST `/api/command-authorization/rules` → add a rule
  - DELETE `/api/command-authorization/rules/{rule_id}` → remove a rule
  - GET `/api/command-authorization/templates` → available templates
  - POST `/api/command-authorization/templates/{name}/apply` → apply template

Runtime Behavior
- TACACS+ authorization consults the engine (in addition to existing prefix rules) using the current user privilege level, user groups, and device group to make an allow/deny decision. Denials emit an `authorization_failure` webhook with reason.

## API Token Protection

By default the REST API under `/api/*` is disabled unless an API token is configured. To enable and protect the API, set an API token via environment variable:

- `API_TOKEN="<your-strong-token>"`

Accepted headers on requests:
- `X-API-Token: <your-strong-token>`
- or `Authorization: Bearer <your-strong-token>`

Notes:
- Admin endpoints under `/api/admin/*` also require an authenticated admin session. The admin UI calls these with the session cookie; direct calls must also include the API token header.
- Configure admin credentials in `[admin]` (username, password_hash) and log in via the admin UI.

## Environment Variables (credentials only)

Configuration is loaded from a file/URL. Environment variables are used to supply keys that are not present in the loaded configuration; sensitive secrets (for example `ADMIN_PASSWORD_HASH`, Okta API token, RADIUS secret) are injected from the environment regardless of a file value. Interpolation like `${VAR}` is not evaluated (the config parser runs with `interpolation=None`); secrets are injected by explicit overrides in the loader.

Key environment variables

| Variable | Purpose | Notes |
|----------|---------|-------|
| `TACACS_CONFIG` | Configuration source path/URL | Overrides default `config/tacacs.conf` |
| `CONFIG_REFRESH_SECONDS` | URL config refresh interval | Used by config URL handler/scheduler |
| `ADMIN_USERNAME` | Admin UI username | Mirrors `[admin].username` (file → env precedence) |
| `ADMIN_PASSWORD_HASH` | Bcrypt admin password hash | Populates `[admin].password_hash`; preferred for production |
| `ADMIN_PASSWORD` | Plaintext admin password | Hashed at startup only when `ADMIN_PASSWORD_HASH` is not set; development convenience only |
| `LDAP_BIND_PASSWORD` | LDAP bind password | Injected into `[ldap].bind_password` |
| `OKTA_DOMAIN` / `OKTA_CLIENT_ID` / `OKTA_CLIENT_SECRET` / `OKTA_PRIVATE_KEY` / `OKTA_PRIVATE_KEY_ID` | Okta integration secrets | Populate `[okta]` fields via the loader |
| `BACKUP_ENCRYPTION_PASSPHRASE` | Backup encryption passphrase | Injected into `[backup].encryption_passphrase` |
| `RADIUS_AUTH_SECRET` | RADIUS auth backend shared secret | Injected into `[radius_auth].radius_secret` |
| `API_TOKEN` | Admin/API bearer token for `/api/*` | Used by the web API middleware/`require_admin_or_api` |

Examples

```ini
# In configuration file: values are plain strings;
# environment variables override them when set.

[ldap]
bind_password = "change-me"  # overridden by LDAP_BIND_PASSWORD if present

[okta]
;client_secret = "placeholder"

[admin]
username = admin
password_hash = ""           # overridden by ADMIN_PASSWORD_HASH if present
```

```bash
# In environment (secrets only; non-secret tuning via config file)
export LDAP_BIND_PASSWORD="secure_ldap_password"
export OKTA_CLIENT_SECRET="example"
export ADMIN_PASSWORD_HASH="$2b$12$..."
export API_TOKEN="$(openssl rand -hex 24)"
export TACACS_CONFIG="/etc/tacacs/tacacs.conf"
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

Tip: For a quick checklist of common pitfalls (API tokens, admin hash, PROXY protocol scope, UDP constraints), refer to the top-level FAQ.md.

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
bind_password = ${LDAP_BIND_PASSWORD}
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
