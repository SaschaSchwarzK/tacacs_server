# Okta Authentication Backend

This document describes the Okta backend integration, configuration, behavior, caching, and metrics.

## Overview

The Okta backend authenticates users via Okta and optionally derives a TACACS+/RADIUS privilege level from Okta group membership.

Supported flows
- Resource Owner Password Credentials (ROPC) password grant (configurable via `ropc_enabled`).
  - Note: ROPC is discouraged by Okta and may be disabled in many orgs.
- Optional token introspection for fallback when token expiry is unknown.

Group privilege mapping
- Uses the Okta Management API to query `/api/v1/users/{sub}/groups` if `api_token` is provided.
- Maps group names to privilege levels via `group_privilege_map` (case-insensitive).

## Configuration

Add `okta` to the `[auth]` backends list and configure the `[okta]` section. See `docs/CONFIGURATION.md` for all options. Key settings:

```ini
[auth]
backends = local, okta

[okta]
org_url = https://company.okta.com
client_id = ${OKTA_CLIENT_ID}
api_token = ${OKTA_API_TOKEN}      # required for group lookups
verify_tls = true

# Optional client secret for confidential clients (ROPC or introspection)
client_secret = ${OKTA_CLIENT_SECRET}

# Optional: require mapped group membership to pass authentication
require_group_for_auth = false
group_privilege_map = {"Network-Admins": 15, "Operators": 7, "Users": 1}

# Timeouts and pooling
connect_timeout = 3
read_timeout = 10
pool_maxsize = 50
max_retries = 2
backoff_factor = 0.3

# Caching
group_cache_ttl = 1800
group_cache_fail_ttl = 60

# Flow flags
ropc_enabled = true
introspection_enabled = false

# Circuit breaker
circuit_failures = 5
circuit_cooldown = 30
```

## Behavior

- Auth cache is keyed by HMAC(username, password) with a server-side key (`AUTH_CACHE_HMAC_KEY`). Passwords are never stored; only boolean results and safe attributes are cached.
- JWT `exp` is used only as a cache hint; it is not trusted for authorization.
- Group names are normalized to lowercase before matching, and mappings are case-insensitive.
- 429 handling:
  - Token endpoint: respects `Retry-After` by opening the circuit breaker for a short cooldown.
  - Groups endpoint: respects `Retry-After` by increasing the short negative-cache TTL to reduce thundering herds.
- Circuit breaker: after `circuit_failures` consecutive failures, authentication is short-circuited for `circuit_cooldown` seconds; resets after cooldown.
- `close()` gracefully releases HTTP sockets; called during application shutdown.

## Required Okta permissions

- Authentication: ROPC requires an Okta app that allows password grant; many orgs prohibit this.
- Group lookups: The API token must have privileges to read user groups (`okta.groups.read` equivalent). Consult Okta documentation for least privilege.

## Metrics

Prometheus metrics (exposed by the monitoring endpoint):
- `okta_token_requests_total`: token endpoint requests
- `okta_token_latency_seconds`: token request latency
- `okta_group_requests_total`: group API requests
- `okta_group_latency_seconds`: group API latency
- `okta_retries_total`: count of retry-worthy responses (429/5xx)
- `okta_group_cache_hits_total`, `okta_group_cache_misses_total`
- `okta_circuit_open`: 1 when the circuit breaker is open; 0 when closed

The admin dashboard also shows a small status pill for the Okta backend (Healthy or Circuit Open) and the backend stats table includes `retries_429_total`.

## Security notes

- Do not log access tokens or passwords.
- Configure `AUTH_CACHE_HMAC_KEY` to keep auth cache keys stable across restarts.
- Prefer non-ROPC flows where possible (e.g., AuthN API, OIDC code flow + token introspection) based on your environment and policies.

