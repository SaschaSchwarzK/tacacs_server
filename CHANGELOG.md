# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]
### Added
- Proxy-aware device matching with HAProxy PROXY protocol v2 (TCP):
  - Exact match: client_ip ∈ device.network AND proxy_ip ∈ group.proxy_network
  - Fallback match: client_ip ∈ device.network AND proxy_network IS NULL
  - Tenant isolation with per-group `proxy_network` (CIDR)
- Identity lookup cache for (client_ip, proxy_ip) → device with configurable TTL/size:
  - `[devices].identity_cache_ttl_seconds`, `[devices].identity_cache_size`
  - In-memory TTL cache + prefix-sorted in-memory indexes
  - Optional SQL numeric range prefilter to reduce candidates on large inventories
- Prometheus metrics:
  - Proxied vs direct: `tacacs_connections_proxied_total`, `tacacs_connections_direct_total`
  - Identity cache Gauges: hits/misses/evictions
  - Identity cache Counters: hits_total/misses_total/evictions_total
- Admin API/UI support for `proxy_network` on device groups (create, update, list, details)
- Integration/unit/functional tests covering PROXY v2 parsing, identity matching, cache metrics, and API endpoints
- Admin CLI `tacacs-admin` with `check-config`, `generate-bcrypt`, `audit-hashes`, `migrate-hashes`.
- Security headers middleware across web apps.
- Readiness (`/ready`) and liveness (`/health`) endpoints.
- Per-IP connection cap (configurable) and extended rate limiting.
- Multi-stage Dockerfile with ACA/ACI profiles and ACI deployment template.
- Property-based and golden-vector tests for TACACS packet/validation and malformed inputs.

### Changed
- Admin auth now bcrypt-only; legacy SHA-256 rejected with clear guidance.
- Local user password verification centralized with rehash-on-login for legacy.
- Device store gains precomputed device network numeric ranges (IPv4/IPv6) for optional SQL prefiltering.
- Device store maintains in-memory indexes and a TTL cache for fast identity lookups; indexes refresh on change events.

### Fixed
- Test environment uses isolated temp DBs; avoids polluting production DB.

### Migration Notes
- New columns will be added automatically at startup if missing:
  - `device_groups.proxy_network` (TEXT)
  - `device_groups.realm_id` (INTEGER, references `realms.id`)
  - `devices.network_start`, `devices.network_end` (TEXT) with index `idx_devices_net_range`
- A default `realms` table is created and all existing groups are assigned to the `default` realm.
- Existing configurations continue to work: groups without `proxy_network` remain valid fallback targets.
- You can tune the identity cache via `[devices]` section:
  - `identity_cache_ttl_seconds = 60`
  - `identity_cache_size = 10000`
