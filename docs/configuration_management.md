Configuration Management Guide

Overview
- The server supports layered configuration with explicit precedence and durable audit history.
- Sources (high → low): environment variables → database overrides → base (file/URL) → defaults.

Override Database Schema
- SQLite database at `data/config_overrides.db` with tables:
  - config_overrides: active overrides with unique (section,key) while active.
  - config_history: audit trail for changes (old/new values, who, when, reason, hash).
  - config_versions: full configuration snapshots with SHA-256 hash.
  - system_metadata: instance identity (instance_id/name), config_source, last_url_fetch.

API Endpoints (Admin)
- Base prefix: `/api/admin/config`
- GET `/sections` → list sections
- GET `/{section}` → values + overridden_keys
- POST `/validate` → validate change before apply; params: section, key, value
- PUT `/{section}` (body: `{section, updates, reason}`) → applies changes with validation & history
- GET `/history` (optional `section`, `limit`) → audit trail
- GET `/versions` → list version snapshots (metadata)
- POST `/versions/{version}/restore` → safety snapshot, then restore snapshot
- GET `/drift` → detect differences between base and overrides

Merge Behavior
- TacacsConfig loads defaults → base (file/URL) → applies DB overrides → environment variables are respected in getters.
- URL sources are cached to `data/config_baseline_cache.conf` and refreshed periodically (CONFIG_REFRESH_SECONDS).

Pre-Apply Validation
- Use `/api/admin/config/validate` to check changes.
- Server-side checks include schema validation and custom rules like port availability and approved backend names.

Best Practices (Production)
- Prefer URL-based configuration for centralized management; enforce HTTPS and avoid localhost/private addresses.
- Use overrides sparingly for emergency hotfixes; track reasons and users.
- Enable periodic refresh (default 5 minutes) and monitor the logs for baseline updates.
- Implement backup/retention via the `backup` config (cron schedule, destination), and snapshot versions before maintenance.

