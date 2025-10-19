# Security Policy

## Supported Versions
The `main` and `develop` branches are actively maintained. Security updates are released as needed.

## Reporting a Vulnerability
Please open a private security advisory on GitHub (Security > Advisories) or contact the maintainers.

## Guidelines
- Do not include secrets in code or images. Provide secrets via environment variables or mounted files.
- Admin passwords must use bcrypt. Legacy hashes are not supported for admin and are auto-migrated for local users on login.
- Enable HTTPS in production and ensure `SECURE_COOKIES=true`.

## Threat Model (High Level)

- Assets: Authentication credentials, accounting logs, device/group configuration, API tokens, admin sessions.
- Trust boundaries: Network devices (untrusted), admin users, web/API clients, local storage (DB files), external auth providers.
- Attack surfaces:
  - TACACS+/RADIUS listeners (malformed packets, floods)
  - Web/API endpoints (auth bypass, input validation)
  - Auth backends (timeout abuse, credential stuffing)
  - Local databases (tampering, leakage)

Mitigations:
- Protocol validation and max packet length caps; rate limiting per IP.
- Authentication on admin/API; CSRF-safe design when using API tokens; strict cookie security in production.
- Backend timeouts and rate limiting; caching with TTL to reduce stale data.
- SQLite PRAGMAs and path validation; optional syslog for audit trail.

## Security Assumptions

- The deployment environment enforces TLS termination and firewalling of admin/API.
- Secrets are provided via environment/secret stores; not hardcoded in config files.
- Device groups are configured with distinct TACACS+/RADIUS secrets.

## Deployment Best Practices

- Run behind a reverse proxy with HTTPS (e.g., Nginx, Envoy).
- Restrict inbound access to TACACS+/RADIUS ports to trusted networks.
- Set strong per-device group secrets; rotate regularly.
- Configure `API_TOKEN` and enforce token checks for `/api/*`.
- Set secure cookie flags in production (Secure, HttpOnly, SameSite=Lax/Strict).
- Use systemd or container orchestrators with health checks and resource limits.
- Monitor logs (JSON events) and metrics; set alerts for repeated failures.
