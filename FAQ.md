TACACS+ Server — Frequently Asked Questions (FAQ)

This FAQ collects common deployment questions, gotchas, and limitations observed when running the TACACS+ server and its optional components (Web UI/API, RADIUS, Syslog, etc.).


General Startup
- Where is the configuration file?  The server loads `config/tacacs.conf` by default (or the path provided via `--config` or `TACACS_CONFIG`). If the file doesn’t exist, a default one is created with safe defaults.
- How do I check that the server is healthy?  Use the Web API health endpoint `GET /api/health` (when monitoring is enabled), or check the process logs for “Server ready - waiting for connections…”.
- Why do I see “Default TACACS secret in use”?  If you have not set per‑device/group secrets in the device store, the TACACS server falls back to a compiled default and logs a warning. Configure device groups and set `tacacs_secret` in group metadata for production.


Web UI / Admin Authentication
- The Web UI says “Admin authentication required”.  You must configure the admin user in the config file:
  - In `[admin]`, set `username` and `password_hash` (bcrypt). Tests and tools can generate a hash; see docs or `LocalUserService` utilities.
  - If `password_hash` is empty, admin routes are disabled and requests are rejected by default.
- I can’t access Web UI or API without logging in.  This is intended when admin auth is enabled. For automated testing or development, you can set an `API_TOKEN` and use `Authorization: Bearer <token>` for API routes guarded by admin.


API Access / Tokens
- Why do API calls return 401/403?  When API token enforcement is enabled (`API_TOKEN` is set), requests must include `Authorization: Bearer <token>` or `X-API-Token: <token>`. Without a token the API may be disabled or reject requests by default.
- I’m getting redirected (307/308) instead of 401.  Some setups send redirects to login; tests treat 307/308 as a valid “locked down” response for admin endpoints.


Monitoring (OpenAPI / Docs)
- How do I enable the Web UI/API?  In `[monitoring]`, set `enabled = true`, `web_host`, `web_port`. The app will start a FastAPI+Uvicorn service on that address.
- “Server” header is exposed by Uvicorn.  We disable it via `server_header = False` and also strip headers in middleware. If you still see “uvicorn/…”, ensure you’re running the included code paths (not a custom runner) and that proxies don’t inject their own “Server” headers.


Command Authorization Engine
- My rules are being overwritten at runtime.  The engine is initialized once during startup from `[command_authorization]`. If you programmatically inject rules later, ensure you don’t reinitialize the engine (monitoring does not re‑init it). Use the provided load/export APIs to modify rules persistently.
- “authorization_granted/denied” is missing from logs.  The server writes structured JSON logs for both outcomes. Confirm you’re looking at the main server log (not just syslog) and that your log collector is not filtering INFO.


Syslog
- No syslog messages are received.  Configure `[syslog]` or set `SYSLOG_ADDRESS` for subsystems that support it. For the built‑in handler, set `[syslog] enabled=true, host, port, protocol=udp|tcp, facility, severity`.
- Messages look split or fields appear under “hostname”.  Simple RFC3164 parsers may split structured JSON into hostname/message fragments. Prefer RFC5424‑aware receivers or adjust tests to combine hostname/app/message.


PROXY Protocol (HAProxy v2)
- Which protocols support PROXY?  PROXY v2 is only applicable to the TACACS+ TCP server. RADIUS is UDP and does not use PROXY.
- How do I enable it?  In `[proxy_protocol]`, set `enabled=true`, `accept_proxy_protocol=true`. To enforce allow‑lists, also set `validate_sources=true` and configure proxy networks in the device store.
- Connections are rejected as “unknown proxy”.  When `validate_sources=true`, the proxy’s source IP must belong to a configured proxy network (Device Store > Proxies). Add your proxy CIDR (e.g., `127.0.0.1/32` for local testing).
- What does `validate_sources=false` do?  Lenient mode: invalid/unsupported PROXY headers are ignored and connections fall back to direct client IP. This prevents accidental lockouts during testing.


RADIUS (UDP)
- Why doesn’t RADIUS work on Azure Container Apps (ACA)?  ACA does not support UDP workloads; RADIUS is UDP and cannot be hosted there.
- Does Azure Container Instances (ACI) support UDP?  Yes — ACI supports UDP endpoints, so you can run the RADIUS component in ACI (or other platforms that allow UDP), while ACA remains unsuitable for UDP services.
- Sharing TACACS+ auth backends with RADIUS.  Enabled via `[radius] share_backends=true`. Ensure the device store and accounting are configured for both paths if needed.


Accounting Database
- Tests fail with “accounting_logs not found in DB”.  Ensure the server process current working directory (CWD) matches where tests expect files to appear. The test harness sets a per‑test work dir and starts the server with `cwd` set accordingly. Avoid overly restrictive path validation.
- Where is the DB stored?  `[database] accounting_db` (default `data/tacacs_accounting.db`). The directory is created if missing.


Security Headers & Server Metadata
- How do I enable strict security headers?  The middleware sets common headers by default (CSP, X‑Frame‑Options, X‑Content‑Type‑Options, etc.). You can override CSP via `CSP_POLICY` env var. HSTS is applied only when HTTPS (or `X‑Forwarded‑Proto=https`).
- Removing identifying headers.  The middleware removes `Server`, `X-Powered-By`, and other identifying headers. As a fallback, a generic `Server: AAA-Server` may be added if some platform forces a header.


Admin & Local Users
- User creation fails (“Password must be at least 8 characters”).  The local user service enforces minimum policy. Use strong passwords (e.g., `Passw0rd1`) in tests and examples.
- How do I seed users quickly?  Use `LocalUserService` against the configured `local_auth_db`, or wire admin+API and call the provided endpoints.


Ports, Networking, and Timeouts
- TACACS+ port binding fails.  Ensure the `server.port` is free and accessible. In test environments, the harness chooses an available port per run.
- Clients disconnect unexpectedly.  Check `client_timeout` in `[server]` and avoid long idle gaps between initial connection, PROXY header (if used), and sending TACACS data.


Containers & Cloud
- Why do I see missing bcrypt on some images?  Ensure your runtime image provides bcrypt compiled for your Python version. The server logs a warning if bcrypt is unavailable when admin auth is configured.
- Why does the API/Web UI show the wrong hostname?  Behind proxies/load balancers, set `X‑Forwarded‑Proto` and related headers correctly. HSTS is only applied when the request is HTTPS (directly or via forwarded proto).


Troubleshooting Checklist
- Enable DEBUG logs (set `server.log_level = DEBUG`) to surface detailed diagnostics.
- Verify configuration sections are present and saved (the server persists updates via its config manager).
- For PROXY v2, confirm the debug line `PROXY header: read=.., parser consumed=.., addr_len=..` shows expected values (IPv4 addr_len=12).
- Confirm API token and admin password hash are set if you expect authenticated access to the Web UI/API.
- For syslog, check logs for `Syslog configured: host:port proto=.. facility=.. severity=..` and verify your receiver binds the same host/port.


Limitations / Design Notes
- PROXY v2 is only implemented for TACACS+ (TCP). RADIUS is UDP and does not use PROXY.
- Azure Container Apps (ACA) do not support UDP. RADIUS cannot be hosted there.
- The server focuses on production‑grade defaults; some tests and examples set permissive values (e.g., lenient PROXY validation, flexible authorization defaults) to facilitate developer workflows.


Deployment Matrix (Capabilities Overview)
- TACACS+ (TCP)
  - Supported on most platforms (VMs, containers, Kubernetes). Works with ACA/ACI/AKS.
  - PROXY v2 available for TACACS+ only (not RADIUS). Ensure `accept_proxy_protocol=true` where required.
- RADIUS (UDP)
  - Azure Container Apps (ACA): Not supported (no UDP workloads).
  - Azure Container Instances (ACI): Supported (UDP endpoints allowed), suitable for RADIUS.
  - Azure Kubernetes Service (AKS): Supported; expose UDP Service and configure network policies as needed.
  - Bare-metal/VMs/other container runtimes: Supported (ensure host/network allows UDP 1812/1813).
- Syslog
  - UDP and TCP supported by the server’s syslog integration; ensure your platform/network opens the chosen port.
- Web UI / Monitoring (HTTP)
  - Runs on TCP; supported on all listed platforms. Behind proxies, set `X-Forwarded-Proto` for HSTS and correct scheme handling.
