# TACACS+ Server

A modern TACACS+/RADIUS appliance implemented in Python. The project focuses on clear configuration management, secure credential handling, and an approachable web console for daily operations.

![Dashboard](docs/images/Dashbaord_page.png)

## Key Features
- **AAA backends**: Local SQLite, LDAP, and Okta integrations with group-aware authorisation rules.
- **Secure device management**: Shared secrets defined on device groups only (no per-device secrets), with masking in logs and UI.
- **Rich admin console**: Manage devices, device groups, user groups, local users, and review masked configuration directly in the browser.
- **Insightful dashboard**: Dedicated tiles for system health, TACACS+, and RADIUS showing real-time success/failure rates, CPU/memory usage, and connection counts.
- **Event visibility**: Consistent TACACS+/RADIUS logging with detailed failure reasons and backend identifiers.
- **Prometheus ready**: `/metrics` endpoint plus helper Grafana queries.
- **Config flexibility**: Load configuration from the default file or via the `TACACS_CONFIG` environment variable (filesystem path or URL).
- **Comprehensive test suite**: Pytest-based tests and helper scripts for TACACS+/RADIUS clients.

Quickstart (Poetry)
1. Install dependencies:
   poetry install

2. Set up runtime directories (config, data, logs, scripts):
   python scripts/setup_project.py --project-root "$(pwd)" --move-test-client

3. (Optional) Install editable package in current environment:
   poetry run pip install -e .

4. Run tests:
   poetry run pytest -q

Running the server
- Use the package entrypoint:
  poetry run python -m tacacs_server.main --config path/to/tacacs.conf
- Or after installation:
  poetry run tacacs-server

Access the Web Interface:

- Dashboard: http://127.0.0.1:8080
- API Status: http://127.0.0.1:8080/api/status
- Health Check: http://127.0.0.1:8080/api/health
- Prometheus Metrics: http://127.0.0.1:8080/metrics

## Admin Web Console

- **Dashboard** – Three dedicated tiles for system health, TACACS+, and RADIUS along with recent devices, groups, and users.
- **Devices** – Create or edit devices with a group dropdown (no inline secrets).
  ![Devices](docs/images/Devices_page.png)
- **Device Groups** – Maintain shared secrets, device metadata, and allowed user groups via multi-select controls.
  ![Device groups](docs/images/Device_Groups_page.png)
- **User Groups** – Manage privilege levels and directory mappings.
  ![User groups](docs/images/User_Groups_page.png)
- **Local Users** – Edit users, privilege, and group memberships with selection lists.
  ![Users](docs/images/Users_page.png)
- **Configuration Viewer** – Read-only view of the active configuration with secrets masked, reflecting whatever source `TACACS_CONFIG` resolved to.
  ![Configuration](docs/images/Configuration_page.png)

Unauthenticated admin requests are redirected to the login page; sessions are held in-memory with configurable timeouts.

## Configuration

- Default configuration file: `config/tacacs.conf`
- Override via environment variable: `TACACS_CONFIG=/path/to/tacacs.conf` or `TACACS_CONFIG=https://example/config.ini`
- URL sources are fetched read-only; local files remain editable through the web console or manual edits.

## APIs & Monitoring

- `/api/status`, `/api/stats`, `/api/backends`, `/api/sessions`, `/api/accounting` – JSON endpoints backing the UI.
- `/api/admin/reload-config`, `/api/admin/reset-stats` – management helpers.
- `/metrics` – Prometheus scrape endpoint.

Prometheus Configuration
Add this to your prometheus.yml:

```yaml
scrape_configs:
  - job_name: 'tacacs-server'
    static_configs:
      - targets: ['127.0.0.1:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```
Grafana Dashboard
Create a Grafana dashboard with these queries:
```promql
# Authentication Rate
rate(tacacs_auth_requests_total[5m])

# Success Rate
(rate(tacacs_auth_requests_total{status="success"}[5m]) / rate(tacacs_auth_requests_total[5m])) * 100

# Active Connections
tacacs_active_connections

# Server Uptime
tacacs_server_uptime_seconds
```


Project layout
- tacacs_server/        -> package source
  - auth/               -> authentication backends (local.py, ldap_auth.py, okta_auth.py, base.py)
  - tacacs/             -> TACACS+ protocol/server implementation (server.py, handlers.py, packet.py, constants.py)
  - accounting/         -> accounting models and database helpers (models.py, database.py)
  - config/             -> configuration helpers (config.py)
  - static/             -> Custom styles
  - templates/          -> HTML template
  - utils/              -> utility helpers (crypto.py, logger.py)
  - web/                -> monitoring and admin API
  - cli.py              -> package CLI entrypoint
  - main.py             -> package main() entrypoint
- tests/                -> pytest test-suite and conftest
- scripts/              -> helper scripts (tacacs_client.py, setup_project.py)
- config/, data/, logs/ -> runtime directories created by setup_project.py

Important files
- pyproject.toml        -> Poetry configuration and package metadata
- README.md             -> this file
- LICENSE               -> license text (MIT)
- MANIFEST.in           -> optional package include patterns
- scripts/setup_project.py -> create runtime dirs and move test client
- scripts/tacacs_client.py -> TACACS+ client script (moved from tests/)

Configuration
- Default config file: config/tacacs.conf
- Use --config to point to a custom file when starting the server
- Set `TACACS_CONFIG` to a file path or URL to load config automatically

Testing notes
- Tests expect either the package installed editable (poetry run pip install -e .) or running with PYTHONPATH set to the project root:
  PYTHONPATH="$(pwd)" poetry run pytest -q

Development notes
- Prefer Authorization Code / PKCE or Authn API + SSWS token for Okta integrations.
- Keep secrets out of source control. Use environment variables or external secret store.
- Use poetry for dependency and packaging management.

Contributing
- Fork, create a feature branch, and open a pull request.
- Run tests locally: poetry run pytest

License
- MIT (Attribution Required). All forks, copies, or deployments must retain the
  upstream attribution notice and link back to
  https://github.com/SaschaSchwarzK/tacacs_server. See the LICENSE file for full
  terms.
