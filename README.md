# TACACS+ Server

A simple TACACS+ (Terminal Access Controller Access-Control System Plus) server implementation in Python providing Authentication, Authorization and Accounting (AAA) backends and test tooling.

Features
- Authentication backends: local, LDAP, Okta
- Authorization via group membership (Okta/LDAP) or local rules
- Accounting support and example TACACS+ server for testing
- Web Dashboard Real-time statistics
- Prometheus Integration Standard metrics, Grafana ready 
- REST API Health checks, Detailed stats, Admin controls and recent logs
- Test suite with pytest and helper scripts

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



| Endpoint                     | Description                  |
|-------------------------------|------------------------------|
| GET /HTML                     | Dashboard                   |
| GET /api/statusServer         | status JSON                 |
| GET /api/healthHealth         | check                       |
| GET /api/statsDetailed        | statistics                  |
| GET /api/backendsAuth         | backend status              |
| GET /api/sessions             | Active sessions             |
| GET /api/accounting           | Recent accounting records   |
| GET /metrics                  | Prometheus metrics          |
| POST /api/admin/reload-config | Reload configuration        |
| POST /api/admin/reset-stats   | Reset statistics            |


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
- scripts/              -> helper scripts (test_client.py, setup_project.py)
- config/, data/, logs/ -> runtime directories created by setup_project.py

Important files
- pyproject.toml        -> Poetry configuration and package metadata
- README.md             -> this file
- LICENSE               -> license text (MIT)
- MANIFEST.in           -> optional package include patterns
- scripts/setup_project.py -> create runtime dirs and move test client
- scripts/test_client.py -> test client script (moved from tests/)

Configuration
- Default config file: config/tacacs.conf
- Use --config to point to a custom file when starting the server

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
- See LICENSE file for details.