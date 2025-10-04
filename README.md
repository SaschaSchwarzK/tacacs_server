# TACACS+ Server

[![Quality Checks](https://github.com/SaschaSchwarzK/tacacs_server/actions/workflows/quality_checks.yml/badge.svg)](https://github.com/SaschaSchwarzK/tacacs_server/actions/workflows/quality_checks.yml)

A modern, enterprise-grade TACACS+/RADIUS appliance implemented in Python. Designed for network administrators who need reliable AAA services with comprehensive management capabilities, real-time monitoring, and enterprise integrations.

![Dashboard](docs/images/Dashbaord_page.png)

## 🚀 Key Features

### **Authentication & Authorization (AAA)**
- **Multiple backends**: Local SQLite, LDAP, and Okta integrations
- **Group-based authorization**: User groups with privilege levels and device access control
- **Per-device group secrets**: No global secrets - each device group has its own TACACS+/RADIUS shared secrets
- **Policy engine**: Flexible authorization rules based on user groups and device groups
- **Password management**: Secure bcrypt hashing with configurable complexity

### **Protocol Support**
- **TACACS+ (RFC 8907)**: Full AAA support with encryption
- **RADIUS (RFC 2865/2866)**: Authentication and accounting
- **Shared backends**: Both protocols can use the same authentication sources
- **Per-device secrets**: Device groups define their own shared secrets
- **Rate limiting**: Configurable request rate limiting and connection management

### **Device & Network Management**
- **Device inventory**: Centralized device database with grouping
- **Network-based matching**: IP networks and CIDR ranges for device identification
- **Device groups**: Organize devices with shared configurations and secrets
- **Metadata support**: Custom attributes and configuration per device/group
- **Change notifications**: Real-time updates when device configurations change

### **Web Administration Console**
- **Real-time dashboard**: WebSocket-powered live metrics and system health
- **Device management**: Create, edit, and organize network devices and groups
- **User management**: Local user accounts with group assignments and privilege levels
- **Configuration viewer**: Live configuration display with validation status
- **Search & filtering**: Advanced filtering across all management interfaces
- **Session management**: Secure admin sessions with configurable timeouts

### **Monitoring & Observability**
- **Prometheus metrics**: `/metrics` endpoint with comprehensive server statistics
- **Real-time WebSocket**: Live dashboard updates without page refreshes
- **Historical data**: Metrics history with configurable retention
- **Health checks**: System health monitoring with memory and CPU metrics
- **Audit logging**: Comprehensive audit trail for all administrative actions
- **Event correlation**: Detailed logging with request tracing and failure analysis

### **Security & Compliance**
- **Input validation**: Comprehensive validation using Pydantic schemas
- **SQL injection protection**: Parameterized queries and input sanitization
- **Rate limiting**: Per-client request rate limiting
- **Secure secrets**: Per-device group secrets with no global fallbacks
- **Session security**: Secure admin sessions with CSRF protection
- **Audit trails**: Complete audit logging for compliance requirements

### **Configuration & Deployment**
- **Flexible configuration**: File-based or URL-based configuration loading
- **Environment integration**: Environment variable support for secrets
- **Docker support**: Container-ready with docker-compose configuration
- **Configuration validation**: Pre-deployment validation with detailed error reporting
- **Backup & restore**: Automatic configuration backups on changes
- **Hot reload**: Configuration changes without service restart

### **Development & Testing**
- **Comprehensive test suite**: 130+ tests with >90% coverage
- **Batch testing**: Test multiple credentials simultaneously
- **Performance benchmarks**: Built-in performance testing and metrics
- **Client tools**: TACACS+ and RADIUS client scripts for testing
- **API documentation**: Complete REST API documentation
- **Type safety**: Full mypy type checking

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Poetry (recommended) or pip

### Installation

```bash
# Clone the repository
git clone https://github.com/SaschaSchwarzK/tacacs_server.git
cd tacacs_server

# Install dependencies
poetry install

# Set up runtime directories
python scripts/setup_project.py --project-root "$(pwd)" --move-test-client

# Run tests to verify installation
poetry run pytest -q
```

### Running the Server

```bash
# Start the server
poetry run python -m tacacs_server.main --config config/tacacs.conf

# Or use the CLI entrypoint
poetry run tacacs-server

# Validate configuration before starting
poetry run python scripts/validate_config.py
```

### Web Interface Access

| Service | URL | Description |
|---------|-----|-------------|
| **Dashboard** | http://127.0.0.1:8080 | Main admin interface |
| **API Status** | http://127.0.0.1:8080/api/status | Server status JSON |
| **Health Check** | http://127.0.0.1:8080/api/health | Health monitoring |
| **Metrics** | http://127.0.0.1:8080/metrics | Prometheus metrics |
| **WebSocket** | ws://127.0.0.1:8080/ws/metrics | Real-time updates |

### Testing the Installation

```bash
# Test TACACS+ authentication
python scripts/tacacs_client.py localhost 49 tacacs123 admin admin123

# Test RADIUS authentication  
python scripts/radius_client.py localhost 1812 radius123 admin admin123

# Batch test multiple credentials
python scripts/tacacs_client.py --batch scripts/example_credentials.csv
```

## 📊 Admin Web Console

The web console provides comprehensive management capabilities with real-time monitoring:

### **Real-time Dashboard**
- Live-updating metrics tiles with WebSocket connectivity
- System health monitoring (CPU, memory, uptime)
- TACACS+ and RADIUS statistics with success rates
- Active connections and session tracking
- Historical metrics with configurable time ranges

### **Device Management**
![Devices](docs/images/Devices_page.png)
- **Device inventory**: Add, edit, and organize network devices
- **Network matching**: IP addresses and CIDR ranges for device identification
- **Search & filtering**: Advanced filtering by name, network, group, and status
- **Bulk operations**: Import/export device configurations
- **No inline secrets**: Secrets managed at device group level for security

### **Device Groups**
![Device groups](docs/images/Device_Groups_page.png)
- **Shared secrets**: TACACS+ and RADIUS secrets per group
- **User group permissions**: Control which user groups can access devices
- **Metadata management**: Custom attributes and configuration templates
- **Multi-select controls**: Easy assignment of users and permissions
- **Configuration profiles**: TACACS+ and RADIUS profiles per group

### **User Groups**
![User groups](docs/images/User_Groups_page.png)
- **Privilege levels**: Configure authorization levels (0-15)
- **Directory mappings**: Map to LDAP/Okta groups
- **Access control**: Define which device groups users can access
- **Bulk management**: Import/export user group configurations

### **Local Users**
![Users](docs/images/Users_page.png)
- **User accounts**: Create and manage local user accounts
- **Group assignments**: Assign users to multiple groups
- **Password management**: Secure bcrypt hashing
- **Status tracking**: Enable/disable accounts
- **Search & filtering**: Filter by status, group, and activity
- **Bulk operations**: Import users from CSV

### **Configuration Management**
![Configuration](docs/images/Configuration_page.png)
- **Live configuration**: Real-time view of current configuration
- **Validation status**: Immediate feedback on configuration issues
- **Backup functionality**: Automatic backups on changes
- **Change tracking**: Audit trail of configuration modifications
- **Export/import**: Configuration portability

### **Security Features**
- **Session management**: Secure admin sessions with configurable timeouts
- **Authentication required**: All admin requests require authentication
- **CSRF protection**: Cross-site request forgery protection
- **Input validation**: Comprehensive validation of all inputs
- **Audit logging**: Complete audit trail of administrative actions

## ⚙️ Configuration

### **Configuration Sources**
- **Default file**: `config/tacacs.conf`
- **Environment override**: `TACACS_CONFIG=/path/to/tacacs.conf`
- **URL sources**: `TACACS_CONFIG=https://example.com/config.ini` (read-only)
- **Web console**: Live editing through admin interface

### **Configuration Sections**

#### **Server Configuration**
```ini
[server]
host = 0.0.0.0
port = 49
log_level = INFO
max_connections = 50
socket_timeout = 30
```

#### **Authentication Backends**
```ini
[auth]
backends = local,ldap
local_auth_db = data/local_auth.db
require_all_backends = false
```

#### **LDAP Integration**
```ini
[ldap]
server = ldap://localhost:389
base_dn = ou=people,dc=example,dc=com
user_attribute = uid
bind_dn = cn=admin,dc=example,dc=com
bind_password = secret
use_tls = true
timeout = 10
```

#### **RADIUS Server**
```ini
[radius]
enabled = true
auth_port = 1812
acct_port = 1813
host = 0.0.0.0
share_backends = true
share_accounting = true
```

#### **Security Settings**
```ini
[security]
max_auth_attempts = 3
auth_timeout = 300
encryption_required = true
rate_limit_requests = 60
rate_limit_window = 60
```

### **Configuration Management**
- **Validation**: `python scripts/validate_config.py`
- **Automatic backups**: Changes create timestamped backups
- **Hot reload**: Configuration changes without restart
- **Schema validation**: Pydantic-based validation with detailed error messages
- **Environment variables**: Support for secrets via environment variables

## 🔌 APIs & Monitoring

### **REST API Endpoints**

#### **Status & Health**
- `GET /api/status` - Server status and statistics
- `GET /api/health` - Health check with system metrics
- `GET /api/stats` - Detailed server statistics
- `GET /api/backends` - Authentication backend status
- `GET /api/sessions` - Active session information
- `GET /api/accounting` - Recent accounting records

#### **Device Management**
- `GET /api/devices` - List all devices with filtering
- `POST /api/devices` - Create new device
- `GET /api/devices/{id}` - Get device details
- `PUT /api/devices/{id}` - Update device
- `DELETE /api/devices/{id}` - Delete device
- `GET /api/device-groups` - List device groups
- `POST /api/device-groups` - Create device group

#### **User Management**
- `GET /api/users` - List local users with filtering
- `POST /api/users` - Create new user
- `GET /api/users/{id}` - Get user details
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user
- `GET /api/user-groups` - List user groups
- `POST /api/user-groups` - Create user group

#### **Administrative**
- `POST /api/admin/reload-config` - Reload configuration
- `POST /api/admin/reset-stats` - Reset server statistics
- `GET /api/admin/logs` - Recent log entries
- `POST /api/admin/backup-config` - Create configuration backup

#### **RADIUS (when enabled)**
- `GET /api/radius/status` - RADIUS server status
- `GET /api/radius/clients` - RADIUS client configuration

### **Real-time Updates**
- `WebSocket /ws/metrics` - Real-time metrics for dashboard
- Live updates for connections, authentication rates, and system health
- Automatic reconnection with exponential backoff

### **Monitoring Integration**
- `GET /metrics` - Prometheus metrics endpoint
- Historical metrics with configurable retention
- Custom metrics for TACACS+ and RADIUS operations
- System metrics (CPU, memory, connections)

### **API Features**
- **Search & filtering**: All list endpoints support advanced filtering
- **Pagination**: Configurable page sizes and offset-based pagination
- **Sorting**: Multi-field sorting with ascending/descending options
- **Field selection**: Choose specific fields to reduce response size
- **Error handling**: Consistent error responses with detailed messages
- **Rate limiting**: API rate limiting to prevent abuse

### **Prometheus Integration**

Add to your `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'tacacs-server'
    static_configs:
      - targets: ['127.0.0.1:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
    scrape_timeout: 10s
```

### **Available Metrics**

#### **TACACS+ Metrics**
- `tacacs_auth_requests_total{status, backend}` - Authentication requests
- `tacacs_auth_duration_seconds` - Authentication latency histogram
- `tacacs_active_connections` - Current active connections
- `tacacs_server_uptime_seconds` - Server uptime
- `tacacs_accounting_records_total{status}` - Accounting records

#### **RADIUS Metrics**
- `radius_auth_requests_total{status}` - RADIUS authentication requests
- `radius_acct_requests_total{type}` - RADIUS accounting requests
- `radius_active_clients` - Configured RADIUS clients

#### **System Metrics**
- `process_cpu_seconds_total` - CPU usage
- `process_resident_memory_bytes` - Memory usage
- `process_open_fds` - Open file descriptors

### **Grafana Dashboard Queries**

```promql
# Authentication Rate (requests/second)
rate(tacacs_auth_requests_total[5m])

# Success Rate Percentage
(rate(tacacs_auth_requests_total{status="success"}[5m]) / rate(tacacs_auth_requests_total[5m])) * 100

# Authentication Latency (95th percentile)
histogram_quantile(0.95, rate(tacacs_auth_duration_seconds_bucket[5m]))

# Active Connections
tacacs_active_connections

# Server Uptime (hours)
tacacs_server_uptime_seconds / 3600

# Error Rate
rate(tacacs_auth_requests_total{status="error"}[5m])

# Backend Performance
rate(tacacs_auth_requests_total[5m]) by (backend)

# RADIUS vs TACACS+ Usage
rate(tacacs_auth_requests_total[5m]) + rate(radius_auth_requests_total[5m])
```

## 📁 Project Architecture

```
tacacs_server/
├── auth/                    # Authentication backends
│   ├── base.py             # Abstract backend interface
│   ├── local.py            # Local SQLite authentication
│   ├── ldap_auth.py        # LDAP integration
│   ├── okta_auth.py        # Okta SSO integration
│   ├── local_store.py      # Local user database
│   ├── local_user_service.py      # User management service
│   └── local_user_group_service.py # User group management
├── tacacs/                  # TACACS+ protocol implementation
│   ├── server.py           # TACACS+ server core
│   ├── handlers.py         # AAA request handlers
│   ├── packet.py           # TACACS+ packet encoding/decoding
│   └── constants.py        # Protocol constants
├── radius/                  # RADIUS protocol implementation
│   ├── server.py           # RADIUS server core
│   └── constants.py        # RADIUS constants
├── devices/                 # Device management
│   ├── store.py            # Device database operations
│   └── service.py          # Device management service
├── accounting/              # Accounting and logging
│   ├── models.py           # Data models
│   ├── database.py         # Database operations
│   └── async_database.py   # High-performance async logging
├── config/                  # Configuration management
│   ├── config.py           # Configuration loader
│   └── schema.py           # Pydantic validation schemas
├── web/                     # Web interface and APIs
│   ├── monitoring.py       # Monitoring dashboard and APIs
│   └── admin/              # Admin interface
│       ├── auth.py         # Admin authentication
│       └── routers.py      # Admin API routes
├── utils/                   # Utility modules
│   ├── logger.py           # Structured logging
│   ├── metrics.py          # Metrics collection
│   ├── policy.py           # Authorization policies
│   ├── security.py         # Security utilities
│   ├── validation.py       # Input validation
│   ├── crypto.py           # Cryptographic functions
│   ├── rate_limiter.py     # Rate limiting
│   └── audit_logger.py     # Audit trail logging
├── static/                  # Web assets
│   └── css/                # Stylesheets
├── templates/               # HTML templates
│   ├── dashboard.html      # Main dashboard
│   └── admin/              # Admin interface templates
├── cli.py                   # Command-line interface
└── main.py                  # Application entry point

tests/                       # Test suite
├── conftest.py             # Test configuration
├── test_auth.py            # Authentication tests
├── test_server.py          # Server tests
├── test_radius.py          # RADIUS tests
├── test_api_*.py           # API tests
└── test_benchmark.py       # Performance tests

scripts/                     # Utility scripts
├── setup_project.py        # Project setup
├── validate_config.py      # Configuration validation
├── tacacs_client.py        # TACACS+ test client
├── radius_client.py        # RADIUS test client
└── example_credentials.csv # Test credentials

config/                      # Configuration files
└── tacacs.conf             # Main configuration

data/                        # Runtime data
├── local_auth.db           # Local user database
├── devices.db              # Device inventory
├── tacacs_accounting.db    # Accounting records
└── audit_trail.db          # Audit logs

logs/                        # Log files
└── tacacs.log              # Application logs
```

### **Key Files**

| File | Purpose |
|------|----------|
| `pyproject.toml` | Poetry configuration and package metadata |
| `docker-compose.yml` | Container orchestration configuration |
| `Dockerfile` | Container build configuration |
| `.github/workflows/` | CI/CD pipeline configuration |
| `mypy.ini` | Type checking configuration |
| `pytest.ini` | Test configuration |
| `.bandit` | Security scanning configuration |

### **Scripts & Tools**

| Script | Purpose |
|--------|----------|
| `scripts/setup_project.py` | Initialize project directories and test clients |
| `scripts/validate_config.py` | Pre-deployment configuration validation |
| `scripts/tacacs_client.py` | TACACS+ test client with batch testing |
| `scripts/radius_client.py` | RADIUS test client with batch testing |
| `scripts/example_credentials.csv` | Sample credentials for batch testing |
| `scripts/okta_check.py` | Okta integration testing tool |

## 🔧 Advanced Configuration

### **Configuration Loading Priority**
1. Command line `--config` parameter
2. `TACACS_CONFIG` environment variable
3. Default `config/tacacs.conf` file

### **Environment Variables**
- `TACACS_CONFIG` - Configuration file path or URL
- `ADMIN_USERNAME` - Admin console username
- `ADMIN_PASSWORD_HASH` - Admin console password hash
- `TACACS_DEFAULT_SECRET` - Fallback TACACS+ secret
- `RADIUS_DEFAULT_SECRET` - Fallback RADIUS secret

### **URL-based Configuration**
```bash
# Load from HTTPS URL (read-only)
export TACACS_CONFIG=https://config.example.com/tacacs.conf

# Load from file URL
export TACACS_CONFIG=file:///etc/tacacs/tacacs.conf
```

## 🧪 Testing & Validation

### **Running Tests**
```bash
# Run all tests
poetry run pytest -q

# Run with coverage
poetry run pytest --cov=tacacs_server --cov-report=html

# Run specific test categories
poetry run pytest tests/test_auth.py -v
poetry run pytest tests/test_api_*.py -v
poetry run pytest tests/test_benchmark.py -v

# Run performance benchmarks
poetry run pytest tests/test_benchmark.py --benchmark-only
```

### **Advanced Testing with Server Fixture**
The test suite includes advanced tests that require a running server. These tests use an automatic server fixture that:
- **Starts the server**: Automatically launches TACACS+ server before tests
- **Waits for readiness**: Ensures server is fully operational
- **Runs tests**: Executes tests against the live server
- **Stops server**: Cleanly shuts down server after tests complete

```bash
# Run advanced test suites (server auto-managed)
poetry run pytest tests/chaos/ -v          # Chaos engineering tests
poetry run pytest tests/security/ -v       # Security penetration tests
poetry run pytest tests/contract/ -v       # API contract tests
poetry run pytest tests/e2e/ -v            # End-to-end integration tests

# Run all advanced tests
poetry run python scripts/run_advanced_tests.py

# Run specific advanced test type
poetry run python scripts/run_advanced_tests.py --test-type chaos
poetry run python scripts/run_advanced_tests.py --test-type security

# List available advanced test types
poetry run python scripts/run_advanced_tests.py --list-tests
```

**Test Categories:**
- **Core Tests** (143 tests): Unit tests that don't require a running server
- **Chaos Tests**: Network resilience, resource exhaustion, cascade failures
- **Security Tests**: OWASP Top 10, penetration testing, vulnerability scanning
- **Contract Tests**: API schema validation, consumer-driven contracts
- **E2E Tests**: Complete user workflows, integration testing

### **Batch Testing**
```bash
# Test multiple TACACS+ credentials
python scripts/tacacs_client.py --batch scripts/example_credentials.csv

# Test multiple RADIUS credentials
python scripts/radius_client.py --batch scripts/example_credentials.csv

# Custom credential file format (CSV)
# username,password,expected_result
admin,admin123,success
user1,wrongpass,failure
```

### **Configuration Validation**
```bash
# Validate current configuration
python scripts/validate_config.py

# Validate specific configuration file
python scripts/validate_config.py /path/to/tacacs.conf

# Quiet mode (only show errors)
python scripts/validate_config.py --quiet
```

### **Integration Testing**
```bash
# Test Okta integration
python scripts/okta_check.py

# Test LDAP connectivity
python -c "from tacacs_server.auth.ldap_auth import LDAPAuthBackend; print('LDAP OK')"

# Test server fixture functionality
poetry run pytest tests/chaos/test_chaos.py::TestNetworkChaos::test_network_latency_resilience -v
```

### **Server Fixture Architecture**
The server fixture (`tacacs_server`) provides:
- **Session scope**: Server starts once per test session
- **Automatic lifecycle**: Start → Wait for ready → Provide to tests → Stop
- **Port availability**: Checks TACACS+ (49) and HTTP (8080) ports
- **Clean shutdown**: Graceful termination with SIGTERM/SIGKILL fallback
- **Error handling**: Robust error handling and timeout management

```python
# Using server fixture in tests
class TestMyFeature:
    @pytest.fixture(autouse=True)
    def setup_server(self, tacacs_server):
        """Use server fixture"""
        self.server_info = tacacs_server
    
    def test_my_feature(self):
        # Server is automatically running
        response = requests.get("http://localhost:8080/api/health")
        assert response.status_code == 200
```

## 🛠️ Development

### **Development Setup**
```bash
# Install development dependencies
poetry install --with dev

# Install pre-commit hooks
poetry run pre-commit install

# Run quality checks
poetry run ruff check .
poetry run ruff format .
poetry run mypy .
poetry run bandit -r . -x tests
```

### **Code Quality**
- **Linting**: Ruff for fast Python linting
- **Formatting**: Ruff for consistent code formatting
- **Type checking**: mypy for static type analysis
- **Security**: Bandit for security vulnerability scanning
- **Testing**: pytest with comprehensive test coverage

### **Architecture Principles**
- **Separation of concerns**: Clear module boundaries
- **Dependency injection**: Services injected via constructors
- **Type safety**: Full type annotations with mypy checking
- **Security first**: Input validation, SQL injection prevention
- **Observability**: Comprehensive logging and metrics
- **Testability**: Dependency injection enables easy testing

### **Security Guidelines**
- **No global secrets**: All secrets are per-device group
- **Input validation**: Pydantic schemas for all inputs
- **SQL safety**: Parameterized queries only
- **Session security**: Secure session management
- **Audit logging**: Complete audit trail
- **Rate limiting**: Protection against abuse

### **Integration Best Practices**
- **Okta**: Use Authorization Code + PKCE or API tokens
- **LDAP**: Prefer TLS connections and service accounts
- **Secrets**: Environment variables or external secret stores
- **Configuration**: Validate before deployment
- **Monitoring**: Prometheus metrics for observability

## 🤝 Contributing

### **Development Workflow**
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes with tests
4. Run quality checks: `poetry run ruff check . && poetry run mypy .`
5. Run tests: `poetry run pytest`
6. Commit with conventional commits: `git commit -m "feat: add amazing feature"`
7. Push and create a pull request

### **Code Standards**
- Follow PEP 8 style guidelines
- Add type annotations for all functions
- Write tests for new functionality
- Update documentation for user-facing changes
- Use conventional commit messages

### **Pull Request Requirements**
- All tests must pass
- Code coverage should not decrease
- Security scans must pass
- Documentation must be updated
- Changes must be backwards compatible

## 📚 Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[API Reference](docs/API_REFERENCE.md)** - Complete REST API documentation
- **[Configuration Guide](docs/CONFIGURATION.md)** - Detailed configuration options
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions
- **[Integration Guide](docs/INTEGRATIONS.md)** - LDAP, Okta, and other integrations
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

## 🐳 Docker Deployment

```bash
# Build and run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f tacacs-server

# Scale for high availability
docker-compose up -d --scale tacacs-server=3
```

## 📈 Performance

- **Concurrent connections**: 1000+ simultaneous connections
- **Authentication rate**: 10,000+ authentications/second
- **Memory usage**: <100MB typical, <500MB under load
- **Startup time**: <5 seconds
- **Response time**: <10ms average authentication latency

## 🔒 Security

- **CVE scanning**: Automated vulnerability scanning
- **Dependency updates**: Regular security updates
- **Input validation**: Comprehensive input sanitization
- **Audit logging**: Complete audit trail
- **Rate limiting**: DDoS protection
- **Secure defaults**: Security-first configuration

## 🚀 What's New

### **Recent Features**
- ✅ Per-device group secrets (no more global secrets)
- ✅ Real-time WebSocket dashboard updates
- ✅ Comprehensive API with search and filtering
- ✅ RADIUS server with shared authentication backends
- ✅ Advanced device and user group management
- ✅ Prometheus metrics with Grafana integration
- ✅ Docker containerization with docker-compose
- ✅ Comprehensive test suite with 130+ tests
- ✅ Type safety with full mypy coverage
- ✅ Security scanning with bandit and semgrep

### **Coming Soon**
- 🔄 High availability clustering
- 🔄 Advanced reporting and analytics
- 🔄 SAML/OAuth2 integration
- 🔄 REST API for device provisioning
- 🔄 Mobile-responsive admin interface

## 📄 License

MIT License with Attribution Requirement

All forks, copies, or deployments must retain the upstream attribution notice and link back to the original repository: https://github.com/SaschaSchwarzK/tacacs_server

See the [LICENSE](LICENSE) file for full terms.

## 🙏 Acknowledgments

- Built with modern Python and FastAPI
- Inspired by enterprise network management needs
- Community contributions and feedback
- Open source security and networking tools

---

**Enterprise Support**: For enterprise support, custom integrations, or professional services, please contact the maintainers.

**Community**: Join our community for discussions, questions, and contributions.