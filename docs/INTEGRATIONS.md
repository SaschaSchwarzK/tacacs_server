# Integration Guide

This guide covers integrating the TACACS+ server with various authentication backends, monitoring systems, and network infrastructure.

## Authentication Backend Integrations

### LDAP Integration

#### Active Directory Integration

```ini
[ldap]
server = ldap://ad.company.com:389
base_dn = ou=Users,dc=company,dc=com
user_attribute = sAMAccountName
bind_dn = cn=tacacs-service,ou=Service Accounts,dc=company,dc=com
bind_password = "change-me"  # overridden by LDAP_BIND_PASSWORD if set
use_tls = true
timeout = 10
group_attribute = memberOf
```

**Setup Steps:**

1. Create service account in Active Directory
2. Grant read permissions to user objects
3. Configure LDAP over SSL (recommended)
4. Test connectivity

```bash
# Test LDAP connectivity
ldapsearch -H ldap://ad.company.com:389 \
  -D "cn=tacacs-service,ou=Service Accounts,dc=company,dc=com" \
  -w "password" \
  -b "ou=Users,dc=company,dc=com" \
  "(sAMAccountName=testuser)"
```

#### OpenLDAP Integration

```ini
[ldap]
server = ldap://openldap.company.com:389
base_dn = ou=people,dc=company,dc=com
user_attribute = uid
bind_dn = cn=admin,dc=company,dc=com
bind_password = "change-me"  # overridden by LDAP_BIND_PASSWORD if set
use_tls = true
group_attribute = memberOf
```

### Okta Integration

The server integrates with Okta using the Authentication API (AuthN) for user authentication. Group membership is fetched from the Management API and evaluated by the central AAA layer to enforce device-scoped policies.

For a complete guide on Okta integration, including MFA setup, the device-scoped authorization flow, and troubleshooting, please see the detailed [Okta Integration Guide](OKTA.md).

#### Complete Okta Configuration Example

```ini
[okta]
# Your Okta organization URL
org_url = https://company.okta.com

# Okta Management API OAuth credentials (choose one auth_method)
# auth_method = client_secret
# client_id = ${OKTA_CLIENT_ID}
# client_secret = ${OKTA_CLIENT_SECRET}
# auth_method = private_key_jwt
# client_id = ${OKTA_CLIENT_ID}
# private_key = /path/to/private_key.pem
# private_key_id = <kid>

# TLS verification (default true)
verify_tls = true

# Optional: Require membership in at least one Okta group for authentication to succeed
require_group_for_auth = false

# Connection and pooling options
request_timeout = 10
connect_timeout = 3
read_timeout = 10
pool_maxsize = 50
max_retries = 2
backoff_factor = 0.3
trust_env = false

# Group cache controls
group_cache_ttl = 1800
group_cache_maxsize = 50000
group_cache_fail_ttl = 60

# Flow controls
authn_enabled = true
strict_group_mode = false

# Circuit breaker for Okta outages
circuit_failures = 5
circuit_cooldown = 30
```

#### Basic Configuration

1.  Create an OAuth service app in Okta (client_credentials) using either `client_secret` or `private_key_jwt`.
2.  Add `okta` to the `backends` list in the `[auth]` section of your configuration.
3.  Configure the `[okta]` section with your organization's details.

```ini
[okta]
# Your Okta organization URL
org_url = https://company.okta.com
# Choose one auth_method: client_secret or private_key_jwt
auth_method = client_secret
client_id = ${OKTA_CLIENT_ID}
client_secret = ${OKTA_CLIENT_SECRET}
# auth_method = private_key_jwt
# client_id = ${OKTA_CLIENT_ID}
# private_key = /path/to/private_key.pem
# private_key_id = <kid>
# Optional: Require membership in at least one Okta group for authentication to succeed.
# Device- and backend-specific group allow-lists are enforced in AAAHandlers based on
# local user groups linked via okta_group / ldap_group / radius_group.
require_group_for_auth = false
```

**Note:** Unlike other backends, privilege levels are not directly mapped from Okta groups. Instead, privilege is determined by the server's policy engine based on the user's membership in local user groups, which can be linked to Okta groups. See `OKTA.md` for a detailed explanation.

## Network Device Integration

## Load Balancers & Proxy Protocol

This server supports HAProxy PROXY protocol v2 (TCP) for extracting the original client IP when connections are forwarded by a proxy/load balancer.

### Behavior

- On connection accept, the server detects and consumes a PROXY v2 header if present.
- If the header is present and valid, the server sets:
  - `client_ip` to the original source (from the header)
  - `proxy_ip` to the immediate peer (the load balancer IP)
- If no header is present, `client_ip` is the TCP peer address and `proxy_ip` is `None`.

### Proxy-aware device selection

Device matching uses a two-stage policy:

1. Exact: `client_ip ∈ device.network` AND `proxy_ip ∈ group.proxy_network` (longest prefix wins)
2. Fallback: `client_ip ∈ device.network` AND `group.proxy_network` is NULL (longest prefix wins)

This allows tenant isolation (devices match only through their proxy) while preserving backward compatibility for direct connections.

### Configuration

- Configure device groups with a `proxy_network` (CIDR) to require a specific proxy path.
- Direct-only groups omit `proxy_network`.

### Notes

- PROXY v2 is a TCP feature; RADIUS (UDP) is not affected.
- Metrics:
  - JSON `/api/stats` includes `connections.proxied` and `connections.direct`.
  - Prometheus exports `tacacs_connections_proxied_total` and `tacacs_connections_direct_total`.

### Cisco IOS/IOS-XE

```
! Basic TACACS+ configuration
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
aaa accounting commands 15 default start-stop group tacacs+

! TACACS+ server configuration
tacacs server TACACS-SERVER-1
 address ipv4 10.0.1.10
 key 7 <encrypted-key>
 timeout 5
 single-connection

tacacs server TACACS-SERVER-2
 address ipv4 10.0.1.11
 key 7 <encrypted-key>
 timeout 5
 single-connection

! Server group
aaa group server tacacs+ TACACS-SERVERS
 server name TACACS-SERVER-1
 server name TACACS-SERVER-2
 ip tacacs source-interface Loopback0
```

### Cisco Nexus

```
! Enable TACACS+
feature tacacs+

! Configure TACACS+ servers
tacacs-server host 10.0.1.10 key 7 <encrypted-key> timeout 5
tacacs-server host 10.0.1.11 key 7 <encrypted-key> timeout 5

! Configure AAA
aaa group server tacacs+ TACACS-SERVERS
  server 10.0.1.10
  server 10.0.1.11
  use-vrf management
  source-interface mgmt0

aaa authentication login default group TACACS-SERVERS local
aaa authorization config-commands default group TACACS-SERVERS local
aaa authorization commands default group TACACS-SERVERS local
aaa accounting default group TACACS-SERVERS
```

### Juniper JunOS

```
# TACACS+ configuration
set system tacplus-server 10.0.1.10 secret "$9$encrypted-key"
set system tacplus-server 10.0.1.10 timeout 5
set system tacplus-server 10.0.1.10 single-connection
set system tacplus-server 10.0.1.11 secret "$9$encrypted-key"
set system tacplus-server 10.0.1.11 timeout 5
set system tacplus-server 10.0.1.11 single-connection

# Authentication order
set system authentication-order tacplus
set system authentication-order password

# Authorization
set system login class network-admin permissions all
set system login class network-operator permissions [ clear network reset trace view ]
```

### Arista EOS

```
! TACACS+ configuration
tacacs-server host 10.0.1.10 key 7 <encrypted-key>
tacacs-server host 10.0.1.11 key 7 <encrypted-key>

! AAA configuration
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
aaa accounting exec default start-stop group tacacs+
aaa accounting commands all default start-stop group tacacs+

! Source interface
ip tacacs source-interface Management1
```

## RADIUS Integration

### Network Access Server (NAS) Configuration

#### Cisco WLC (Wireless LAN Controller)

```
# RADIUS server configuration
config radius auth add 1 10.0.1.10 1812 ascii "radius-secret"
config radius auth add 2 10.0.1.11 1812 ascii "radius-secret"

# RADIUS accounting
config radius acct add 1 10.0.1.10 1813 ascii "radius-secret"
config radius acct add 2 10.0.1.11 1813 ascii "radius-secret"

# Enable RADIUS authentication
config radius auth enable 1
config radius auth enable 2
config radius acct enable 1
config radius acct enable 2
```

#### pfSense

1. Navigate to System > User Manager > Authentication Servers
2. Add new RADIUS server:
   - Hostname: 10.0.1.10
   - Port: 1812
   - Shared Secret: radius-secret
   - Authentication Timeout: 5

#### Ubiquiti UniFi

```json
{
  "radius_profile": {
    "name": "Corporate-RADIUS",
    "auth_servers": [
      {
        "ip": "10.0.1.10",
        "port": 1812,
        "x_secret": "radius-secret"
      },
      {
        "ip": "10.0.1.11",
        "port": 1812,
        "x_secret": "radius-secret"
      }
    ],
    "acct_servers": [
      {
        "ip": "10.0.1.10",
        "port": 1813,
        "x_secret": "radius-secret"
      }
    ]
  }
}
```

## Monitoring System Integration

### Prometheus Integration

#### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'tacacs-server'
    static_configs:
      - targets: ['tacacs-server-1:8080', 'tacacs-server-2:8080', 'tacacs-server-3:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
    scrape_timeout: 10s
    
  - job_name: 'tacacs-server-health'
    static_configs:
      - targets: ['tacacs-server-1:8080', 'tacacs-server-2:8080', 'tacacs-server-3:8080']
    metrics_path: '/api/health'
    scrape_interval: 30s
```

#### Alert Rules

```yaml
# tacacs_alerts.yml
groups:
  - name: tacacs_server
    rules:
      - alert: TacacsServerDown
        expr: up{job="tacacs-server"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "TACACS+ server is down"
          description: "TACACS+ server {{ $labels.instance }} has been down for more than 1 minute"
          
      - alert: TacacsHighAuthFailureRate
        expr: rate(tacacs_auth_requests_total{status="failure"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High TACACS+ authentication failure rate"
          description: "TACACS+ server {{ $labels.instance }} has high authentication failure rate: {{ $value }} failures/sec"
          
      - alert: TacacsHighLatency
        expr: histogram_quantile(0.95, rate(tacacs_auth_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High TACACS+ authentication latency"
          description: "95th percentile latency is {{ $value }}s on {{ $labels.instance }}"
```

### Grafana Integration

#### Dashboard Configuration

```json
{
  "dashboard": {
    "title": "TACACS+ Server Dashboard",
    "tags": ["tacacs", "aaa", "networking"],
    "panels": [
      {
        "title": "Authentication Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(tacacs_auth_requests_total[5m])",
            "legendFormat": "{{ instance }} - {{ status }}"
          }
        ],
        "yAxes": [
          {
            "label": "Requests/sec"
          }
        ]
      },
      {
        "title": "Success Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "(sum(rate(tacacs_auth_requests_total{status=\"success\"}[5m])) / sum(rate(tacacs_auth_requests_total[5m]))) * 100",
            "legendFormat": "Success Rate"
          }
        ],
        "valueName": "current",
        "format": "percent",
        "thresholds": "80,95"
      }
    ]
  }
}
```

### Splunk Integration

#### Log Forwarding

```ini
# /opt/splunkforwarder/etc/system/local/inputs.conf
[monitor:///opt/tacacs_server/logs/tacacs.log]
disabled = false
index = network_security
sourcetype = tacacs_log
host = tacacs-server-1

[monitor:///opt/tacacs_server/data/audit_trail.db]
disabled = false
index = audit
sourcetype = tacacs_audit
```

#### Search Queries

```spl
# Authentication failures by user
index=network_security sourcetype=tacacs_log status=failure
| stats count by username
| sort -count

# Top authenticating devices
index=network_security sourcetype=tacacs_log
| stats count by client_ip
| sort -count
| head 10

# Authentication timeline
index=network_security sourcetype=tacacs_log
| timechart span=1h count by status
```

## SIEM Integration

### Elastic Stack (ELK)

#### Logstash Configuration

```ruby
# /etc/logstash/conf.d/tacacs.conf
input {
  file {
    path => "/opt/tacacs_server/logs/tacacs.log"
    start_position => "beginning"
    codec => "json"
    tags => ["tacacs"]
  }
}

filter {
  if "tacacs" in [tags] {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    if [message] =~ /authentication/ {
      mutate {
        add_tag => ["authentication"]
      }
    }
    
    if [message] =~ /authorization/ {
      mutate {
        add_tag => ["authorization"]
      }
    }
  }
}

output {
  if "tacacs" in [tags] {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "tacacs-%{+YYYY.MM.dd}"
    }
  }
}
```

#### Kibana Dashboards

```json
{
  "version": "7.10.0",
  "objects": [
    {
      "id": "tacacs-auth-timeline",
      "type": "visualization",
      "attributes": {
        "title": "TACACS+ Authentication Timeline",
        "visState": {
          "type": "histogram",
          "params": {
            "grid": {"categoryLines": false, "style": {"color": "#eee"}},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": true, "style": {}, "scale": {"type": "linear"}, "labels": {"show": true, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": true, "style": {}, "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": true, "rotate": 0, "filter": false, "truncate": 100}, "title": {"text": "Count"}}]
          }
        }
      }
    }
  ]
}
```

## Network Management Integration

### LibreNMS Integration

#### SNMP Configuration

```ini
# /opt/tacacs_server/config/snmp.conf
[snmp]
enabled = true
community = public
port = 161
location = "Data Center 1"
contact = "network-team@company.com"
```

#### Custom OIDs

```
# TACACS+ Server MIB
.1.3.6.1.4.1.12345.1.1.1 - tacacsAuthRequests
.1.3.6.1.4.1.12345.1.1.2 - tacacsAuthSuccesses
.1.3.6.1.4.1.12345.1.1.3 - tacacsAuthFailures
.1.3.6.1.4.1.12345.1.2.1 - tacacsActiveConnections
.1.3.6.1.4.1.12345.1.3.1 - tacacsServerUptime
```

### Nagios Integration

#### Check Script

```bash
#!/bin/bash
# /usr/local/nagios/libexec/check_tacacs_server

HOST=$1
PORT=${2:-8080}
WARNING=${3:-90}
CRITICAL=${4:-95}

# Check health endpoint
RESPONSE=$(curl -s -w "%{http_code}" "http://$HOST:$PORT/api/health")
HTTP_CODE=${RESPONSE: -3}
BODY=${RESPONSE%???}

if [ "$HTTP_CODE" != "200" ]; then
    echo "CRITICAL - TACACS+ server health check failed (HTTP $HTTP_CODE)"
    exit 2
fi

# Parse response for success rate
SUCCESS_RATE=$(echo "$BODY" | jq -r '.auth_success_rate // 0')

if (( $(echo "$SUCCESS_RATE < $CRITICAL" | bc -l) )); then
    echo "CRITICAL - Authentication success rate: ${SUCCESS_RATE}%"
    exit 2
elif (( $(echo "$SUCCESS_RATE < $WARNING" | bc -l) )); then
    echo "WARNING - Authentication success rate: ${SUCCESS_RATE}%"
    exit 1
else
    echo "OK - Authentication success rate: ${SUCCESS_RATE}%"
    exit 0
fi
```

## Configuration Management Integration

### Ansible Integration

#### Playbook Example

```yaml
# tacacs_server.yml
---
- name: Deploy TACACS+ Server
  hosts: tacacs_servers
  become: yes
  vars:
    tacacs_version: "latest"
    tacacs_config:
      server:
        host: "0.0.0.0"
        port: 49
        log_level: "INFO"
      auth:
        backends: "ldap,local"
        local_auth_db: "data/local_auth.db"
      ldap:
        server: "{{ ldap_server }}"
        base_dn: "{{ ldap_base_dn }}"
        bind_dn: "{{ ldap_bind_dn }}"
        bind_password: "{{ ldap_bind_password }}"

  tasks:
    - name: Create tacacs user
      user:
        name: tacacs
        system: yes
        shell: /bin/false
        home: /opt/tacacs_server

    - name: Install dependencies
      package:
        name:
          - python3.13
          - python3-pip
          - git
        state: present

    - name: Clone repository
      git:
        repo: https://github.com/SaschaSchwarzK/tacacs_server.git
        dest: /opt/tacacs_server
        version: "{{ tacacs_version }}"
      become_user: tacacs

    - name: Install Python dependencies
      pip:
        requirements: /opt/tacacs_server/requirements.txt
        virtualenv: /opt/tacacs_server/.venv
        virtualenv_python: python3.13
      become_user: tacacs

    - name: Generate configuration
      template:
        src: tacacs.conf.j2
        dest: /opt/tacacs_server/config/tacacs.conf
        owner: tacacs
        group: tacacs
        mode: '0640'
      notify: restart tacacs

    - name: Install systemd service
      template:
        src: tacacs-server.service.j2
        dest: /etc/systemd/system/tacacs-server.service
      notify:
        - reload systemd
        - restart tacacs

    - name: Start and enable service
      systemd:
        name: tacacs-server
        state: started
        enabled: yes

  handlers:
    - name: reload systemd
      systemd:
        daemon_reload: yes

    - name: restart tacacs
      systemd:
        name: tacacs-server
        state: restarted
```

### Terraform Integration

```hcl
# main.tf
resource "aws_instance" "tacacs_server" {
  count                  = var.instance_count
  ami                    = var.ami_id
  instance_type         = var.instance_type
  key_name              = var.key_name
  vpc_security_group_ids = [aws_security_group.tacacs.id]
  subnet_id             = var.subnet_ids[count.index]

  user_data = templatefile("${path.module}/user_data.sh", {
    ldap_server      = var.ldap_server
    ldap_bind_dn     = var.ldap_bind_dn
    ldap_bind_password = var.ldap_bind_password
  })

  tags = {
    Name = "tacacs-server-${count.index + 1}"
    Role = "tacacs-server"
  }
}

resource "aws_security_group" "tacacs" {
  name_prefix = "tacacs-server-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 49
    to_port     = 49
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }

  ingress {
    from_port   = 1812
    to_port     = 1813
    protocol    = "udp"
    cidr_blocks = var.allowed_cidrs
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.management_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lb" "tacacs" {
  name               = "tacacs-server-lb"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.subnet_ids

  enable_deletion_protection = false
}

resource "aws_lb_target_group" "tacacs" {
  name     = "tacacs-server-tg"
  port     = 49
  protocol = "TCP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/api/health"
    port                = "8080"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }
}
```

## API Integration Examples

### Python Client

```python
import requests
import json

class TacacsServerClient:
    def __init__(self, base_url, username=None, password=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if username and password:
            self.login(username, password)
    
    def login(self, username, password):
        """Authenticate with the TACACS+ server admin interface"""
        response = self.session.post(
            f"{self.base_url}/api/admin/login",
            json={"username": username, "password": password}
        )
        response.raise_for_status()
        return response.json()
    
    def get_status(self):
        """Get server status"""
        response = self.session.get(f"{self.base_url}/api/status")
        response.raise_for_status()
        return response.json()
    
    def get_devices(self, search=None, group=None):
        """Get device list with optional filtering"""
        params = {}
        if search:
            params['search'] = search
        if group:
            params['group'] = group
        
        response = self.session.get(f"{self.base_url}/api/devices", params=params)
        response.raise_for_status()
        return response.json()
    
    def create_device(self, name, network, group=None):
        """Create a new device"""
        data = {"name": name, "network": network}
        if group:
            data["group"] = group
        
        response = self.session.post(f"{self.base_url}/api/devices", json=data)
        response.raise_for_status()
        return response.json()

# Usage example
client = TacacsServerClient("http://tacacs-server:8080", "admin", "password")
status = client.get_status()
print(f"Server status: {status['status']}")

devices = client.get_devices(group="routers")
print(f"Found {len(devices)} router devices")
```

### PowerShell Client

```powershell
# TacacsServer.psm1
class TacacsServerClient {
    [string]$BaseUrl
    [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    
    TacacsServerClient([string]$BaseUrl) {
        $this.BaseUrl = $BaseUrl.TrimEnd('/')
        $this.Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    }
    
    [hashtable] Login([string]$Username, [string]$Password) {
        $body = @{
            username = $Username
            password = $Password
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$($this.BaseUrl)/api/admin/login" `
            -Method Post -Body $body -ContentType "application/json" `
            -WebSession $this.Session
        
        return $response
    }
    
    [hashtable] GetStatus() {
        $response = Invoke-RestMethod -Uri "$($this.BaseUrl)/api/status" `
            -Method Get -WebSession $this.Session
        return $response
    }
    
    [array] GetDevices([string]$Search, [string]$Group) {
        $params = @{}
        if ($Search) { $params.search = $Search }
        if ($Group) { $params.group = $Group }
        
        $uri = "$($this.BaseUrl)/api/devices"
        if ($params.Count -gt 0) {
            $queryString = ($params.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"
            $uri += "?$queryString"
        }
        
        $response = Invoke-RestMethod -Uri $uri -Method Get -WebSession $this.Session
        return $response
    }
}

# Usage
$client = [TacacsServerClient]::new("http://tacacs-server:8080")
$client.Login("admin", "password")
$status = $client.GetStatus()
Write-Host "Server status: $($status.status)"
```

## Troubleshooting Integration Issues

### Common LDAP Issues

1. **Connection timeouts**
   ```bash
   # Test LDAP connectivity
   ldapsearch -H ldap://ldap.company.com:389 -x -b "" -s base
   ```

2. **Authentication failures**
   ```bash
   # Test bind credentials
   ldapsearch -H ldap://ldap.company.com:389 \
     -D "cn=service,dc=company,dc=com" -w "password" \
     -b "dc=company,dc=com" "(objectClass=*)" dn
   ```

3. **Group membership issues**
   ```bash
   # Check user group membership
   ldapsearch -H ldap://ldap.company.com:389 \
     -D "cn=service,dc=company,dc=com" -w "password" \
     -b "ou=users,dc=company,dc=com" \
     "(sAMAccountName=testuser)" memberOf
   ```

### Network Device Integration Issues

1. **Shared secret mismatch**
   - Verify secrets match between device and server
   - Check for special characters in secrets
   - Ensure proper encoding

2. **Network connectivity**
   ```bash
   # Test TACACS+ port connectivity
   telnet tacacs-server 49
   
   # Test from device
   test aaa group tacacs+ username password new-code
   ```

3. **Authorization failures**
   - Check user group mappings
   - Verify privilege levels
   - Review authorization policies

### Monitoring Integration Issues

1. **Metrics not appearing**
   - Check Prometheus scrape configuration
   - Verify metrics endpoint accessibility
   - Review firewall rules

2. **Alert not firing**
   - Validate alert rule syntax
   - Check alert evaluation intervals
   - Verify notification channels

This integration guide provides comprehensive examples for connecting the TACACS+ server with various systems and platforms. Each integration includes configuration examples, troubleshooting tips, and best practices for production deployments.
