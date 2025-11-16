# Deployment Guide

This guide covers deploying the TACACS+ server in various environments, from development to enterprise production deployments.

## Deployment Overview

```mermaid
graph TD
    subgraph Local
        L1[Poetry dev server<br/>python -m tacacs_server.main]
    end

    subgraph Containers
        D1[Docker single container]
        D2[Docker Compose<br/>+ Prometheus/Grafana]
        K1[Kubernetes Deployment<br/>(config via ConfigMap/Secret)]
        A1[Azure ACI HTTPS image<br/>Key Vault + Storage]
    end

    L1 --> D1
    D1 --> D2
    D2 --> K1
    K1 --> A1
```

Use this file as the top‑level deployment guide. HTTPS/ACI specifics are covered in detail in:
- `DEPLOYMENT-GUIDE-HTTPS.md` – Azure ACI + Key Vault + Storage
- `HTTPS-README.md` / `HTTPS-QUICK-REFERENCE.md` – HTTPS/TLS behavior and quick commands

## Quick Deployment

### Development Environment

```bash
# Clone and setup
git clone https://github.com/SaschaSchwarzK/tacacs_server.git
cd tacacs_server
poetry install
python scripts/setup_project.py --project-root "$(pwd)"

# Start development server
poetry run python -m tacacs_server.main
```

### Production Environment

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install python3.13 python3.13-venv python3-pip

# Create service user
sudo useradd -r -s /bin/false tacacs
sudo mkdir -p /opt/tacacs_server
sudo chown tacacs:tacacs /opt/tacacs_server

# Install application
cd /opt/tacacs_server
sudo -u tacacs git clone https://github.com/SaschaSchwarzK/tacacs_server.git .
sudo -u tacacs python3.13 -m pip install poetry
sudo -u tacacs poetry install --only=main
sudo -u tacacs python scripts/setup_project.py --project-root /opt/tacacs_server
```

## Docker Deployment

### Single Container

```bash
# Build image
docker build -t tacacs-server .

# Run container
docker run -d \
  --name tacacs-server \
  -p 49:49 \
  -p 1812:1812/udp \
  -p 1813:1813/udp \
  -p 8080:8080 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  tacacs-server
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  tacacs-server:
    build: .
    ports:
      - "49:49"           # TACACS+
      - "1812:1812/udp"   # RADIUS Auth
      - "1813:1813/udp"   # RADIUS Acct
      - "8080:8080"       # Web Interface
    volumes:
      - ./config:/app/config
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - TACACS_CONFIG=/app/config/tacacs.conf
      - ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}
      # Backup encryption
      - BACKUP_ENCRYPTION_PASSPHRASE=${BACKUP_ENCRYPTION_PASSPHRASE}
      # Destination credentials (optional; prefer secret managers)
      - FTP_PASSWORD=${FTP_PASSWORD}
      - SSH_KEY_PASSPHRASE=${SSH_KEY_PASSPHRASE}
      # Azure auth choices (pick one):
      - AZURE_CONNECTION_STRING=${AZURE_CONNECTION_STRING}
      - AZURE_ACCOUNT_KEY=${AZURE_ACCOUNT_KEY}
      # Optional runtime tuning
      - TACACS_LISTEN_BACKLOG=512
      - TACACS_CLIENT_TIMEOUT=15
      - TACACS_MAX_PACKET_LENGTH=4096
      - TACACS_IPV6_ENABLED=false
      - TACACS_TCP_KEEPALIVE=true
      - TACACS_TCP_KEEPIDLE=60
      - TACACS_TCP_KEEPINTVL=10
      - TACACS_TCP_KEEPCNT=5
      - TACACS_DB_POOL_SIZE=10
      # RADIUS tuning
      - RADIUS_WORKERS=16
      - RADIUS_SOCKET_TIMEOUT=1.0
      - RADIUS_SO_RCVBUF=2097152
      - TACACS_USE_THREAD_POOL=true
      - TACACS_THREAD_POOL_MAX=200
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-storage:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources

volumes:
  grafana-storage:
```

```bash
# Deploy with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f tacacs-server
```

## Kubernetes Deployment

### Basic Deployment

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tacacs-server
---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: tacacs-config
  namespace: tacacs-server
data:
  tacacs.conf: |
    [server]
    host = 0.0.0.0
    port = 49
    log_level = INFO
    
    [auth]
    backends = local
    local_auth_db = data/local_auth.db
    
    [admin]
    username = admin
    password_hash = ${ADMIN_PASSWORD_HASH}
    
    [monitoring]
    enabled = true
    web_host = 0.0.0.0
    web_port = 8080
---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: tacacs-secrets
  namespace: tacacs-server
type: Opaque
data:
  admin-password-hash: <base64-encoded-hash>
---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tacacs-server
  namespace: tacacs-server
spec:
  replicas: 2
  selector:
    matchLabels:
      app: tacacs-server
  template:
    metadata:
      labels:
        app: tacacs-server
    spec:
      containers:
      - name: tacacs-server
        image: tacacs-server:latest
        ports:
        - containerPort: 49
          name: tacacs
        - containerPort: 1812
          name: radius-auth
          protocol: UDP
        - containerPort: 1813
          name: radius-acct
          protocol: UDP
        - containerPort: 8080
          name: web
        env:
        - name: ADMIN_PASSWORD_HASH
          valueFrom:
            secretKeyRef:
              name: tacacs-secrets
              key: admin-password-hash
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: data
          mountPath: /app/data
        livenessProbe:
          httpGet:
            path: /api/health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /api/health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: tacacs-config
      - name: data
        persistentVolumeClaim:
          claimName: tacacs-data
---
# k8s/pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: tacacs-data
  namespace: tacacs-server
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: tacacs-server
  namespace: tacacs-server
spec:
  selector:
    app: tacacs-server
  ports:
  - name: tacacs
    port: 49
    targetPort: 49
  - name: radius-auth
    port: 1812
    targetPort: 1812
    protocol: UDP
  - name: radius-acct
    port: 1813
    targetPort: 1813
    protocol: UDP
  - name: web
    port: 8080
    targetPort: 8080
  type: LoadBalancer
```

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n tacacs-server
kubectl get services -n tacacs-server

# View logs
kubectl logs -f deployment/tacacs-server -n tacacs-server
```

## Systemd Service

### Service Configuration

```ini
# /etc/systemd/system/tacacs-server.service
[Unit]
Description=TACACS+ Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=tacacs
Group=tacacs
WorkingDirectory=/opt/tacacs_server
Environment=PATH=/opt/tacacs_server/.venv/bin
Environment=TACACS_LISTEN_BACKLOG=512
Environment=TACACS_CLIENT_TIMEOUT=15
Environment=TACACS_MAX_PACKET_LENGTH=4096
Environment=TACACS_IPV6_ENABLED=false
Environment=TACACS_TCP_KEEPALIVE=true
Environment=TACACS_USE_THREAD_POOL=true
Environment=TACACS_THREAD_POOL_MAX=200
Environment=RADIUS_WORKERS=16
Environment=RADIUS_SOCKET_TIMEOUT=1.0
Environment=RADIUS_SO_RCVBUF=2097152
ExecStart=/opt/tacacs_server/.venv/bin/python -m tacacs_server.main --config /opt/tacacs_server/config/tacacs.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tacacs-server

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/tacacs_server/data /opt/tacacs_server/logs
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
# Install and start service
sudo systemctl daemon-reload
sudo systemctl enable tacacs-server
sudo systemctl start tacacs-server

# Check status
sudo systemctl status tacacs-server

# View logs
sudo journalctl -u tacacs-server -f
```

## Example Load Balancer Configuration

> The server does **not** implement clustering or high availability.  
> The following examples show how to route traffic through a proxy; they do not add state replication.

### HAProxy Configuration

```
# /etc/haproxy/haproxy.cfg
global
    daemon
    maxconn 4096

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

# TACACS+ Load Balancing
frontend tacacs_frontend
    bind *:49
    default_backend tacacs_servers

backend tacacs_servers
    balance roundrobin
    server tacacs1 10.0.1.10:49 check
    server tacacs2 10.0.1.11:49 check
    server tacacs3 10.0.1.12:49 check

# RADIUS Authentication Load Balancing
frontend radius_auth_frontend
    bind *:1812
    mode udp
    default_backend radius_auth_servers

backend radius_auth_servers
    mode udp
    balance roundrobin
    server radius1 10.0.1.10:1812 check
    server radius2 10.0.1.11:1812 check
    server radius3 10.0.1.12:1812 check

# Web Interface Load Balancing
frontend web_frontend
    bind *:8080
    mode http
    option forwardfor
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    default_backend web_servers

backend web_servers
    mode http
    balance roundrobin
    option httpchk GET /ready
    timeout http-keep-alive 60s
    timeout tunnel 1h
    server web1 10.0.1.10:8080 check
    server web2 10.0.1.11:8080 check
    server web3 10.0.1.12:8080 check
```

### NGINX Configuration

```nginx
# /etc/nginx/sites-available/tacacs-server
upstream tacacs_backend {
    server 10.0.1.10:49;
    server 10.0.1.11:49;
    server 10.0.1.12:49;
}

upstream web_backend {
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
}

# TACACS+ TCP Proxy
server {
    listen 49;
    proxy_pass tacacs_backend;
    proxy_timeout 1s;
    proxy_responses 1;
}

# Web Interface
server {
    listen 80;
    server_name tacacs.company.com;
    
    location / {
        proxy_pass http://web_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # WebSocket support
    location /ws/ {
        proxy_pass http://web_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### Shared Storage Configuration

#### NFS Shared Storage

```bash
# NFS Server setup
sudo apt-get install nfs-kernel-server
sudo mkdir -p /srv/nfs/tacacs/{data,logs,config}
sudo chown -R tacacs:tacacs /srv/nfs/tacacs

# /etc/exports
/srv/nfs/tacacs 10.0.1.0/24(rw,sync,no_subtree_check,no_root_squash)

sudo systemctl restart nfs-kernel-server

# NFS Client setup (on each TACACS+ server)
sudo apt-get install nfs-common
sudo mkdir -p /opt/tacacs_server/{data,logs,config}
sudo mount -t nfs nfs-server:/srv/nfs/tacacs/data /opt/tacacs_server/data
sudo mount -t nfs nfs-server:/srv/nfs/tacacs/logs /opt/tacacs_server/logs
sudo mount -t nfs nfs-server:/srv/nfs/tacacs/config /opt/tacacs_server/config

# Add to /etc/fstab for persistence
nfs-server:/srv/nfs/tacacs/data /opt/tacacs_server/data nfs defaults 0 0
nfs-server:/srv/nfs/tacacs/logs /opt/tacacs_server/logs nfs defaults 0 0
nfs-server:/srv/nfs/tacacs/config /opt/tacacs_server/config nfs defaults 0 0
```

## Database Deployment

### SQLite (Default)

```bash
# Ensure proper permissions
sudo chown -R tacacs:tacacs /opt/tacacs_server/data
sudo chmod 755 /opt/tacacs_server/data
sudo chmod 644 /opt/tacacs_server/data/*.db
```

### PostgreSQL Integration

```python
# Custom database backend (future enhancement)
# tacacs_server/accounting/postgresql.py
import asyncpg
from .models import AccountingRecord

class PostgreSQLLogger:
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
    
    async def log_accounting(self, record: AccountingRecord):
        conn = await asyncpg.connect(self.connection_string)
        await conn.execute("""
            INSERT INTO accounting_logs 
            (username, session_id, status, service, command, client_ip)
            VALUES ($1, $2, $3, $4, $5, $6)
        """, record.username, record.session_id, record.status,
            record.service, record.command, record.client_ip)
        await conn.close()
```

## Monitoring Deployment

### Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "tacacs_rules.yml"

scrape_configs:
  - job_name: 'tacacs-server'
    static_configs:
      - targets: ['tacacs-server:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
    scrape_timeout: 10s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "TACACS+ Server Monitoring",
    "panels": [
      {
        "title": "Authentication Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(tacacs_auth_requests_total[5m])",
            "legendFormat": "Auth Requests/sec"
          }
        ]
      },
      {
        "title": "Success Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "(rate(tacacs_auth_requests_total{status=\"success\"}[5m]) / rate(tacacs_auth_requests_total[5m])) * 100",
            "legendFormat": "Success Rate %"
          }
        ]
      }
    ]
  }
}
```

## Security Hardening

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 49/tcp    # TACACS+
sudo ufw allow 1812/udp  # RADIUS Auth
sudo ufw allow 1813/udp  # RADIUS Acct
sudo ufw allow 8080/tcp  # Web Interface (restrict to management network)
sudo ufw enable

# iptables
iptables -A INPUT -p tcp --dport 49 -j ACCEPT
iptables -A INPUT -p udp --dport 1812 -j ACCEPT
iptables -A INPUT -p udp --dport 1813 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT
```

### SSL/TLS Configuration

```nginx
# NGINX SSL termination
server {
    listen 443 ssl http2;
    server_name tacacs.company.com;
    
    ssl_certificate /etc/ssl/certs/tacacs.company.com.crt;
    ssl_certificate_key /etc/ssl/private/tacacs.company.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;
    
    location / {
        proxy_pass http://web_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

### File Permissions

```bash
# Secure file permissions
sudo chmod 750 /opt/tacacs_server
sudo chmod 640 /opt/tacacs_server/config/tacacs.conf
sudo chmod 750 /opt/tacacs_server/data
sudo chmod 640 /opt/tacacs_server/data/*.db
sudo chmod 750 /opt/tacacs_server/logs
sudo chmod 640 /opt/tacacs_server/logs/*.log
```

## Backup and Recovery

### Automated Backup Script

```bash
#!/bin/bash
# /opt/tacacs_server/scripts/backup.sh

BACKUP_DIR="/backup/tacacs"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/tacacs_backup_$DATE"

# Create backup directory
mkdir -p "$BACKUP_PATH"

# Backup configuration
cp -r /opt/tacacs_server/config "$BACKUP_PATH/"

# Backup databases
cp /opt/tacacs_server/data/*.db "$BACKUP_PATH/"

# Backup logs (last 7 days)
find /opt/tacacs_server/logs -name "*.log" -mtime -7 -exec cp {} "$BACKUP_PATH/" \;

# Create archive
tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_DIR" "tacacs_backup_$DATE"
rm -rf "$BACKUP_PATH"

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "tacacs_backup_*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_PATH.tar.gz"
```

```bash
# Add to crontab
crontab -e
# Daily backup at 2 AM
0 2 * * * /opt/tacacs_server/scripts/backup.sh
```

### Recovery Procedure

```bash
# Stop service
sudo systemctl stop tacacs-server

# Restore from backup
BACKUP_FILE="/backup/tacacs/tacacs_backup_20231201_020000.tar.gz"
cd /tmp
tar -xzf "$BACKUP_FILE"

# Restore configuration
sudo cp -r tacacs_backup_*/config/* /opt/tacacs_server/config/

# Restore databases
sudo cp tacacs_backup_*/data/*.db /opt/tacacs_server/data/

# Fix permissions
sudo chown -R tacacs:tacacs /opt/tacacs_server

# Start service
sudo systemctl start tacacs-server
```

## Performance Tuning

### System Optimization

```bash
# Increase file descriptor limits
echo "tacacs soft nofile 65536" >> /etc/security/limits.conf
echo "tacacs hard nofile 65536" >> /etc/security/limits.conf

# Optimize network settings
echo "net.core.somaxconn = 1024" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 5000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 1024" >> /etc/sysctl.conf
sysctl -p
```

### Application Tuning

```ini
# config/tacacs.conf
[server]
max_connections = 500
socket_timeout = 10

[security]
rate_limit_requests = 1000
rate_limit_window = 60

[database]
# Use faster database settings for high load
cleanup_days = 30
auto_cleanup = true
```

## Troubleshooting Deployment

### Common Issues

1. **Port binding errors**
   ```bash
   # Check port usage
   sudo netstat -tlnp | grep :49
   sudo lsof -i :49
   ```

2. **Permission errors**
   ```bash
   # Fix ownership
   sudo chown -R tacacs:tacacs /opt/tacacs_server
   sudo chmod -R 755 /opt/tacacs_server
   ```

3. **Database connection issues**
   ```bash
   # Check database files
   ls -la /opt/tacacs_server/data/
   sqlite3 /opt/tacacs_server/data/local_auth.db ".tables"
   ```

4. **Service startup failures**
   ```bash
   # Check service logs
   sudo journalctl -u tacacs-server -f
   sudo systemctl status tacacs-server
   ```

### Health Checks

```bash
# Service health check
curl -f http://localhost:8080/api/health

# TACACS+ connectivity test
python scripts/tacacs_client.py localhost 49 secret admin password

# RADIUS connectivity test
python scripts/radius_client.py localhost 1812 secret admin password
```

### Log Analysis

```bash
# Monitor authentication logs
tail -f /opt/tacacs_server/logs/tacacs.log | grep -i auth

# Check error patterns
grep -i error /opt/tacacs_server/logs/tacacs.log | tail -20

# Monitor performance
grep -i "slow\|timeout\|error" /opt/tacacs_server/logs/tacacs.log
```

## Deployment Checklist

### Pre-deployment

- [ ] Configuration validated
- [ ] Secrets properly configured
- [ ] Database directories created
- [ ] File permissions set correctly
- [ ] Firewall rules configured
- [ ] SSL certificates installed (if applicable)
- [ ] Backup procedures tested
- [ ] Monitoring configured

### Post-deployment

## Backup & Restore Deployment Considerations

### Volume Mounts

- Ensure the following paths are persisted across container restarts and have sufficient capacity:
  - `data/backup_executions.db` (backup execution/store metadata)
  - `data/backup_jobs.db` (scheduler jobstore)
  - Destination base paths (e.g., `/backups/tacacs`) when using local destinations
- Grant read/write permissions to the application user for all backup‑related volumes.

### Encryption Environment Variables

- `BACKUP_ENCRYPTION_PASSPHRASE`: Optional passphrase. If set, archives can be encrypted/decrypted transparently.
- Pair with at-rest encryption on destination (e.g., encrypted volumes or provider features) for stronger protection.

### Recommended Schedules

- Start with daily backups during low‑traffic windows (e.g., `0 2 * * *`).
- Increase frequency for configurations that change often; use interval jobs for short cadences.
- Validate restore regularly in a staging environment.

### Disaster Recovery Procedures

- Keep at least one off‑site/off‑AZ copy of recent backups.
- Automate restore drills: select a backup, restore to a sandbox, and validate configuration.
- Document emergency contacts and the exact steps to restore essential services.

### Container-specific Notes

- Use named volumes or bind mounts for backup jobstore and execution DBs.
- Set resource limits to avoid backup tasks being OOM‑killed (backups may be I/O heavy during compression).
- If running behind orchestrators (K8s), expose admin API only within trusted networks.


- [ ] Service starts successfully
- [ ] Health checks pass
- [ ] Authentication tests successful
- [ ] Web interface accessible
- [ ] Metrics collection working
- [ ] Log rotation configured
- [ ] Backup schedule active
- [ ] Documentation updated

### Production Readiness

- [ ] Load balancer configured
- [ ] Multiple instances tested (if used)
- [ ] Disaster recovery plan
- [ ] Performance benchmarks met
- [ ] Security audit completed
- [ ] Monitoring alerts configured
- [ ] Runbook documentation
- [ ] Team training completed
