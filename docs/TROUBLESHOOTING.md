# Troubleshooting Guide

This guide covers common issues and their solutions when deploying and operating the TACACS+ server.

## Common Issues

### Server Won't Start

**Symptoms:**
- Service fails to start
- Port binding errors
- Configuration validation errors

**Solutions:**

1. **Check port availability:**
   ```bash
   sudo netstat -tlnp | grep :49
   sudo lsof -i :49
   ```

2. **Validate configuration:**
   ```bash
   python scripts/validate_config.py
   ```

3. **Check file permissions:**
   ```bash
   sudo chown -R tacacs:tacacs /opt/tacacs_server
   sudo chmod 755 /opt/tacacs_server/data
   ```

### Authentication Failures

**Symptoms:**
- Users cannot authenticate
- LDAP connection errors
- Backend timeouts

**Solutions:**

1. **Test LDAP connectivity:**
   ```bash
   ldapsearch -H ldap://ldap.company.com:389 \
     -D "cn=service,dc=company,dc=com" -w "password" \
     -b "dc=company,dc=com" "(objectClass=*)" dn
   ```

2. **Check user group mappings:**
   ```bash
   # Via admin API
   curl -H "X-API-Token: token" http://localhost:8080/api/users/testuser
   ```

3. **Verify backend configuration:**
   ```ini
   [ldap]
   server = ldap://ldap.company.com:389
   timeout = 10
   use_tls = true
   ```

### Performance Issues

**Symptoms:**
- Slow authentication responses
- High CPU usage
- Memory leaks

**Solutions:**

1. **Increase connection limits:**
   ```ini
   [server]
   max_connections = 500
   ```

2. **Optimize database settings:**
   ```ini
   [database]
   cleanup_days = 30
   auto_cleanup = true
   ```

3. **Monitor system resources:**
   ```bash
   htop
   iostat -x 1
   ```

### Network Connectivity

**Symptoms:**
- Devices cannot reach server
- Intermittent connection drops
- Proxy protocol issues

**Solutions:**

1. **Test TACACS+ connectivity:**
   ```bash
   telnet tacacs-server 49
   ```

2. **Check firewall rules:**
   ```bash
   sudo ufw status
   sudo iptables -L
   ```

3. **Verify proxy protocol configuration:**
   ```ini
   [proxy_protocol]
   enabled = true
   accept_proxy_protocol = true
   validate_sources = true
   ```

## Log Analysis

### Authentication Logs
```bash
# Monitor authentication attempts
tail -f /opt/tacacs_server/logs/tacacs.log | grep -i auth

# Check for failures
grep -i "auth.*fail" /opt/tacacs_server/logs/tacacs.log | tail -20
```

### Error Patterns
```bash
# Common error patterns
grep -E "(error|exception|timeout)" /opt/tacacs_server/logs/tacacs.log

# Performance issues
grep -E "(slow|timeout|high)" /opt/tacacs_server/logs/tacacs.log
```

## Health Checks

### Service Health
```bash
# Check service status
sudo systemctl status tacacs-server

# Test API health
curl -f http://localhost:8080/api/health
```

### Database Health
```bash
# Check database files
ls -la /opt/tacacs_server/data/
sqlite3 /opt/tacacs_server/data/local_auth.db ".tables"
```

## Recovery Procedures

### Configuration Recovery
```bash
# Restore from backup
sudo cp config/tacacs.conf.backup config/tacacs.conf
sudo systemctl restart tacacs-server
```

### Database Recovery
```bash
# Stop service
sudo systemctl stop tacacs-server

# Restore database
sudo cp backup/local_auth.db.backup data/local_auth.db
sudo chown tacacs:tacacs data/local_auth.db

# Start service
sudo systemctl start tacacs-server
```

## Getting Help

1. **Check logs first:** Always examine the application logs for error messages
2. **Validate configuration:** Use the validation script before making changes
3. **Test connectivity:** Verify network connectivity between components
4. **Monitor resources:** Check system resources (CPU, memory, disk)
5. **Review documentation:** Consult the relevant documentation sections

For additional support, check the project's GitHub issues or create a new issue with:
- Server version
- Configuration (sanitized)
- Log excerpts
- Steps to reproduce