# TACACS+ Azure Deployment - Quick Reference

## Prerequisites Setup (One-Time)

```bash
# 1. Create resource group
az group create --name tacacs-rg --location westeurope

# 2. Create Key Vault
az keyvault create \
  --name tacacs-shared-kv \
  --resource-group tacacs-rg \
  --location westeurope

# 3. Create Storage Account
az storage account create \
  --name tacacsstorage \
  --resource-group tacacs-rg \
  --location westeurope \
  --sku Standard_LRS

# 4. Get storage connection string and store in Key Vault
STORAGE_CONN=$(az storage account show-connection-string \
  --name tacacsstorage \
  --resource-group tacacs-rg \
  --query connectionString -o tsv)

az keyvault secret set \
  --vault-name tacacs-shared-kv \
  --name storage-connection-string \
  --value "$STORAGE_CONN"

# 5. Create storage container
az storage container create \
  --name tacacs-data \
  --account-name tacacsstorage
```

## Deploy New Customer

```bash
# Make scripts executable
chmod +x deploy/aci/deploy-customer.sh deploy/aci/manage-customers.sh

# Deploy with certificate
./deploy/aci/deploy-customer.sh acme-corp acme-corp.pfx MyP@ssw0rd

# Deploy without password-protected cert
./deploy/aci/deploy-customer.sh contoso contoso.pfx
```

## Local HTTPS Smoke Test (Self-Signed)

```bash
# Build HTTPS image from repo root
make docker-build-https

# Run container with self-signed cert
docker run --rm \
  -e CUSTOMER_ID=test \
  -e AZURE_STORAGE_CONNECTION_STRING=UseDevelopmentStorage=true \
  -e STORAGE_CONTAINER=tacacs-data \
  -e ADMIN_PASSWORD=DevAdminPass1 \
  -e API_TOKEN=devtoken \
  -p 49:49 \
  -p 1812:1812/udp \
  -p 1813:1813/udp \
  -p 8443:8443 \
  tacacs-server:https

# In another terminal – verify HTTPS health
curl -k https://localhost:8443/health
```

## Manage Customers

```bash
# List all deployed customers
./deploy/aci/manage-customers.sh list

# Show customer details
./deploy/aci/manage-customers.sh info acme-corp

# View logs
./deploy/aci/manage-customers.sh logs acme-corp
./deploy/aci/manage-customers.sh logs acme-corp --follow

# Restart container
./deploy/aci/manage-customers.sh restart acme-corp

# List backups
./deploy/aci/manage-customers.sh backup-list acme-corp

# Delete container (keeps data)
./deploy/aci/manage-customers.sh delete acme-corp

# Complete deletion (destructive!)
./deploy/aci/manage-customers.sh purge acme-corp
```

## Storage Structure

```
Storage Account: tacacsstorage
└── Container: tacacs-data
    └── <CUSTOMER_ID>/
        ├── config.ini          # Runtime configuration
        └── backups/            # Automated backups
            ├── backup-2025-01-15-020000.db
            ├── backup-2025-01-16-020000.db
            └── backup-2025-01-17-020000.db
```

## Key Vault Structure

```
Key Vault: tacacs-shared-kv

Certificates:
├── <CUSTOMER_ID>-ssl-cert           # PFX certificate per customer

Secrets:
├── storage-connection-string        # Shared storage connection
├── <CUSTOMER_ID>-admin-password     # Web admin password
└── <CUSTOMER_ID>-api-token          # API authentication token
```

## Environment Variables

Each container receives:

```bash
# Direct variables
CUSTOMER_ID=acme-corp
KEYVAULT_URL=https://tacacs-shared-kv.vault.azure.net/
CERT_NAME=acme-corp-ssl-cert
STORAGE_CONTAINER=tacacs-data

# From Key Vault
AZURE_STORAGE_CONNECTION_STRING=<from-keyvault>
ADMIN_PASSWORD=<from-keyvault>
API_TOKEN=<from-keyvault>
```

## Accessing Services

After deployment, services are available at:

```
TACACS Server:    <CONTAINER_IP>:49
RADIUS Auth:      <CONTAINER_IP>:1812/udp
RADIUS Acct:      <CONTAINER_IP>:1813/udp
Web Admin (HTTPS): https://<CONTAINER_IP>:8443
```

## Common Operations

### Update Configuration

```bash
# Download current config
az storage blob download \
  --account-name tacacsstorage \
  --container-name tacacs-data \
  --name acme-corp/config.ini \
  --file config.ini

# Edit config.ini locally
nano config.ini

# Upload updated config
az storage blob upload \
  --account-name tacacsstorage \
  --container-name tacacs-data \
  --name acme-corp/config.ini \
  --file config.ini \
  --overwrite

# Restart container to load new config
./deploy/aci/manage-customers.sh restart acme-corp
```

### Rotate Certificate

```bash
CUSTOMER_ID="acme-corp"
KV_NAME="tacacs-shared-kv"

# Upload new certificate
az keyvault certificate import \
  --vault-name $KV_NAME \
  --name "${CUSTOMER_ID}-ssl-cert" \
  --file new-cert.pfx \
  --password "pfx-password"

# Restart container to load new cert
./deploy/aci/manage-customers.sh restart $CUSTOMER_ID
```

### Download Backup

```bash
# List available backups
./deploy/aci/manage-customers.sh backup-list acme-corp

# Download specific backup
az storage blob download \
  --account-name tacacsstorage \
  --container-name tacacs-data \
  --name acme-corp/backups/backup-2025-01-15-020000.db \
  --file backup.db
```

### Change Admin Password

```bash
CUSTOMER_ID="acme-corp"
KV_NAME="tacacs-shared-kv"

# Generate new password
NEW_PWD=$(openssl rand -base64 24)

# Update in Key Vault
az keyvault secret set \
  --vault-name $KV_NAME \
  --name "${CUSTOMER_ID}-admin-password" \
  --value "$NEW_PWD"

# Restart container
./deploy/aci/manage-customers.sh restart $CUSTOMER_ID

echo "New password: $NEW_PWD"
```

## Troubleshooting

### Container won't start

```bash
# Check container events
az container show \
  --name tacacs-acme-corp \
  --resource-group tacacs-rg \
  --query instanceView

# Check logs
./deploy/aci/manage-customers.sh logs acme-corp
```

### Certificate issues

```bash
# Verify certificate exists
az keyvault certificate show \
  --vault-name tacacs-shared-kv \
  --name acme-corp-ssl-cert

# Test certificate download
az keyvault certificate download \
  --vault-name tacacs-shared-kv \
  --name acme-corp-ssl-cert \
  --file test.pem
```

### Config not loading

```bash
# Verify config exists
az storage blob exists \
  --account-name tacacsstorage \
  --container-name tacacs-data \
  --name acme-corp/config.ini

# Download and check config
az storage blob download \
  --account-name tacacsstorage \
  --container-name tacacs-data \
  --name acme-corp/config.ini \
  --file test-config.ini

cat test-config.ini
```

### Backups not working

```bash
# Check backup folder exists
az storage blob list \
  --account-name tacacsstorage \
  --container-name tacacs-data \
  --prefix acme-corp/backups/

# Check container logs for backup errors
./deploy/aci/manage-customers.sh logs acme-corp | grep -i backup
```

## Network Configuration

### Configure Custom Domain (Optional)

```bash
# Create DNS CNAME record
# Point your-domain.com to tacacs-acme-corp.westeurope.azurecontainer.io

# Update Caddyfile in container to use custom domain
# Then redeploy container
```

### Configure Network Security

```bash
# Create network profile with NSG
# Restrict access to specific IPs/ranges
# This requires VNet integration (additional setup)
```

## Monitoring

### View Real-Time Logs

```bash
./deploy/aci/manage-customers.sh logs acme-corp --follow
```

### Check Container Health

```bash
az container show \
  --name tacacs-acme-corp \
  --resource-group tacacs-rg \
  --query "{State:instanceView.state, RestartCount:containers[0].instanceView.restartCount}"
```

### Monitor Resource Usage

```bash
# CPU/Memory metrics (requires Azure Monitor setup)
az monitor metrics list \
  --resource /subscriptions/<sub>/resourceGroups/tacacs-rg/providers/Microsoft.ContainerInstance/containerGroups/tacacs-acme-corp \
  --metric "CpuUsage"
```

## Cost Estimation

Per customer container (approximate):

```
Component             Cost/Month (West Europe)
-------------------------------------------------
ACI (2 CPU, 4GB)      ~$80-100
Storage (5GB)         ~$0.10
Key Vault secrets     ~$0.03 per 10K operations
Data transfer         Variable
-------------------------------------------------
Estimated Total:      ~$85-105/customer/month
```

## Security Best Practices

1. **Rotate secrets regularly** (every 90 days)
2. **Use strong PFX passwords** for certificates
3. **Limit Key Vault access** to specific Managed Identities
4. **Enable soft-delete** on Key Vault
5. **Configure firewall rules** on Storage Account
6. **Monitor access logs** in Azure Monitor
7. **Backup Key Vault** configurations
8. **Use separate resource groups** for dev/prod

## Disaster Recovery

### Backup Strategy

- **Automated**: Daily backups to Storage (configured in config.ini)
- **Manual**: Download backups regularly to off-site location
- **Key Vault**: Enable soft-delete and purge protection
- **Storage**: Enable geo-redundancy (GRS) for production

### Recovery Procedure

```bash
# 1. Redeploy container
./deploy/aci/deploy-customer.sh acme-corp acme-corp.pfx password

# 2. Restore latest backup (if needed)
# Upload backup to storage and restart container
```
