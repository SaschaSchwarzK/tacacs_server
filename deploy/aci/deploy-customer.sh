#!/bin/bash
# deploy-customer.sh - Deploy new TACACS instance
# Usage: ./deploy/aci/deploy-customer.sh <customer-id> <cert-pfx-file> [pfx-password]

set -e

CUSTOMER_ID=$1
CERT_FILE=$2
CERT_PASSWORD=${3:-""}

if [ -z "$CUSTOMER_ID" ] || [ -z "$CERT_FILE" ]; then
    echo "Usage: $0 <customer-id> <cert-pfx-file> [pfx-password]"
    echo ""
    echo "Example:"
    echo "  $0 acme-corp acme-corp.pfx MyP@ssw0rd"
    echo "  $0 contoso contoso.pfx"
    exit 1
fi

# Configuration
KV_NAME="tacacs-shared-kv"
RG="tacacs-rg"
STORAGE_ACCOUNT="tacacsstorage"
STORAGE_CONTAINER="tacacs-data"
IMAGE="yourregistry.azurecr.io/tacacs-server:https"
LOCATION="westeurope"

echo "======================================"
echo "TACACS+ Container Deployment"
echo "======================================"
echo "Customer ID: ${CUSTOMER_ID}"
echo "Key Vault: ${KV_NAME}"
echo "Storage: ${STORAGE_ACCOUNT}/${STORAGE_CONTAINER}"
echo "Resource Group: ${RG}"
echo "======================================"
echo ""

# Check if certificate file exists
if [ ! -f "$CERT_FILE" ]; then
    echo "ERROR: Certificate file not found: $CERT_FILE"
    exit 1
fi

# Step 1: Create Managed Identity
echo "[1/7] Creating Managed Identity..."
if az identity show --name "tacacs-${CUSTOMER_ID}-identity" --resource-group $RG &>/dev/null; then
    echo "  ℹ Managed Identity already exists, skipping creation"
else
    az identity create \
      --name "tacacs-${CUSTOMER_ID}-identity" \
      --resource-group $RG \
      --location $LOCATION
    echo "  ✓ Created"
fi

IDENTITY_ID=$(az identity show \
  --name "tacacs-${CUSTOMER_ID}-identity" \
  --resource-group $RG \
  --query id -o tsv)

PRINCIPAL_ID=$(az identity show \
  --name "tacacs-${CUSTOMER_ID}-identity" \
  --resource-group $RG \
  --query principalId -o tsv)

echo "  Identity ID: ${IDENTITY_ID}"
echo "  Principal ID: ${PRINCIPAL_ID}"

# Step 2: Grant Key Vault access
echo ""
echo "[2/7] Granting Key Vault access..."
az keyvault set-policy \
  --name $KV_NAME \
  --object-id $PRINCIPAL_ID \
  --secret-permissions get \
  --certificate-permissions get \
  --output none
echo "  ✓ Permissions granted"

# Step 3: Upload certificate
echo ""
echo "[3/7] Uploading certificate..."
if [ -n "$CERT_PASSWORD" ]; then
    az keyvault certificate import \
      --vault-name $KV_NAME \
      --name "${CUSTOMER_ID}-ssl-cert" \
      --file "$CERT_FILE" \
      --password "$CERT_PASSWORD" \
      --output none
else
    az keyvault certificate import \
      --vault-name $KV_NAME \
      --name "${CUSTOMER_ID}-ssl-cert" \
      --file "$CERT_FILE" \
      --output none
fi
echo "  ✓ Certificate uploaded: ${CUSTOMER_ID}-ssl-cert"

# Step 4: Generate and store secrets
echo ""
echo "[4/7] Creating secrets..."
ADMIN_PWD=$(openssl rand -base64 24)
API_TOKEN="tok_$(openssl rand -hex 16)"

az keyvault secret set \
  --vault-name $KV_NAME \
  --name "${CUSTOMER_ID}-admin-password" \
  --value "$ADMIN_PWD" \
  --output none
echo "  ✓ Admin password stored"

az keyvault secret set \
  --vault-name $KV_NAME \
  --name "${CUSTOMER_ID}-api-token" \
  --value "$API_TOKEN" \
  --output none
echo "  ✓ API token stored"

# Step 5: Upload initial config
echo ""
echo "[5/7] Uploading initial config..."
cat > /tmp/${CUSTOMER_ID}-config.ini <<EOF
[server]
port = 49
host = 0.0.0.0

[web]
enabled = true
port = 8080

[database]
path = /tmp/tacacs.db

[backup]
enabled = true
backend = azure
schedule = "0 2 * * *"

[logging]
level = INFO
EOF

az storage blob upload \
  --account-name $STORAGE_ACCOUNT \
  --container-name $STORAGE_CONTAINER \
  --name "${CUSTOMER_ID}/config.ini" \
  --file /tmp/${CUSTOMER_ID}-config.ini \
  --overwrite \
  --output none
echo "  ✓ Config uploaded: ${CUSTOMER_ID}/config.ini"

rm /tmp/${CUSTOMER_ID}-config.ini

# Step 6: Create backups folder
echo ""
echo "[6/7] Creating backup folder..."
echo "" | az storage blob upload \
  --account-name $STORAGE_ACCOUNT \
  --container-name $STORAGE_CONTAINER \
  --name "${CUSTOMER_ID}/backups/.placeholder" \
  --file /dev/stdin \
  --overwrite \
  --output none
echo "  ✓ Backup folder created: ${CUSTOMER_ID}/backups/"

# Step 7: Deploy container
echo ""
echo "[7/7] Deploying ACI container..."

# Check if container already exists
if az container show --name "tacacs-${CUSTOMER_ID}" --resource-group $RG &>/dev/null; then
    echo "  ⚠ Container already exists. Delete it first if you want to redeploy."
    echo "    az container delete --name tacacs-${CUSTOMER_ID} --resource-group $RG --yes"
    exit 1
fi

az container create \
  --resource-group $RG \
  --name "tacacs-${CUSTOMER_ID}" \
  --image $IMAGE \
  --assign-identity $IDENTITY_ID \
  --ports 49 1812 1813 8443 \
  --cpu 2 \
  --memory 4 \
  --restart-policy Always \
  --location $LOCATION \
  --environment-variables \
    CUSTOMER_ID="${CUSTOMER_ID}" \
    KEYVAULT_URL="https://${KV_NAME}.vault.azure.net/" \
    CERT_NAME="${CUSTOMER_ID}-ssl-cert" \
    STORAGE_CONTAINER="${STORAGE_CONTAINER}" \
  --secure-environment-variables \
    AZURE_STORAGE_CONNECTION_STRING="@Microsoft.KeyVault(SecretUri=https://${KV_NAME}.vault.azure.net/secrets/storage-connection-string/)" \
    ADMIN_PASSWORD="@Microsoft.KeyVault(SecretUri=https://${KV_NAME}.vault.azure.net/secrets/${CUSTOMER_ID}-admin-password/)" \
    API_TOKEN="@Microsoft.KeyVault(SecretUri=https://${KV_NAME}.vault.azure.net/secrets/${CUSTOMER_ID}-api-token/)" \
  --output none

echo "  ✓ Container deployed"

# Wait a moment for IP assignment
sleep 5

CONTAINER_IP=$(az container show \
  --resource-group $RG \
  --name "tacacs-${CUSTOMER_ID}" \
  --query ipAddress.ip -o tsv)

echo ""
echo "======================================"
echo "✓ Deployment Complete!"
echo "======================================"
echo ""
echo "Customer ID:      ${CUSTOMER_ID}"
echo "Container Name:   tacacs-${CUSTOMER_ID}"
echo "Public IP:        ${CONTAINER_IP}"
echo ""
echo "Services:"
echo "  TACACS:         ${CONTAINER_IP}:49"
echo "  RADIUS Auth:    ${CONTAINER_IP}:1812"
echo "  RADIUS Acct:    ${CONTAINER_IP}:1813"
echo "  Web Admin:      https://${CONTAINER_IP}:8443"
echo ""
echo "Credentials (SAVE THESE SECURELY!):"
echo "  Admin Password: ${ADMIN_PWD}"
echo "  API Token:      ${API_TOKEN}"
echo ""
echo "Storage Paths:"
echo "  Config:  ${STORAGE_CONTAINER}/${CUSTOMER_ID}/config.ini"
echo "  Backups: ${STORAGE_CONTAINER}/${CUSTOMER_ID}/backups/"
echo ""
echo "Key Vault Resources:"
echo "  Certificate:    ${CUSTOMER_ID}-ssl-cert"
echo "  Admin Password: ${CUSTOMER_ID}-admin-password"
echo "  API Token:      ${CUSTOMER_ID}-api-token"
echo ""
echo "======================================"
echo ""
echo "Next Steps:"
echo "1. Save the credentials above"
echo "2. Access web admin: https://${CONTAINER_IP}:8443"
echo "3. Configure TACACS clients"
echo "4. Monitor logs: az container logs -g ${RG} -n tacacs-${CUSTOMER_ID} --follow"
echo ""

