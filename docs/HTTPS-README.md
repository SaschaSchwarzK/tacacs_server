# HTTPS Setup with Azure Key Vault Certificate

## Files Created

1. **fetch_cert.py** - Fetches PFX from Key Vault, converts to PEM
2. **Caddyfile** - Caddy reverse proxy config (HTTPS on 8443)
3. **bootstrap-https.sh** - Modified bootstrap that fetches cert + starts Caddy
4. **docker/Dockerfile.https** - Adds Caddy + Azure cert dependencies

## Environment Variables Required

```bash
# Existing
CUSTOMER_ID=customer123
AZURE_STORAGE_CONNECTION_STRING=...
ADMIN_PASSWORD=...
API_TOKEN=...

# New for HTTPS
KEYVAULT_URL=https://your-vault.vault.azure.net/
CERT_NAME=your-cert-name
CERT_PASSWORD=pfx-password  # Optional if PFX has password
```

## How It Works

1. Container starts with Managed Identity
2. `fetch_cert.py` attempts to download certificate from Key Vault
3. **If Key Vault available**: Uses production certificate
4. **If Key Vault unavailable**: Generates self-signed wildcard certificate (*.kyndryl.com)
5. Converts to cert.pem + key.pem in `/certs/`
6. Caddy starts on port 8443 with TLS
7. Caddy proxies to web admin on localhost:8080
8. Web admin always starts (with Key Vault or self-signed certificate)

## Certificate Behavior

- **Key Vault configured + accessible**: Uses production certificate
- **Key Vault unavailable**: Generates self-signed *.kyndryl.com certificate (browser warning)
- **No Key Vault configured**: Uses self-signed certificate (development mode)
- **Certificate generation fails completely**: Web admin disabled, TACACS/RADIUS continue
- **Caddy fails**: Web admin disabled, TACACS/RADIUS continue
- **Config fetch fails**: Uses default config from image

## Build & Local Smoke Test

```bash
# Build HTTPS image from repo root
make docker-build-https

# Minimal self-signed test run (no Key Vault needed)
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

## Access

- TACACS: Port 49
- RADIUS: Ports 1812/1813
- Web Admin: https://localhost:8443 (was http://localhost:8080)

## Notes

- Healthcheck tries HTTPS first, falls back to HTTP
- Caddy runs in background, TACACS server in foreground
- Certificate must exist in Key Vault as Secret (not Certificate object)
- Managed Identity needs "Get" permission on Key Vault secrets
