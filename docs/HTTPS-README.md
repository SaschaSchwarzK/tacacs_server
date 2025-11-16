# HTTPS / TLS Overview

This document gives a high‑level view of how HTTPS is provided around the TACACS+ server container and points you to more detailed, source‑of‑truth documents.

The web admin/API always listens on HTTP `:8080` inside the container. HTTPS is provided by a sidecar reverse proxy (Caddy) in the `https` image variant.

## Certificate strategy (source of truth)

For complete details of certificate behavior and fallback, see:

- `CERTIFICATE-OPTIONS.md` – design/architecture of certificate options (per‑customer, wildcard, App Gateway).
- `CERTIFICATE-FALLBACK.md` – exact behavior of the Key Vault + self‑signed fallback implementation.

In short:

- Primary: fetch a PFX from Azure Key Vault, convert to PEM, and serve it via Caddy.
- Fallback: if Key Vault is missing or unavailable, `fetch_cert.py` generates a self‑signed wildcard certificate (`CERT_FALLBACK_DOMAIN`, default `*.kyndryl.com`).
- If both Key Vault and self‑signed generation fail: the container skips Caddy and still starts TACACS+/RADIUS with the internal HTTP admin on `8080`.

## Files involved (https image)

- `docker/https/fetch_cert.py` – fetches PFX from Key Vault and/or generates a self‑signed wildcard certificate, writes `cert.pem` and `key.pem` under `CERT_DIR` (default `/certs`).
- `docker/https/bootstrap-https.sh` – downloads per‑customer config from Azure Blob Storage, runs `fetch_cert.py`, and starts Caddy + tacacs‑server.
- `docker/Dockerfile.https` – Dockerfile that assembles the HTTPS image with Caddy, `fetch_cert.py` and the bootstrap.
- `Caddyfile` – config used by Caddy to terminate TLS on `8443` and proxy to `http://localhost:8080`.

These files define the behavior; the docs above summarize and reference them rather than duplicating their content.

## Key environment variables

The HTTPS image uses the following key variables (see `DEPLOYMENT-GUIDE-HTTPS.md` for full tables and Azure CLI examples):

- Certificate / Key Vault:
  - `KEYVAULT_URL` – Key Vault URL (e.g. `https://tacacs-shared-kv.vault.azure.net/`).
  - `CERT_NAME` – secret name containing the PFX in Key Vault.
  - `CERT_PASSWORD` – optional PFX password.
  - `CERT_FALLBACK_DOMAIN` – domain to use when generating a self‑signed wildcard (default `*.kyndryl.com`).
  - `CERT_DIR` – directory where `cert.pem`/`key.pem` are written (default `/certs`).
- Storage / config:
  - `AZURE_STORAGE_CONNECTION_STRING` – Azure Storage connection string.
  - `STORAGE_CONTAINER` – container holding per‑customer configs (default `tacacs-data`).
  - `CUSTOMER_ID` – per‑customer namespace; config is read from `<CUSTOMER_ID>/config.ini`.
- Admin / API:
  - `ADMIN_PASSWORD` – plaintext admin password for the web UI (hashed at startup by `web_app`).
  - `API_TOKEN` – bearer token for `/api/*` protection.

The full HTTPS deployment flow, including Managed Identity and Key Vault policy setup, is documented in `DEPLOYMENT-GUIDE-HTTPS.md`.

## Local HTTPS smoke test (self‑signed)

For a quick local HTTPS test using the self‑signed fallback:

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

Access:
- TACACS: port 49
- RADIUS: ports 1812/1813 (UDP)
- Web Admin/API: `https://localhost:8443` (proxied to `http://localhost:8080`)
