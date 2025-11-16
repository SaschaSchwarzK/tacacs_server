# Certificate Fallback Update - Summary

## What Changed

Updated the HTTPS setup to **always start the web admin** by implementing a self-signed certificate fallback mechanism.

## New Behavior

### Before
- ❌ If Key Vault unavailable → Web admin disabled
- ❌ If certificate missing → Web admin disabled
- ❌ TACACS/RADIUS only mode

### After
- ✅ If Key Vault available → Use production certificate
- ✅ If Key Vault unavailable → Generate self-signed certificate
- ✅ Web admin **always starts** (with browser warning if self-signed)
- ✅ TACACS/RADIUS always available

## Updated Files

### 1. `fetch_cert.py` (Major Changes)
**New functionality:**
- Try to fetch certificate from Key Vault first
- If Key Vault fails → Generate self-signed wildcard certificate
- Default domain: `*.kyndryl.com`
- Customizable via `CERT_FALLBACK_DOMAIN` env var
- Clear logging of which certificate is being used

**Code flow:**
```python
1. Try Key Vault fetch
   ├─ Success → Use Key Vault certificate
   └─ Fail → Generate self-signed *.kyndryl.com
2. Save cert.pem + key.pem
3. Return success (almost always)
```

### 2. `bootstrap-https.sh` (Minor Changes)
**Updated:**
- Removed explicit Key Vault check
- Always calls `fetch_cert.py`
- Script handles fallback automatically
- Web admin starts if any certificate available

### 3. `DEPLOYMENT-GUIDE.md` (Documentation Update)
**Updated sections:**
- Startup sequence diagram (shows fallback flow)
- Environment variables table (added `CERT_FALLBACK_DOMAIN`)
- Behavior descriptions

### 4. `README.md` (Documentation Update)
**Updated sections:**
- "How It Works" - Explains fallback
- "Certificate Behavior" - Details all scenarios

### 5. New: `CERTIFICATE-FALLBACK.md`
**Complete new document covering:**
- Behavior flow diagram
- Certificate priority
- Use cases (dev/prod/disaster recovery)
- Deployment scenarios
- Logging examples
- Troubleshooting
- Migration path
- Best practices

### 6. `INDEX.md` (Navigation Update)
**Updated:**
- Added `CERTIFICATE-FALLBACK.md` to file list
- Updated documentation count (5 → 6)

## New Environment Variable

```bash
CERT_FALLBACK_DOMAIN="*.kyndryl.com"  # Default
```

Customize the self-signed certificate domain:
```bash
CERT_FALLBACK_DOMAIN="*.mycompany.com"
```

## Use Cases

### Development (No Key Vault Needed)
```bash
# Deploy without Key Vault configuration
az container create \
  --environment-variables CUSTOMER_ID="dev" \
  # No KEYVAULT_URL, no CERT_NAME

# Result: Self-signed cert, web admin accessible
```

### Production (Key Vault Preferred)
```bash
# Deploy with Key Vault
az container create \
  --environment-variables \
    CUSTOMER_ID="prod" \
    KEYVAULT_URL="https://kv.vault.azure.net/" \
    CERT_NAME="prod-ssl-cert"

# Result: Uses Key Vault cert, falls back if needed
```

### Disaster Recovery
```
Key Vault outage detected
├─ Container restarts
├─ Cannot fetch Key Vault certificate
├─ Generates self-signed certificate
├─ Web admin accessible (with browser warning)
└─ TACACS/RADIUS continue normally
```

## Security Considerations

### Self-Signed Certificates
✅ **Good for:**
- Development environments
- Testing
- Emergency access during outages
- Initial deployment

❌ **Not suitable for:**
- Production deployments
- Customer-facing systems
- Compliance requirements

### Browser Warnings
Self-signed certificates will show:
- "Your connection is not private"
- "NET::ERR_CERT_AUTHORITY_INVALID"
- Must click "Advanced" → "Proceed anyway"

## Logging Changes

### Key Vault Success
```
Fetching/generating certificate...
Attempting to fetch certificate 'customer1-ssl-cert' from https://...
Converting PFX to PEM...
✓ Certificate fetched from Key Vault
✓ Certificate saved to /certs/cert.pem
```

### Self-Signed Fallback
```
Fetching/generating certificate...
Attempting to fetch certificate 'customer1-ssl-cert' from https://...
⚠ Key Vault fetch failed: Certificate not found
⚠ Generating self-signed certificate for *.kyndryl.com
⚠ This is NOT suitable for production use!
✓ Self-signed certificate generated successfully
✓ CN: *.kyndryl.com
⚠ WARNING: Browsers will show security warnings!
```

## Migration for Existing Deployments

No action required for existing deployments:
- Containers with Key Vault config continue working
- If Key Vault becomes unavailable, automatically falls back
- No breaking changes to existing behavior

## Testing the Change

### Test Self-Signed Generation
```bash
# Deploy without Key Vault
docker run -e CUSTOMER_ID=test \
  -e STORAGE_CONTAINER=tacacs-data \
  -e AZURE_STORAGE_CONNECTION_STRING="..." \
  tacacs-server:https

# Should see:
# ⚠ Generating self-signed certificate for *.kyndryl.com
# ✓ Web admin accessible at https://localhost:8443
```

### Test Key Vault + Fallback
```bash
# Deploy with Key Vault
docker run -e CUSTOMER_ID=test \
  -e KEYVAULT_URL="https://invalid-kv.vault.azure.net/" \
  -e CERT_NAME="nonexistent-cert" \
  ...

# Should see:
# ⚠ Key Vault fetch failed: ...
# ⚠ Generating self-signed certificate for *.kyndryl.com
```

## Benefits

1. **Faster Development** - No certificate needed to start
2. **Easier Deployment** - Works immediately
3. **Better Reliability** - Service continues during Key Vault issues
4. **Disaster Recovery** - Automatic fallback
5. **Clear Logging** - Know which certificate is active
6. **Backward Compatible** - Existing deployments unaffected

## Key Decisions

### Why `*.kyndryl.com`?
- Wildcard covers all subdomains
- Company-specific default
- Can be overridden via env var

### Why Always Fallback?
- Service availability over security
- Better than no web admin
- Clear warnings about self-signed
- Production should still use Key Vault

### Why Not Fail Hard?
- TACACS/RADIUS must always work
- Web admin is secondary
- Operators need access during outages
- Self-signed better than nothing

## Next Steps

1. **Review** `CERTIFICATE-FALLBACK.md` for full details
2. **Test** self-signed generation locally
3. **Update** deployment scripts if needed
4. **Document** which deployments should use Key Vault
5. **Monitor** for self-signed usage in production

## Files to Read

1. **CERTIFICATE-FALLBACK.md** - Complete fallback documentation
2. **README.md** - Updated behavior summary
3. **DEPLOYMENT-GUIDE.md** - Updated deployment flow
4. **fetch_cert.py** - See implementation

## Summary

**Key Change:** Web admin now always starts by using self-signed certificates as a fallback when Key Vault is unavailable.

**Impact:** 
- ✅ Better development experience
- ✅ Improved disaster recovery
- ✅ Service continuity
- ⚠️ Production should still use Key Vault certificates
