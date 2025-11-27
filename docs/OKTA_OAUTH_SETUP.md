# Okta OAuth 2.0 Setup Guide

## Overview
Your TACACS+ server now supports three authentication methods for Okta Management API:
1. **OAuth 2.0 with private_key_jwt** (RECOMMENDED)
2. **OAuth 2.0 with client_secret** (Fallback)
3. **SSWS API Token** (Legacy - being deprecated by Okta)

## Why OAuth 2.0?
- SSWS tokens are being deprecated by Okta
- OAuth 2.0 with private_key_jwt is more secure (no shared secrets)
- Required for Okta Management API going forward

## Setup Instructions

### Method 1: OAuth 2.0 with private_key_jwt (Recommended)

#### Step 1: Create OAuth Application in Okta
1. Log into Okta Admin Console
2. Go to **Applications** → **Applications**
3. Click **Create App Integration**
4. Select **API Services** (this is for machine-to-machine)
5. Click **Next**
6. Give it a name (e.g., "TACACS Server")
7. Enable **Public key / Private key** authentication
8. Click **Save**

#### Step 2: Generate Key Pair
```bash
# Generate private key
openssl genrsa -out okta_private.pem 2048

# Generate public key
openssl rsa -in okta_private.pem -pubout -out okta_public.pem
```

#### Step 3: Add Public Key to Okta
1. In your OAuth app, go to **General** tab
2. Scroll to **PUBLIC KEYS** section
3. Click **Add key**
4. Paste content of `okta_public.pem`
5. Give it a name (Key ID / kid)
6. Save the Key ID - you'll need this

#### Step 4: Grant API Scopes
1. In your OAuth app, go to **Okta API Scopes** tab
2. Grant these scopes:
   - `okta.users.read`
   - `okta.groups.read`

#### Step 5: Configure TACACS Server
Update your `config/tacacs.conf`:

```ini
[okta]
org_url = https://your-domain.okta.com
auth_method = private_key_jwt
client_id = 0oa1234567890abcdef  # From step 1
private_key = /path/to/okta_private.pem  # From step 2
private_key_id = kid_12345  # From step 3
verify_tls = true
mfa_enabled = true
```

### Method 2: OAuth 2.0 with client_secret (Fallback)

#### Step 1: Create OAuth Application
1. Log into Okta Admin Console
2. Go to **Applications** → **Applications**
3. Click **Create App Integration**
4. Select **API Services**
5. Click **Next**
6. Give it a name (e.g., "TACACS Server")
7. Enable **Client secret** authentication
8. Click **Save**
9. Copy the **Client ID** and **Client secret**

#### Step 2: Grant API Scopes
Same as Method 1, Step 4

#### Step 3: Configure TACACS Server
```ini
[okta]
org_url = https://your-domain.okta.com
auth_method = client_secret
client_id = 0oa1234567890abcdef
client_secret = ${OKTA_CLIENT_SECRET}  # Use env var for security
verify_tls = true
mfa_enabled = true
```

Set environment variable:
```bash
export OKTA_CLIENT_SECRET="your-secret-here"
```

### Method 3: SSWS API Token (Legacy)

**Note:** This method still works but is being deprecated by Okta. Migrate to OAuth 2.0 when possible.

```ini
[okta]
org_url = https://your-domain.okta.com
# OAuth client credentials (choose client_secret or private_key_jwt)
# auth_method = client_secret
# client_id = ${OKTA_CLIENT_ID}
# client_secret = ${OKTA_CLIENT_SECRET}
# auth_method = private_key_jwt
# client_id = ${OKTA_CLIENT_ID}
# private_key = /path/to/private_key.pem
# private_key_id = <kid>
verify_tls = true
mfa_enabled = true
```

## Auto-Detection

If you don't specify `auth_method`, the system will auto-detect based on what you've configured:
- If `private_key` and `private_key_id` exist → uses `private_key_jwt`
- If `client_secret` exists → uses `client_secret`
- If `api_token` exists → uses `ssws`

## Requirements

For private_key_jwt method, you need to install:
```bash
pip install PyJWT[crypto]
```

This is already in your requirements if you're using the full TACACS server installation.

## Verification

Check your configuration:
```bash
# Start server and check logs
tail -f logs/tacacs.log
```

You should see:
```
OAuth access token obtained via private_key_jwt (expires in 3600s)
```

## Troubleshooting

### "PyJWT library required for private_key_jwt"
Install: `pip install PyJWT[crypto]`

### "OAuth token request failed: 401"
- Check client_id is correct
- Verify private key matches public key in Okta
- Ensure private_key_id (kid) matches the key in Okta

### "Failed to get OAuth token"
- Check org_url is correct
- Verify token_endpoint if using custom auth server
- Check network connectivity to Okta

### "No authentication method configured for Management API"
- Add one of the auth methods to [okta] section
- Or set `auth_method` explicitly

## Migration from SSWS to OAuth 2.0

1. Set up OAuth 2.0 credentials (Method 1 or 2)
2. Add OAuth config to `[okta]` section
3. Keep `api_token` as fallback initially
4. Test OAuth authentication
5. Remove `api_token` once confirmed working
6. Set `auth_method = private_key_jwt` explicitly

## Security Best Practices

1. **Never commit secrets to git**
   - Use environment variables for sensitive values
   - Use `${OKTA_CLIENT_SECRET}` syntax in config

2. **Protect private keys**
   ```bash
   chmod 600 okta_private.pem
   ```

3. **Rotate credentials regularly**
   - Generate new key pairs periodically
   - Update Okta with new public key
   - Update config with new private key

4. **Use private_key_jwt over client_secret**
   - More secure (no shared secrets)
   - Industry best practice
