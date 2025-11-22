# OpenID Connect (OIDC) Admin Authentication Integration

## Overview
This guide covers the integration of OpenID Connect authentication for admin web access to the TACACS+ server. Users authenticate via an external OpenID provider (Google, Okta, Keycloak, etc.) and their email address is logged for audit purposes.

## Architecture

- **Phase 1**: `openid_auth.py` - OIDC token exchange and session management
- **Phase 2**: `web_auth.py` - Integration with existing session manager
- **Phase 3/4**: `web_admin.py` + Login Template - OIDC login routes and UI

### Key Features

✅ Email-based user identification in logs  
✅ Concurrent user sessions tracked separately  
✅ No local user accounts created  
✅ Auto-discovery of OIDC provider endpoints  
✅ CSRF protection via state parameter  
✅ Both password and OpenID login methods supported  

## Setup

### 1. Configure Your OIDC Provider

Register your TACACS server with your OpenID provider:

**Redirect URI**: `https://your-tacacs-host/admin/login/openid-callback`  
**Scopes**: `openid profile email` (minimum)  
**Flow**: Authorization Code

**Example providers**:
- Google: https://console.cloud.google.com/
- Okta: https://developer.okta.com/
- Keycloak: Self-hosted or managed

### 2. Set Environment Variables

```bash
export OPENID_ISSUER_URL="https://accounts.google.com"
export OPENID_CLIENT_ID="xxx.apps.googleusercontent.com"
export OPENID_CLIENT_SECRET="your-secret"
export OPENID_REDIRECT_URI="https://your-tacacs-host/admin/login/openid-callback"
export OPENID_SCOPES="openid profile email"
export OPENID_SESSION_TIMEOUT_MINUTES="60"
```

Refer to `config/openid_examples.conf` for provider-specific examples.

### 3. Initialize Auth in main.py

In your application startup (usually in `main.py`):

```python
from tacacs_server.web.openid_auth import OpenIDConfig
from tacacs_server.web.web_auth import init_auth
import os

# Build OpenID config if env vars present
openid_config = None
if os.getenv("OPENID_ISSUER_URL"):
    openid_config = OpenIDConfig(
        issuer_url=os.getenv("OPENID_ISSUER_URL"),
        client_id=os.getenv("OPENID_CLIENT_ID"),
        client_secret=os.getenv("OPENID_CLIENT_SECRET"),
        redirect_uri=os.getenv("OPENID_REDIRECT_URI"),
        scopes=os.getenv("OPENID_SCOPES", "openid profile email"),
        session_timeout_minutes=int(os.getenv("OPENID_SESSION_TIMEOUT_MINUTES", "60"))
    )

# Initialize auth with both password and OpenID support
init_auth(
    admin_username="admin",
    admin_password_hash="$2b$12$...",  # bcrypt hash
    api_token=os.getenv("API_TOKEN"),
    session_timeout=60,
    openid_config=openid_config
)
```

## Login Flow

### Password Login (Existing)
1. User enters username + password on `/admin/login`
2. Credentials verified via bcrypt
3. Session token created and stored in cookie

### OpenID Login (New)
1. User clicks "Sign in with OpenID" button
2. Redirected to `/admin/login/openid-start`
3. Server generates authorization URL with CSRF state
4. User redirected to OIDC provider
5. User authenticates with provider
6. Provider redirects to `/admin/login/openid-callback?code=...&state=...`
7. Server exchanges code for access token
8. Server fetches user info (email, name, etc.)
9. Session created with user's email as identifier
10. User redirected to `/admin/`

## Logging

All admin authentication events are logged with user email:

```
Admin session created via password
  event: admin.session.created
  user_email: admin
  auth_method: password

Admin session created via OpenID
  event: admin.session.created
  user_email: user@example.com
  auth_method: openid

Admin session deleted
  event: admin.session.deleted
  user_email: user@example.com
```

### Tracking Concurrent Users

Each session token uniquely identifies one user. Multiple logins by the same user create separate sessions:

**Session Storage** (in-memory dict):
```
session_token_1 → (expiry_time, "alice@example.com")
session_token_2 → (expiry_time, "bob@example.com")
session_token_3 → (expiry_time, "alice@example.com")  # Different session, same user
```

Logs will show both `user_email` for identification and opaque `session_id` for grouping requests.

## API Endpoints

### Password Login
- `GET /admin/login` - Show login form
- `POST /admin/login` - Process password login

### OpenID Login
- `GET /admin/login/openid-start` - Initiate OIDC flow
- `GET /admin/login/openid-callback` - Handle provider callback

### Session Management
- `POST /admin/logout` - Delete session cookie
- `GET /admin/*` - Protected routes (checks session via `require_admin_session`)

## Error Handling

**Missing OpenID Config**
```
HTTP 503: OpenID not configured
```

**CSRF State Mismatch**
```
HTTP 401: OpenID state validation failed
(Logged as possible CSRF attack)
```

**Token Exchange Failed**
```
HTTP 401: OpenID authentication failed
(Logged with specific error from provider)
```

**Missing Email in User Info**
```
HTTP 401: Authentication failed
(User info must include 'email' claim)
```

## Session Timeout & Refresh

- Sessions expire after configured timeout (default 60 minutes)
- Expired sessions are automatically cleaned up on validation
- No refresh token support - users must re-login after expiry
- Cookie is httponly, secure, and samesite=strict

## Security Considerations

✅ **CSRF Protection**: State parameter validated on callback  
✅ **Secure Cookies**: httponly, secure flag, samesite=strict  
✅ **No Shared Secrets Logged**: Access tokens never logged  
✅ **Email-based Identification**: No local user database needed  
✅ **In-memory Sessions**: No persistent storage of user tokens  

⚠️ **Limitations**:
- In-memory sessions lost on server restart
- No session sharing across multiple server instances
- State tokens not persisted (requires `request.session` middleware)

For production multi-instance deployments, consider:
- Using Redis for distributed session storage
- Implementing state token validation against database
- Adding session cleanup task

## Testing

```bash
# 1. Start server with OpenID config
export OPENID_ISSUER_URL="..."
python -m tacacs_server.main

# 2. Navigate to login
curl https://localhost/admin/login

# 3. Click "Sign in with OpenID" (browser)
# 4. Complete provider authentication
# 5. Check logs for session creation with user_email

# 6. Verify session works
curl -b "admin_session=<token>" https://localhost/admin/

# 7. Logout
curl -X POST https://localhost/admin/logout
```

## Troubleshooting

### "OpenID endpoints not discovered"
- Check OPENID_ISSUER_URL is correct
- Verify `.well-known/openid-configuration` is accessible
- Check firewall/proxy rules

### "User info missing 'email' claim"
- Verify scopes include `email`
- Check provider config returns email in userinfo endpoint
- Some providers need explicit email scope

### State validation failures
- Ensure request.session middleware is enabled (for cookie-based state)
- Check state is generated and stored in same request
- Verify cookies are enabled in browser

### Session not created
- Check logs for specific token exchange errors
- Verify client_id and client_secret are correct
- Test callback URL is publicly accessible

## Files Modified

- `tacacs_server/web/openid_auth.py` - NEW (Phase 1)
- `tacacs_server/web/web_auth.py` - UPDATED (Phase 2)
- `tacacs_server/web/web_admin.py` - UPDATED (Phase 3/4)
- `tacacs_server/templates/admin/login.html` - UPDATED (Phase 3/4)
- `config/openid_examples.conf` - NEW (Phase 4)

## Next Steps

1. ✅ Phase 1: Created `openid_auth.py`
2. ✅ Phase 2: Updated `web_auth.py` with OpenID support
3. ✅ Phase 3: Added OpenID routes to `web_admin.py`
4. ✅ Phase 4: Updated login template and created config examples

Ready for:
- Integration with main.py initialization
- Testing with your OIDC provider
- Production deployment
