# Authentication Service

## Overview
The Authentication Service handles all user authentication and session management for both TACACS+ protocol and web interface access.

## Key Components

### 1. Authentication Backends
- **Local Database**: SQLite-based user store
- **LDAP/Active Directory**: Enterprise directory integration
- **RADIUS**: Proxy authentication to RADIUS servers
- **TACACS+**: For proxy authentication scenarios

### 2. Session Management
- **Web Sessions**: JWT-based with configurable expiration
- **TACACS+ Sessions**: Stateful session tracking
- **API Tokens**: For programmatic access

## Runtime Behavior

### Initialization
1. Loads authentication configuration
2. Initializes selected backends
3. Sets up session storage
4. Configures rate limiting

### Authentication Flow
1. **Web Authentication**:
   - Validates credentials
   - Creates session token
   - Sets secure HTTP-only cookie
   
2. **TACACS+ Authentication**:
   - Handles protocol negotiation
   - Validates credentials against backends
   - Returns appropriate TACACS+ response

## Dependencies
- **Depends On**: Configuration Service
- **Required By**: Web Interface, TACACS+ Server

## Security Features
- Password hashing with bcrypt
- Account lockout after failed attempts
- Session fixation protection
- CSRF protection for web forms
- Rate limiting for authentication attempts
