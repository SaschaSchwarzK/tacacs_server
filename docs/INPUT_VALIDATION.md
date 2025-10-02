# Input Validation Security Implementation

This document describes the comprehensive input validation system implemented to address security vulnerabilities identified in the TACACS+ server codebase.

## Overview

The input validation system provides centralized, security-focused validation to prevent:
- SQL injection attacks
- LDAP injection attacks
- Cross-site scripting (XSS)
- Log injection attacks
- Buffer overflow attacks
- Weak password usage

## Components

### 1. Core Validation Module (`utils/validation.py`)

#### InputValidator Class
Provides static methods for validating common input types:

- **Username validation**: Alphanumeric + underscore/dot/dash, max 64 chars, SQL injection prevention
- **Password validation**: Minimum 8 chars, complexity requirements (upper/lower/digit), max 128 chars
- **Network validation**: Valid IP networks using `ipaddress` module
- **Privilege level validation**: Integer 0-15 for TACACS+ privilege levels
- **Secret validation**: Minimum 8 chars for shared secrets, SQL injection prevention
- **String list validation**: Comma-separated or array input, individual item validation
- **JSON validation**: Depth limiting to prevent DoS attacks
- **Log sanitization**: Control character removal, length limiting

#### FormValidator Class
Specialized validators for web form inputs:

- **Device forms**: Name, network, group validation
- **User forms**: Username, password, privilege, groups validation  
- **Group forms**: Name, secrets, allowed groups validation

#### Security Features
- SQL injection pattern detection using regex
- LDAP injection character filtering
- Input length limits to prevent buffer overflows
- JSON nesting depth limits to prevent DoS
- Log injection prevention through sanitization

### 2. Password Security Module (`utils/password_hash.py`)

#### PasswordHasher Class
Secure password hashing using bcrypt:

- **hash_password()**: Generate bcrypt hash with configurable rounds (default: 12)
- **verify_password()**: Verify password against bcrypt hash
- **needs_rehash()**: Check if hash needs upgrading (more rounds)

#### LegacyPasswordMigrator Class
Migration from weak SHA-256 to bcrypt:

- **is_legacy_hash()**: Detect SHA-256 hashes (64 hex chars)
- **verify_legacy_password()**: Verify against SHA-256 hash
- **migrate_password()**: Upgrade SHA-256 to bcrypt during authentication

#### Security Improvements
- Replaces weak SHA-256 with industry-standard bcrypt
- Automatic migration during user authentication
- Configurable work factor (rounds) for future-proofing
- Constant-time comparison to prevent timing attacks

### 3. SQL Security Module (`utils/sql_security.py`)

#### ParameterizedQuery Class
Secure SQL query building:

- **validate_identifier()**: Table/column name validation
- **validate_value()**: User input validation for SQL
- **build_select/insert/update/delete()**: Parameterized query builders

#### SecureDatabase Class
Database wrapper with built-in security:

- **execute_query()**: Parameterized query execution
- **select/insert/update/delete()**: High-level secure operations
- **Connection security**: Foreign key constraints, WAL mode

#### Security Features
- All queries use parameterized statements
- SQL identifier validation (table/column names)
- SQL injection pattern detection
- Dangerous keyword filtering
- Automatic parameter binding

### 4. Exception Handling (`utils/exceptions.py`)

#### ValidationError
New exception class for input validation failures:
- Consistent error handling across validation functions
- Clear error messages for debugging
- Proper exception chaining

## Integration Points

### Web Admin Interface (`web/admin/routers.py`)

All API endpoints now use input validation:

- **@validate_api_input decorator**: Automatic form validation
- **Path parameter validation**: Username/ID validation in URLs
- **Login endpoint**: Username/password validation
- **Log sanitization**: All logged user input is sanitized

### Authentication Backends

#### Local User Service (`auth/local_user_service.py`)
- Password strength validation using InputValidator
- Automatic bcrypt migration from SHA-256
- Username validation for all operations

#### LDAP Authentication (`auth/ldap_auth.py`)
- Username validation to prevent LDAP injection
- LDAP filter escaping using ldap3.utils.conv.escape_filter_chars()
- Input length limits

### Device Management (`devices/service.py`)
- Network validation using ipaddress module
- Device name and group name validation
- Secret validation for shared secrets

## Usage Examples

### Basic Input Validation
```python
from tacacs_server.utils.validation import InputValidator

# Validate username
username = InputValidator.validate_username("admin")

# Validate password with strength requirements
password = InputValidator.validate_password("SecurePass123")

# Validate network
network = InputValidator.validate_network("192.168.1.0/24")

# Validate privilege level
level = InputValidator.validate_privilege_level(15)
```

### Form Validation
```python
from tacacs_server.utils.validation import FormValidator

# Validate device creation form
device_data = FormValidator.validate_device_form({
    "name": "router1",
    "network": "10.0.0.0/24",
    "group": "routers"
})
```

### Secure Password Hashing
```python
from tacacs_server.utils.password_hash import PasswordHasher

# Hash password
hashed = PasswordHasher.hash_password("SecurePass123")

# Verify password
is_valid = PasswordHasher.verify_password("SecurePass123", hashed)
```

### SQL Security
```python
from tacacs_server.utils.sql_security import ParameterizedQuery

# Build secure SELECT query
query, params = ParameterizedQuery.build_select(
    "users", 
    ["username", "email"],
    {"active": True},
    order_by="username"
)
```

## Testing

Comprehensive test suite in `tests/test_input_validation.py`:

- 25 test cases covering all validation functions
- SQL injection attack prevention tests
- LDAP injection prevention tests
- Password strength validation tests
- Form validation tests
- Parameterized query building tests

Run tests with:
```bash
poetry run pytest tests/test_input_validation.py -v
```

## Security Benefits

1. **SQL Injection Prevention**: All database queries use parameterized statements
2. **LDAP Injection Prevention**: Username escaping and character filtering
3. **Strong Password Policy**: Bcrypt hashing with complexity requirements
4. **Input Sanitization**: Length limits, character filtering, pattern detection
5. **Log Injection Prevention**: Control character removal from logged data
6. **DoS Prevention**: JSON depth limits, input length limits
7. **Legacy Migration**: Automatic upgrade from weak SHA-256 to bcrypt

## Dependencies

Added to `pyproject.toml`:
- `bcrypt = "^4.0.0"` - Secure password hashing

## Configuration

### Password Policy
- Minimum length: 8 characters (configurable)
- Complexity: Must contain uppercase, lowercase, and numeric characters
- Maximum length: 128 characters

### Bcrypt Settings
- Default rounds: 12 (good balance of security and performance)
- Configurable work factor for future increases

### Input Limits
- Username: 64 characters max
- Secrets: 8-128 characters
- JSON nesting: 10 levels max
- Log entries: 1000 characters max

## Migration Guide

### Existing Installations

1. **Password Migration**: Automatic during user authentication
2. **Database Queries**: Existing queries should be updated to use ParameterizedQuery
3. **Form Handling**: Add @validate_api_input decorators to endpoints
4. **Logging**: Use InputValidator.sanitize_log_input() for user data

### Development

1. **New Endpoints**: Always use FormValidator for input validation
2. **Database Access**: Use SecureDatabase or ParameterizedQuery classes
3. **Password Handling**: Use PasswordHasher for all password operations
4. **User Input**: Validate all user input using InputValidator methods

This comprehensive input validation system significantly improves the security posture of the TACACS+ server by preventing common attack vectors and enforcing secure coding practices.