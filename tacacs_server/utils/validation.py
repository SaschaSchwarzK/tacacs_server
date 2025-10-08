"""
Comprehensive input validation utilities for TACACS+ server.
Provides centralized validation to prevent injection attacks and ensure data integrity.
"""

import ipaddress
import re
import string
from typing import Any
from urllib.parse import urlparse

from .exceptions import ValidationError


class InputValidator:
    """Centralized input validation with security-focused checks."""

    # Regex patterns for common validations
    USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
    HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    # Character sets for validation
    SAFE_CHARS = set(string.ascii_letters + string.digits + "_.-")
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|#|/\*|\*/)",
        r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
        r"(\'\s*(OR|AND)\s+\'\w+\'\s*=\s*\'\w+\')",
    ]
    LDAP_INJECTION_CHARS = ["*", "(", ")", "\\", "/", "\x00"]

    @classmethod
    def validate_username(cls, username: str) -> str:
        """Validate username format and security."""
        if not username:
            raise ValidationError("Username is required")

        username = username.strip()
        if not username:
            raise ValidationError("Username cannot be empty")

        if len(username) > 64:
            raise ValidationError("Username must be 64 characters or less")

        if not cls.USERNAME_PATTERN.match(username):
            raise ValidationError(
                "Username can only contain letters, numbers, underscore, dot, and dash"
            )

        # Check for SQL injection patterns
        cls._check_sql_injection(username, "username")

        return username

    @classmethod
    def validate_password(cls, password: str, min_length: int = 8) -> str:
        """Validate password strength and security."""
        if not password:
            raise ValidationError("Password is required")

        if len(password) < min_length:
            raise ValidationError(f"Password must be at least {min_length} characters")

        if len(password) > 128:
            raise ValidationError("Password must be 128 characters or less")

        # Check for basic complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)

        if not (has_upper and has_lower and has_digit):
            raise ValidationError(
                "Password must contain uppercase, lowercase, and numeric characters"
            )

        return password

    @classmethod
    def validate_network(cls, network: str) -> ipaddress._BaseNetwork:
        """Validate IP network format."""
        if not network:
            raise ValidationError("Network is required")

        network = network.strip()
        try:
            return ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            raise ValidationError(f"Invalid network format: {e}")

    @classmethod
    def validate_ip_address(cls, ip_addr: str) -> ipaddress._BaseAddress:
        """Validate IP address format."""
        if not ip_addr:
            raise ValidationError("IP address is required")

        ip_addr = ip_addr.strip()
        try:
            return ipaddress.ip_address(ip_addr)
        except ValueError as e:
            raise ValidationError(f"Invalid IP address: {e}")

    @classmethod
    def validate_hostname(cls, hostname: str) -> str:
        """Validate hostname format."""
        if not hostname:
            raise ValidationError("Hostname is required")

        hostname = hostname.strip().lower()
        if len(hostname) > 253:
            raise ValidationError("Hostname too long")

        if not cls.HOSTNAME_PATTERN.match(hostname):
            raise ValidationError("Invalid hostname format")

        return hostname

    @classmethod
    def validate_port(cls, port: str | int) -> int:
        """Validate port number."""
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            raise ValidationError("Port must be a number")

        if not (1 <= port_num <= 65535):
            raise ValidationError("Port must be between 1 and 65535")

        return port_num

    @classmethod
    def validate_privilege_level(cls, level: str | int) -> int:
        """Validate TACACS+ privilege level."""
        try:
            level_num = int(level)
        except (ValueError, TypeError):
            raise ValidationError("Privilege level must be a number")

        if not (0 <= level_num <= 15):
            raise ValidationError("Privilege level must be between 0 and 15")

        return level_num

    @classmethod
    def validate_string_length(
        cls, value: str, field_name: str, min_len: int = 0, max_len: int = 255
    ) -> str:
        """Validate string length constraints."""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name} must be a string")

        if len(value) < min_len:
            raise ValidationError(f"{field_name} must be at least {min_len} characters")

        if len(value) > max_len:
            raise ValidationError(f"{field_name} must be {max_len} characters or less")

        return value

    @classmethod
    def validate_secret(cls, secret: str, field_name: str = "secret") -> str:
        """Validate shared secret format and strength."""
        if not secret:
            raise ValidationError(f"{field_name} is required")

        secret = secret.strip()
        if len(secret) < 8:
            raise ValidationError(f"{field_name} must be at least 8 characters")

        if len(secret) > 128:
            raise ValidationError(f"{field_name} must be 128 characters or less")

        # Check for SQL injection patterns
        cls._check_sql_injection(secret, field_name)

        return secret

    @classmethod
    def validate_email(cls, email: str) -> str:
        """Validate email address format."""
        if not email:
            raise ValidationError("Email is required")

        email = email.strip().lower()
        if not cls.EMAIL_PATTERN.match(email):
            raise ValidationError("Invalid email format")

        return email

    @classmethod
    def validate_url(cls, url: str) -> str:
        """Validate URL format and security."""
        if not url:
            raise ValidationError("URL is required")

        url = url.strip()
        try:
            parsed = urlparse(url)
        except Exception:
            raise ValidationError("Invalid URL format")

        if not parsed.scheme:
            raise ValidationError("URL must include scheme (http/https)")

        if parsed.scheme not in ["http", "https"]:
            raise ValidationError("URL scheme must be http or https")

        if not parsed.netloc:
            raise ValidationError("URL must include hostname")

        return url

    @classmethod
    def validate_json_dict(cls, data: Any, field_name: str = "data") -> dict[str, Any]:
        """Validate JSON dictionary input."""
        if data is None:
            return {}

        if not isinstance(data, dict):
            raise ValidationError(f"{field_name} must be a JSON object")

        # Check for deeply nested structures (DoS protection)
        cls._check_json_depth(data, field_name)

        return data

    @classmethod
    def validate_string_list(cls, items: Any, field_name: str = "items") -> list[str]:
        """Validate list of strings."""
        if items is None:
            return []

        if isinstance(items, str):
            # Handle comma-separated strings
            items = [item.strip() for item in items.split(",")]

        if not isinstance(items, list):
            raise ValidationError(f"{field_name} must be a list")

        result = []
        for item in items:
            if not isinstance(item, str):
                raise ValidationError(f"All {field_name} must be strings")

            item = item.strip()
            if not item:
                continue  # Skip empty strings

            if len(item) > 255:
                raise ValidationError(
                    f"{field_name} entries must be 255 characters or less"
                )

            # Check for injection patterns
            cls._check_sql_injection(item, f"{field_name} entry")
            cls._check_ldap_injection(item, f"{field_name} entry")

            if item not in result:
                result.append(item)

        return result

    @classmethod
    def sanitize_log_input(cls, value: str) -> str:
        """Sanitize input for safe logging (prevent log injection)."""
        if not isinstance(value, str):
            return str(value)

        # Remove control characters and newlines
        sanitized = "".join(char for char in value if ord(char) >= 32 or char in ["\t"])

        # Truncate if too long
        if len(sanitized) > 1000:
            sanitized = sanitized[:997] + "..."

        return sanitized

    @classmethod
    def validate_ldap_filter(cls, filter_str: str) -> str:
        """Validate LDAP filter to prevent injection."""
        if not filter_str:
            raise ValidationError("LDAP filter is required")

        # Check for LDAP injection characters
        cls._check_ldap_injection(filter_str, "LDAP filter")

        # Basic LDAP filter format validation
        if not (filter_str.startswith("(") and filter_str.endswith(")")):
            raise ValidationError("LDAP filter must be enclosed in parentheses")

        return filter_str

    @classmethod
    def _check_sql_injection(cls, value: str, field_name: str) -> None:
        """Check for SQL injection patterns."""
        value_upper = value.upper()

        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                raise ValidationError(
                    f"{field_name} contains potentially unsafe characters"
                )

    @classmethod
    def _check_ldap_injection(cls, value: str, field_name: str) -> None:
        """Check for LDAP injection characters."""
        for char in cls.LDAP_INJECTION_CHARS:
            if char in value:
                raise ValidationError(
                    f"{field_name} contains invalid character: {char}"
                )

    @classmethod
    def _check_json_depth(
        cls, data: Any, field_name: str, max_depth: int = 10, current_depth: int = 0
    ) -> None:
        """Check JSON nesting depth to prevent DoS attacks."""
        if current_depth > max_depth:
            raise ValidationError(f"{field_name} is nested too deeply")

        if isinstance(data, dict):
            for value in data.values():
                cls._check_json_depth(value, field_name, max_depth, current_depth + 1)
        elif isinstance(data, list):
            for item in data:
                cls._check_json_depth(item, field_name, max_depth, current_depth + 1)


class FormValidator:
    """Specialized validator for web form inputs."""

    @classmethod
    def validate_device_form(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Validate device creation/update form."""
        validated: dict[str, Any] = {}

        if "name" in data:
            validated["name"] = InputValidator.validate_string_length(
                data["name"].strip(), "device name", min_len=1, max_len=64
            )

        if "network" in data:
            validated["network"] = str(InputValidator.validate_network(data["network"]))

        if "group" in data and data["group"]:
            validated["group"] = InputValidator.validate_string_length(
                data["group"].strip(), "group name", min_len=1, max_len=64
            )

        return validated

    @classmethod
    def validate_user_form(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Validate user creation/update form."""
        validated: dict[str, Any] = {}

        if "username" in data:
            validated["username"] = InputValidator.validate_username(data["username"])

        if "password" in data and data["password"]:
            validated["password"] = InputValidator.validate_password(data["password"])

        if "privilege_level" in data:
            validated["privilege_level"] = InputValidator.validate_privilege_level(
                data["privilege_level"]
            )

        if "service" in data:
            validated["service"] = InputValidator.validate_string_length(
                data["service"], "service", min_len=1, max_len=32
            )

        if "shell_command" in data:
            validated["shell_command"] = InputValidator.validate_string_list(
                data["shell_command"], "shell_command"
            )

        if "groups" in data:
            validated["groups"] = InputValidator.validate_string_list(
                data["groups"], "groups"
            )

        if "enabled" in data:
            validated["enabled"] = bool(data["enabled"])

        if "description" in data:
            validated["description"] = InputValidator.validate_string_length(
                data["description"], "description", max_len=500
            )

        return validated

    @classmethod
    def validate_group_form(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Validate device group creation/update form."""
        validated: dict[str, Any] = {}

        if "name" in data:
            validated["name"] = InputValidator.validate_string_length(
                data["name"].strip(), "group name", min_len=1, max_len=64
            )

        if "description" in data:
            validated["description"] = InputValidator.validate_string_length(
                data["description"], "description", max_len=500
            )

        if "tacacs_secret" in data and data["tacacs_secret"]:
            validated["tacacs_secret"] = InputValidator.validate_secret(
                data["tacacs_secret"], "TACACS+ secret"
            )

        if "radius_secret" in data and data["radius_secret"]:
            validated["radius_secret"] = InputValidator.validate_secret(
                data["radius_secret"], "RADIUS secret"
            )

        if "allowed_user_groups" in data:
            validated["allowed_user_groups"] = InputValidator.validate_string_list(
                data["allowed_user_groups"], "allowed_user_groups"
            )

        if "tacacs_profile" in data:
            validated["tacacs_profile"] = InputValidator.validate_json_dict(
                data["tacacs_profile"], "tacacs_profile"
            )

        if "radius_profile" in data:
            validated["radius_profile"] = InputValidator.validate_json_dict(
                data["radius_profile"], "radius_profile"
            )

        if "metadata" in data:
            validated["metadata"] = InputValidator.validate_json_dict(
                data["metadata"], "metadata"
            )

        return validated


def validate_api_input(validator_func):
    """Decorator to validate API input using specified validator function."""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Find the payload in kwargs
            if "payload" in kwargs:
                try:
                    kwargs["payload"] = validator_func(kwargs["payload"])
                except ValidationError as e:
                    from fastapi import HTTPException, status

                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
                    )
            return await func(*args, **kwargs)

        return wrapper

    return decorator
