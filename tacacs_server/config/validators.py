"""Configuration validation functions.

Provides validation for configuration values at various levels:
- Full configuration validation
- Section validation
- Single change validation
"""

import configparser
import os
from typing import Any

from tacacs_server.utils.logger import get_logger

from .getters import get_openid_config
from .schema import TacacsConfigSchema, validate_config_file

logger = get_logger(__name__)


def validate_config(config: configparser.ConfigParser) -> list[str]:
    """Validate full configuration and return list of issues.

    Args:
        config: ConfigParser instance to validate

    Returns:
        List of validation issue strings (empty if valid)
    """
    issues = []

    try:
        # Base sections always validated
        config_dict: dict[str, dict[str, Any]] = {
            "server": dict(config["server"]),
            "auth": dict(config["auth"]),
            "security": dict(config["security"]),
        }

        # Determine which backends are enabled to avoid validating unused sections
        try:
            backends = [
                b.strip().lower()
                for b in config.get("auth", "backends", fallback="local").split(",")
                if b.strip()
            ]
        except Exception:
            backends = ["local"]

        # Include LDAP section only when ldap backend is enabled
        if "ldap" in backends and "ldap" in config:
            config_dict["ldap"] = dict(config["ldap"])
        # Include Okta section only when okta backend is enabled
        if "okta" in backends and "okta" in config:
            config_dict["okta"] = dict(config["okta"])
        # Radius auth section is validated conditionally inside the schema
        if "radius_auth" in config:
            config_dict["radius_auth"] = dict(config["radius_auth"])
        # Global MFA defaults (optional)
        if "mfa" in config:
            config_dict["mfa"] = dict(config["mfa"])

        validated: TacacsConfigSchema = validate_config_file(config_dict)

        # Directory existence checks
        auth_db_path = validated.auth.local_auth_db
        auth_db_dir = os.path.dirname(auth_db_path)
        if auth_db_dir and not os.path.exists(auth_db_dir):
            issues.append(
                f"Local auth database directory does not exist: {auth_db_dir}"
            )

        db_file = config.get("database", "accounting_db")
        db_dir = os.path.dirname(db_file)
        if db_dir and not os.path.exists(db_dir):
            issues.append(f"Database directory does not exist: {db_dir}")

        # Additional validation checks
        issues.extend(_validate_server_config(config))
        issues.extend(_validate_auth_config(config))
        issues.extend(_validate_security_config(config))
        issues.extend(_validate_openid_config(config))

    except ValueError as exc:
        logger.error(
            "✗ Configuration validation failed: %s",
            exc,
            event="tacacs.config.validation.failed",
            service="tacacs",
        )
        issues.append(str(exc))

    if not issues:
        logger.info(
            "✓ Configuration validation passed",
            event="tacacs.config.validation.passed",
            service="tacacs",
        )

    return issues


def _validate_server_config(config: configparser.ConfigParser) -> list[str]:
    """Validate server configuration section."""
    issues = []

    # Port validation
    port = config.getint("server", "port")
    if port < 1 or port > 65535:
        issues.append(f"Invalid server port: {port} (must be 1-65535)")

    # Connection limits
    max_conn = config.getint("server", "max_connections")
    if max_conn < 1 or max_conn > 1000:
        issues.append(f"Invalid max_connections: {max_conn} (must be 1-1000)")

    return issues


def _validate_auth_config(config: configparser.ConfigParser) -> list[str]:
    """Validate authentication configuration section."""
    issues = []

    # Backend validation
    backends_str = config.get("auth", "backends", fallback="local")
    backends = [b.strip().lower() for b in backends_str.split(",") if b.strip()]

    if not backends:
        issues.append("No authentication backends configured")

    for backend in backends:
        if backend not in ["local", "ldap", "okta", "radius"]:
            issues.append(f"Unknown authentication backend: {backend}")

    # When radius auth backend selected, ensure section exists and minimally valid
    if "radius" in backends:
        if "radius_auth" not in config:
            issues.append("Radius backend selected but [radius_auth] section missing")
        else:
            sec = config["radius_auth"]
            if not sec.get("radius_server", "").strip():
                issues.append("[radius_auth].radius_server is required")
            try:
                port = int(sec.get("radius_port", "1812"))
                if port < 1 or port > 65535:
                    issues.append("[radius_auth].radius_port must be 1-65535")
            except Exception:
                issues.append("[radius_auth].radius_port must be an integer")
            secret = sec.get("radius_secret", "").strip()
            if len(secret) < 8:
                issues.append(
                    "[radius_auth].radius_secret must be at least 8 characters"
                )
            try:
                timeout = int(sec.get("radius_timeout", "5"))
                if timeout < 1 or timeout > 60:
                    issues.append("[radius_auth].radius_timeout must be 1-60 seconds")
            except Exception:
                issues.append("[radius_auth].radius_timeout must be an integer")
            try:
                retries = int(sec.get("radius_retries", "3"))
                if retries < 0 or retries > 10:
                    issues.append("[radius_auth].radius_retries must be 0-10")
            except Exception:
                issues.append("[radius_auth].radius_retries must be an integer")
            # MFA tuning (optional)
            try:
                digits = int(sec.get("mfa_otp_digits", "6"))
                if digits < 4 or digits > 10:
                    issues.append("[radius_auth].mfa_otp_digits must be 4-10 digits")
            except Exception:
                issues.append("[radius_auth].mfa_otp_digits must be an integer")
            try:
                poll = float(sec.get("mfa_poll_interval", "2.0"))
                timeout = float(sec.get("mfa_timeout_seconds", "25"))
                if poll <= 0:
                    issues.append("[radius_auth].mfa_poll_interval must be positive")
                if timeout < 1:
                    issues.append("[radius_auth].mfa_timeout_seconds must be at least 1")
                if poll >= timeout:
                    issues.append(
                        "[radius_auth].mfa_poll_interval must be less than mfa_timeout_seconds"
                    )
            except Exception:
                issues.append("Invalid mfa_poll_interval or mfa_timeout_seconds value")

    # Database file validation
    auth_db = config.get("auth", "local_auth_db", fallback="")
    if not auth_db:
        issues.append("Local auth database path not configured")

    return issues


def _validate_security_config(config: configparser.ConfigParser) -> list[str]:
    """Validate security configuration section."""
    issues = []

    # Auth attempts validation
    max_attempts = config.getint("security", "max_auth_attempts")
    if max_attempts < 1 or max_attempts > 10:
        issues.append(f"Invalid max_auth_attempts: {max_attempts} (must be 1-10)")

    # Timeout validation
    timeout = config.getint("security", "auth_timeout")
    if timeout < 30 or timeout > 3600:
        issues.append(f"Invalid auth_timeout: {timeout} (must be 30-3600 seconds)")

    # Per-IP connection cap validation
    try:
        cap = config.getint("security", "max_connections_per_ip")
    except Exception:
        cap = 20
    if cap < 1 or cap > 1000:
        issues.append(f"Invalid max_connections_per_ip: {cap} (must be 1-1000)")

    return issues


def _validate_openid_config(config: configparser.ConfigParser) -> list[str]:
    """Validate OpenID Connect configuration; returns warnings/issues (non-fatal)."""
    issues: list[str] = []
    try:
        cfg = get_openid_config(config) or {}
    except Exception:
        return issues

    # Consider OpenID enabled only when required fields are present
    required_present = bool(
        cfg.get("issuer_url") and cfg.get("client_id") and cfg.get("redirect_uri")
    )
    if not required_present:
        return issues

    if cfg.get("client_auth_method") == "client_secret" and not cfg.get(
        "client_secret"
    ):
        issues.append(
            "OpenID: client_secret auth selected but OPENID_CLIENT_SECRET is missing"
        )
    if cfg.get("client_auth_method") == "private_key_jwt" and not cfg.get(
        "client_private_key"
    ):
        issues.append(
            "OpenID: private_key_jwt auth selected but OPENID_CLIENT_PRIVATE_KEY is missing"
        )
    if cfg.get("use_interaction_code") and not cfg.get("code_verifier"):
        issues.append(
            "OpenID: interaction_code enabled but OPENID_CODE_VERIFIER is missing"
        )

    # Non-fatal warnings (e.g., unused secrets) are logged in getters; do not block startup/tests here.
    return issues


def validate_change(
    config: configparser.ConfigParser, section: str, key: str, value: Any
) -> tuple[bool, list[str]]:
    """Validate a single configuration change against the schema and custom rules.

    Args:
        config: Current ConfigParser instance
        section: Section name to update
        key: Key name to update
        value: New value

    Returns:
        Tuple of (is_valid, issues_list)
    """
    issues: list[str] = []

    # 1) Build a temporary payload with proposed change
    payload: dict[str, dict[str, str]] = {}
    for sec in config.sections():
        payload[sec] = dict(config.items(sec))

    sec_dict = payload.setdefault(section, {})
    sec_dict[key] = str(value)

    # 2) Schema validation (include only sections relevant to enabled backends)
    try:
        # Determine enabled backends from the (possibly modified) payload
        try:
            auth_section = payload.get("auth", {})
            backends = [
                b.strip().lower()
                for b in str(auth_section.get("backends", "local")).split(",")
                if b.strip()
            ]
        except Exception:
            backends = ["local"]

        schema_payload: dict[str, dict[str, Any]] = {
            "server": payload.get("server", {}),
            "auth": payload.get("auth", {}),
            "security": payload.get("security", {}),
        }
        # Only include LDAP if enabled or if the change targets LDAP section
        if ("ldap" in backends) or (section == "ldap"):
            if "ldap" in payload:
                schema_payload["ldap"] = payload.get("ldap", {})
        # Only include Okta if enabled or if the change targets Okta section
        if ("okta" in backends) or (section == "okta"):
            if "okta" in payload:
                schema_payload["okta"] = payload.get("okta", {})
        # Radius section can be present; schema enforces requireds only when enabled
        if "radius_auth" in payload:
            schema_payload["radius_auth"] = payload.get("radius_auth", {})
        # Global MFA defaults
        if "mfa" in payload:
            schema_payload["mfa"] = payload.get("mfa", {})
        # Optional backup section
        if "backup" in payload:
            schema_payload["backup"] = payload.get("backup", {})

        validate_config_file(schema_payload)
    except Exception as e:
        issues.append(str(e))
        return False, issues

    # 3) Custom validation rules
    if section == "server" and key == "port":
        try:
            port_int = int(value)
            if not (1 <= port_int <= 65535):
                issues.append("Port out of valid range (1-65535)")
            elif not _is_port_available(port_int):
                issues.append(f"Port {port_int} is already in use")
        except Exception:
            issues.append("Port must be an integer")

    if section == "auth" and key == "backends":
        try:
            backends = [b.strip().lower() for b in str(value).split(",") if b.strip()]
            valid = {"local", "ldap", "okta", "radius"}
            for b in backends:
                if b not in valid:
                    issues.append(f"Unknown backend: {b}")
        except Exception:
            issues.append("Invalid backends format")

    # radius_auth section validation
    if section == "radius_auth":
        k = key.lower()
        if k == "radius_port":
            try:
                port_int = int(value)
                if port_int < 1 or port_int > 65535:
                    issues.append("radius_port must be 1-65535")
            except Exception:
                issues.append("radius_port must be an integer")
        elif k == "radius_secret":
            if not str(value).strip() or len(str(value).strip()) < 8:
                issues.append("radius_secret must be at least 8 characters")
            if len(str(value)) > 128:
                issues.append("radius_secret must be 128 characters or less")
        elif k == "radius_timeout":
            try:
                t = int(value)
                if t < 1 or t > 60:
                    issues.append("radius_timeout must be 1-60")
            except Exception:
                issues.append("radius_timeout must be an integer")
        elif k == "radius_retries":
            try:
                r = int(value)
                if r < 0 or r > 10:
                    issues.append("radius_retries must be 0-10")
            except Exception:
                issues.append("radius_retries must be an integer")
        elif k == "radius_nas_ip":
            sval = str(value).strip()
            # Allow empty -> default, or validate IPv4 literal
            if sval:
                try:
                    import ipaddress

                    ipaddress.IPv4Address(sval)
                except ValueError:
                    issues.append("radius_nas_ip must be a valid IPv4 address")
        elif k == "mfa_enabled":
            sval = str(value).lower()
            if sval not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
                issues.append("mfa_enabled must be a boolean value")
        elif k == "mfa_otp_digits":
            try:
                digits = int(value)
                if digits < 4 or digits > 10:
                    issues.append("mfa_otp_digits must be between 4 and 10")
            except Exception:
                issues.append("mfa_otp_digits must be an integer")
        elif k == "mfa_timeout_seconds":
            try:
                timeout = int(value)
                if timeout < 1 or timeout > 300:
                    issues.append("mfa_timeout_seconds must be 1-300")
                else:
                    poll = config.getfloat(
                        "radius_auth", "mfa_poll_interval", fallback=2.0
                    )
                    if poll >= timeout:
                        issues.append(
                            "mfa_poll_interval must be less than mfa_timeout_seconds"
                        )
            except Exception:
                issues.append("mfa_timeout_seconds must be an integer")
        elif k == "mfa_poll_interval":
            try:
                poll = float(value)
                if poll <= 0:
                    issues.append("mfa_poll_interval must be greater than 0")
                else:
                    timeout = config.getfloat(
                        "radius_auth", "mfa_timeout_seconds", fallback=25.0
                    )
                    if poll >= timeout:
                        issues.append(
                            "mfa_poll_interval must be less than mfa_timeout_seconds"
                        )
            except Exception:
                issues.append("mfa_poll_interval must be a number")
    # global mfa section validation
    if section == "mfa":
        k = key.lower()
        if k == "mfa_enabled":
            sval = str(value).lower()
            if sval not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
                issues.append("mfa_enabled must be a boolean value")
        elif k == "mfa_otp_digits":
            try:
                digits = int(value)
                if digits < 4 or digits > 10:
                    issues.append("mfa_otp_digits must be between 4 and 10")
            except Exception:
                issues.append("mfa_otp_digits must be an integer")
        elif k == "mfa_timeout_seconds":
            try:
                timeout = int(value)
                if timeout < 1 or timeout > 300:
                    issues.append("mfa_timeout_seconds must be 1-300")
                else:
                    poll = config.getfloat("mfa", "mfa_poll_interval", fallback=2.0)
                    if poll >= timeout:
                        issues.append(
                            "mfa_poll_interval must be less than mfa_timeout_seconds"
                        )
            except Exception:
                issues.append("mfa_timeout_seconds must be an integer")
        elif k == "mfa_poll_interval":
            try:
                poll = float(value)
                if poll <= 0:
                    issues.append("mfa_poll_interval must be greater than 0")
                else:
                    timeout = config.getfloat("mfa", "mfa_timeout_seconds", fallback=25)
                    if poll >= timeout:
                        issues.append(
                            "mfa_poll_interval must be less than mfa_timeout_seconds"
                        )
            except Exception:
                issues.append("mfa_poll_interval must be a number")

    # Devices custom validation
    if section == "devices":
        if key == "auto_register":
            sval = str(value).lower()
            if sval not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
                issues.append("auto_register must be boolean")
        elif key == "default_group":
            if not str(value).strip():
                issues.append("default_group cannot be empty")
        elif key in ("identity_cache_ttl_seconds", "identity_cache_size"):
            try:
                _ = int(value)
            except Exception:
                issues.append(f"{key} must be an integer")

    # Command authorization custom validation
    if section == "command_authorization" and key == "privilege_check_order":
        sval = str(value).strip().lower()
        if sval not in ("before", "after", "none"):
            issues.append("privilege_check_order must be one of: before, after, none")

    return (len(issues) == 0), issues


def _is_port_available(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is available for binding."""
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, int(port)))
            except OSError:
                return False
        return True
    except Exception:
        return False


def validate_section(config: configparser.ConfigParser, section: str) -> list[str]:
    """Validate a specific configuration section.

    Args:
        config: ConfigParser instance
        section: Section name to validate

    Returns:
        List of validation issues for this section
    """
    if section == "server":
        return _validate_server_config(config)
    elif section == "auth":
        return _validate_auth_config(config)
    elif section == "security":
        return _validate_security_config(config)
    else:
        # Generic validation - just check it exists
        if not config.has_section(section):
            return [f"Section '{section}' does not exist"]
        return []
