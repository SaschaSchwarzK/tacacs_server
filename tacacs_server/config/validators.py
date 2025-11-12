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
        config_dict: dict[str, dict[str, Any]] = {
            "server": dict(config["server"]),
            "auth": dict(config["auth"]),
            "security": dict(config["security"]),
        }
        
        if "ldap" in config:
            config_dict["ldap"] = dict(config["ldap"])
        if "okta" in config:
            config_dict["okta"] = dict(config["okta"])
        
        validated: TacacsConfigSchema = validate_config_file(config_dict)
        logger.info("✓ Configuration validation passed")
        
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
        
    except ValueError as exc:
        logger.error("✗ Configuration validation failed: %s", exc)
        issues.append(str(exc))
    
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
        if backend not in ["local", "ldap", "okta"]:
            issues.append(f"Unknown authentication backend: {backend}")
    
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


def validate_change(
    config: configparser.ConfigParser,
    section: str,
    key: str,
    value: Any
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
    
    # 2) Schema validation
    try:
        validate_config_file({
            "server": payload.get("server", {}),
            "auth": payload.get("auth", {}),
            "security": payload.get("security", {}),
            **({"ldap": payload.get("ldap", {})} if "ldap" in payload else {}),
            **({"okta": payload.get("okta", {})} if "okta" in payload else {}),
            **({"backup": payload.get("backup", {})} if "backup" in payload else {}),
        })
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
            valid = {"local", "ldap", "okta"}
            for b in backends:
                if b not in valid:
                    issues.append(f"Unknown backend: {b}")
        except Exception:
            issues.append("Invalid backends format")
    
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


def validate_section(
    config: configparser.ConfigParser,
    section: str
) -> list[str]:
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
