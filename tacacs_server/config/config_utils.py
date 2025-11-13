"""Configuration utility functions.

Provides helper functions used across configuration modules.
"""

import configparser
import os
from typing import Any


def parse_size(size_str: str) -> int:
    """Parse human readable size strings like '10MB' -> bytes.

    Args:
        size_str: Size string (e.g., '10MB', '1GB', '512KB')

    Returns:
        Size in bytes

    Examples:
        >>> parse_size('10MB')
        10485760
        >>> parse_size('1GB')
        1073741824
    """
    try:
        s = size_str.strip().upper()
        if s.endswith("KB"):
            return int(float(s[:-2]) * 1024)
        if s.endswith("MB"):
            return int(float(s[:-2]) * 1024 * 1024)
        if s.endswith("GB"):
            return int(float(s[:-2]) * 1024 * 1024 * 1024)
        return int(s)
    except Exception:
        return 10 * 1024 * 1024  # Default 10MB


def to_bool(val: object) -> bool:
    """Convert various types to boolean.

    Args:
        val: Value to convert

    Returns:
        Boolean value

    Examples:
        >>> to_bool('true')
        True
        >>> to_bool('0')
        False
        >>> to_bool(1)
        True
    """
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    s = str(val).strip().lower()
    return s in ("1", "true", "yes", "on")


def normalize_backend_name(item: Any) -> str:
    """Convert a backend entry to a backend name string.

    Handles:
      - "local" -> "local"
      - {"name": "local", ...} -> "local"
      - {"local": {...}} -> "local"
      - other -> str(item)

    Args:
        item: Backend entry (string or dict)

    Returns:
        Normalized backend name
    """
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        if "name" in item:
            return str(item["name"]).strip()
        if len(item) == 1:
            return str(next(iter(item.keys()))).strip()
        # fallback: try common keys
        for key in ("type", "backend"):
            if key in item:
                return str(item[key]).strip()
        return str(next(iter(item.keys()))).strip()
    return str(item)


def ensure_directory(path: str) -> bool:
    """Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path to ensure

    Returns:
        True if directory exists or was created, False on error
    """
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception:
        return False


def expand_path(path: str) -> str:
    """Expand environment variables and user home in path.

    Args:
        path: Path with potential variables

    Returns:
        Expanded path

    Examples:
        >>> expand_path('$HOME/data')
        '/home/user/data'
        >>> expand_path('~/config')
        '/home/user/config'
    """
    return os.path.expanduser(os.path.expandvars(path))


def merge_configs(
    base: configparser.ConfigParser, override: configparser.ConfigParser
) -> configparser.ConfigParser:
    """Merge two configurations, with override taking precedence.

    Args:
        base: Base configuration
        override: Override configuration

    Returns:
        New merged ConfigParser
    """
    result = configparser.ConfigParser(interpolation=None)

    # Copy base
    for section in base.sections():
        if not result.has_section(section):
            result.add_section(section)
        for key, value in base.items(section):
            result.set(section, key, value)

    # Apply overrides
    for section in override.sections():
        if not result.has_section(section):
            result.add_section(section)
        for key, value in override.items(section):
            result.set(section, key, value)

    return result


def section_to_dict(config: configparser.ConfigParser, section: str) -> dict[str, str]:
    """Convert a config section to a dictionary.

    Args:
        config: ConfigParser instance
        section: Section name

    Returns:
        Dictionary of key-value pairs
    """
    if not config.has_section(section):
        return {}
    return dict(config.items(section))


def compare_configs(
    config1: configparser.ConfigParser, config2: configparser.ConfigParser
) -> dict[str, dict[str, tuple[str, str]]]:
    """Compare two configurations and return differences.

    Args:
        config1: First configuration
        config2: Second configuration

    Returns:
        Dictionary of differences: {section: {key: (value1, value2)}}
    """
    differences: dict[str, dict[str, tuple[str, str]]] = {}

    # Check all sections in config1
    for section in config1.sections():
        if not config2.has_section(section):
            differences[section] = {k: (v, "") for k, v in config1.items(section)}
            continue

        # Compare keys in this section
        for key, value1 in config1.items(section):
            if config2.has_option(section, key):
                value2 = config2.get(section, key)
                if value1 != value2:
                    differences.setdefault(section, {})[key] = (value1, value2)
            else:
                differences.setdefault(section, {})[key] = (value1, "")

    # Check for sections/keys only in config2
    for section in config2.sections():
        if not config1.has_section(section):
            differences[section] = {k: ("", v) for k, v in config2.items(section)}
            continue

        for key, value2 in config2.items(section):
            if not config1.has_option(section, key):
                differences.setdefault(section, {})[key] = ("", value2)

    return differences


def safe_get(
    config: configparser.ConfigParser,
    section: str,
    key: str,
    default: str = "",
    value_type: type = str,
) -> Any:
    """Safely get a configuration value with type conversion.

    Args:
        config: ConfigParser instance
        section: Section name
        key: Key name
        default: Default value if key not found
        value_type: Type to convert to (str, int, float, bool)

    Returns:
        Value converted to requested type, or default on error
    """
    try:
        if not config.has_option(section, key):
            return default

        value = config.get(section, key)

        if value_type is bool:
            return to_bool(value)
        elif value_type is int:
            return int(value)
        elif value_type is float:
            return float(value)
        else:
            return value

    except Exception:
        return default
