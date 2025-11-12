"""Configuration update functions.

Provides unified update mechanism for configuration sections with:
- Validation before update
- History tracking
- Override management
"""

import configparser
import json
import os
from typing import Any

from tacacs_server.utils.logger import get_logger

from .config_store import ConfigStore
from .validators import validate_change

logger = get_logger(__name__)


def update_section(
    config: configparser.ConfigParser,
    section: str,
    updates: dict[str, Any],
    config_store: ConfigStore | None = None,
    config_file: str | None = None,
    is_url_config: bool = False,
    **context
) -> None:
    """Update a configuration section with validation and history tracking.
    
    Args:
        config: ConfigParser instance to update
        section: Section name to update
        updates: Dictionary of key-value pairs to update
        config_store: Optional ConfigStore for override/history tracking
        config_file: Optional config file path for persistence
        is_url_config: Whether config is loaded from URL (no file save)
        **context: Additional context (reason, source_ip, etc.)
    """
    # Extract context hints
    reason = context.get("_change_reason")
    source_ip = context.get("_source_ip")
    
    # Capture previous values for history
    old_values: dict[str, str] = {
        k: config.get(section, k, fallback="") for k in updates.keys()
    }
    
    # Validate all changes
    for key, value in updates.items():
        is_valid, issues = validate_change(config, section, key, value)
        if not is_valid:
            raise ValueError(f"Validation failed: {'; '.join(issues)}")
    
    # Apply updates to config
    if not config.has_section(section):
        config.add_section(section)
    
    for key, value in updates.items():
        config.set(section, key, str(value))
    
    # Track in config store if available
    if config_store is not None:
        user = context.get("_user") or _get_current_user()
        
        for key, new_value in updates.items():
            vtype = _infer_type(new_value)
            
            # Set override
            try:
                config_store.set_override(
                    section=section,
                    key=key,
                    value=new_value,
                    value_type=vtype,
                    changed_by=user,
                    reason=reason,
                )
            except Exception:
                pass  # Override storage failed, continue
            
            # Record change history
            try:
                config_store.record_change(
                    section=section,
                    key=key,
                    old_value=old_values.get(key),
                    new_value=new_value,
                    value_type=vtype,
                    changed_by=user,
                    reason=reason,
                    source_ip=source_ip,
                )
            except Exception:
                pass  # Change history recording failed, continue
        
        # Create version snapshot
        try:
            config_dict = _export_full_config(config)
            config_store.create_version(
                config_dict=config_dict,
                created_by=user,
                description=f"Updated {section} config: {', '.join(updates.keys())}",
            )
        except Exception:
            pass  # Version snapshot failed, continue
    
    # Persist to file if not URL config
    if not is_url_config and config_file:
        try:
            _save_config_to_file(config, config_file)
        except Exception as e:
            logger.warning("Failed to persist config file: %s", e)


def update_command_authorization_config(
    config: configparser.ConfigParser,
    default_action: str | None = None,
    rules: list[dict] | None = None,
    privilege_check_order: str | None = None,
    config_file: str | None = None,
    is_url_config: bool = False,
) -> None:
    """Update command authorization configuration.
    
    Args:
        config: ConfigParser instance
        default_action: Optional new default action
        rules: Optional new rules list
        privilege_check_order: Optional new privilege check order
        config_file: Optional config file path
        is_url_config: Whether config is from URL
    """
    if "command_authorization" not in config:
        config.add_section("command_authorization")
    
    section = config["command_authorization"]
    
    if default_action is not None:
        section["default_action"] = str(default_action)
    
    if rules is not None:
        section["rules_json"] = json.dumps(rules)
    
    if privilege_check_order is not None:
        pco = str(privilege_check_order).strip().lower()
        if pco in ("before", "after", "none"):
            section["privilege_check_order"] = pco
    
    # Persist
    if not is_url_config and config_file:
        try:
            _save_config_to_file(config, config_file)
        except Exception as e:
            logger.warning("Failed to persist command authorization config: %s", e)


def update_webhook_config(
    config: configparser.ConfigParser,
    config_file: str | None = None,
    is_url_config: bool = False,
    **kwargs: Any
) -> None:
    """Update webhook configuration and persist.
    
    Args:
        config: ConfigParser instance
        config_file: Optional config file path
        is_url_config: Whether config is from URL
        **kwargs: Webhook configuration parameters
    """
    if "webhooks" not in config:
        config.add_section("webhooks")
    
    section = config["webhooks"]
    
    urls = kwargs.get("urls")
    if isinstance(urls, list):
        section["urls"] = ",".join(urls)
    
    headers = kwargs.get("headers")
    if isinstance(headers, dict):
        section["headers_json"] = json.dumps(headers)
    
    template = kwargs.get("template")
    if isinstance(template, dict):
        section["template_json"] = json.dumps(template)
    
    if "timeout" in kwargs and kwargs.get("timeout") is not None:
        section["timeout"] = str(kwargs.get("timeout"))
    
    if "threshold_count" in kwargs and kwargs.get("threshold_count") is not None:
        tc = kwargs.get("threshold_count")
        if isinstance(tc, (int, float, str)):
            section["threshold_count"] = str(int(float(tc)))
    
    if "threshold_window" in kwargs and kwargs.get("threshold_window") is not None:
        tw = kwargs.get("threshold_window")
        if isinstance(tw, (int, float, str)):
            section["threshold_window"] = str(int(float(tw)))
    
    # Persist
    if not is_url_config and config_file:
        try:
            _save_config_to_file(config, config_file)
        except Exception as e:
            logger.warning("Failed to persist webhook config: %s", e)


def _get_current_user() -> str:
    """Return current admin user for audit purposes."""
    return os.getenv("CURRENT_ADMIN_USER", "system")


def _infer_type(value: Any) -> str:
    """Infer value type for storage."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "json"
    return "string"


def _export_full_config(config: configparser.ConfigParser) -> dict[str, dict[str, str]]:
    """Export full config as nested dict."""
    out: dict[str, dict[str, str]] = {}
    for section in config.sections():
        out[section] = {k: v for k, v in config.items(section)}
    return out


def _save_config_to_file(config: configparser.ConfigParser, config_file: str) -> None:
    """Save configuration to file."""
    cfg_dir = os.path.dirname(config_file)
    if cfg_dir and not os.path.exists(cfg_dir):
        os.makedirs(cfg_dir, exist_ok=True)
    
    with open(config_file, "w") as fh:
        config.write(fh)
