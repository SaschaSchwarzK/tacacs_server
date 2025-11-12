"""Configuration defaults module.

Provides a single function to populate all default configuration values.
"""

import configparser

from .constants import DEFAULTS


def populate_defaults(config: configparser.ConfigParser) -> None:
    """Populate configuration with default values.
    
    This is the single source of truth for all default configuration values.
    
    Args:
        config: ConfigParser instance to populate
    """
    for section, values in DEFAULTS.items():
        if not config.has_section(section):
            config.add_section(section)
        for key, value in values.items():
            config.set(section, key, value)
