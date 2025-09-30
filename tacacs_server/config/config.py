"""
Configuration Management for TACACS+ Server
"""
import os
import logging
import configparser
import json
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, List
from urllib.parse import urlparse
from urllib.request import urlopen
from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.auth.ldap_auth import LDAPAuthBackend
from .schema import TacacsConfigSchema, validate_config_file

logger = logging.getLogger(__name__)

# helper to normalize backend entries (string, dict, ...)
def _normalize_backend_name(item: Any) -> str:
    """
    Convert a backend entry to a backend name string.
    Handles:
      - "local" -> "local"
      - {"name": "local", ...} -> "local"
      - {"local": {...}} -> "local"
      - other -> str(item)
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

class TacacsConfig:
    """TACACS+ server configuration manager"""

    def __init__(self, config_file: str='config/tacacs.conf'):
        env_source = os.environ.get('TACACS_CONFIG')
        self.config_source = env_source or config_file
        self.config_file = None if self._is_url(self.config_source) else self.config_source
        self.config = configparser.ConfigParser(interpolation=None)
        self._load_config()

    def _load_config(self):
        """Load configuration from file"""
        self._set_defaults()
        try:
            if self._is_url(self.config_source):
                self._load_from_url(self.config_source)
            else:
                path = self.config_file or self.config_source
                if os.path.exists(path):
                    self.config.read(path)
                else:
                    self.config_file = path
                    self.save_config()
        except Exception as e:
            logger.exception('Failed to load configuration (%s). Using defaults.', e)

    def _set_defaults(self):
        """Set default configuration values"""
        self.config['server'] = {'host': '0.0.0.0', 'port': '49', 'secret_key': 'tacacs123', 'log_level': 'INFO', 'max_connections': '50', 'socket_timeout': '30'}
        self.config['auth'] = {
            'backends': 'local',
            'local_auth_db': 'data/local_auth.db',
            'require_all_backends': 'false'
        }
        self.config['ldap'] = {'server': 'ldap://localhost:389', 'base_dn': 'ou=people,dc=example,dc=com', 'user_attribute': 'uid', 'bind_dn': '', 'bind_password': '', 'use_tls': 'false', 'timeout': '10'}
        self.config['database'] = {'accounting_db': 'data/tacacs_accounting.db', 'cleanup_days': '90', 'auto_cleanup': 'true'}
        self.config['security'] = {'max_auth_attempts': '3', 'auth_timeout': '300', 'encryption_required': 'true', 'allowed_clients': '', 'denied_clients': ''}
        self.config['logging'] = {'log_file': 'logs/tacacs.log', 'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s', 'log_rotation': 'true', 'max_log_size': '10MB', 'backup_count': '5'}
        self.config['admin'] = {
            'username': 'admin',
            'password_hash': '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
            'session_timeout_minutes': '60'
        }
        self.config['devices'] = {'database': 'data/devices.db', 'default_group': 'default'}
        self.config['radius'] = {
            'enabled': 'false',
            'auth_port': '1812',
            'acct_port': '1813',
            'host': '0.0.0.0',
            'share_backends': 'true',
            'share_accounting': 'true'
        }

    def save_config(self):
        """Save configuration to file"""
        if self._is_url(self.config_source):
            raise RuntimeError('Cannot save configuration when source is a URL')
        try:
            cfg_dir = os.path.dirname(self.config_file)
            if cfg_dir and (not os.path.exists(cfg_dir)):
                os.makedirs(cfg_dir, exist_ok=True)
            with open(self.config_file, 'w') as fh:
                self.config.write(fh)
        except Exception as e:
            logger.exception('Failed to save configuration: %s', e)

    def get_server_config(self) -> Dict[str, Any]:
        """Get server configuration"""
        return {'host': self.config.get('server', 'host'), 'port': self.config.getint('server', 'port'), 'secret_key': self.config.get('server', 'secret_key'), 'max_connections': self.config.getint('server', 'max_connections'), 'socket_timeout': self.config.getint('server', 'socket_timeout')}

    def get_auth_backends(self) -> List[str]:
        """Get list of enabled authentication backends"""
        backends_str = self.config.get('auth', 'backends', fallback='local')
        return [backend.strip() for backend in backends_str.split(',') if backend.strip()]

    def get_local_auth_db(self) -> str:
        if self.config.has_option('auth', 'local_auth_db'):
            return self.config.get('auth', 'local_auth_db')
        return 'data/local_auth.db'

    def create_auth_backends(self) -> List:
        """Create authentication backend instances"""
        backends = []
        backend_names = self.get_auth_backends()
        for backend_name in backend_names:
            try:
                # normalize backend_name before using .lower()
                backend_name = _normalize_backend_name(backend_name)
                if backend_name.lower() == 'local':
                    backends.append(LocalAuthBackend(self.get_local_auth_db()))
                elif backend_name.lower() == 'ldap':
                    backends.append(LDAPAuthBackend(dict(self.config['ldap'])))
                else:
                    logger.warning("Unknown auth backend '%s' configured", backend_name)
            except Exception:
                logger.exception("Failed to initialize auth backend '%s'", backend_name)
        if not backends:
            try:
                backends.append(LocalAuthBackend(self.get_local_auth_db()))
            except Exception:
                logger.exception('Failed to initialize fallback local auth backend')
        return backends

    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration"""
        return {'accounting_db': self.config.get('database', 'accounting_db'), 'cleanup_days': self.config.getint('database', 'cleanup_days'), 'auto_cleanup': self.config.getboolean('database', 'auto_cleanup')}

    def get_device_store_config(self) -> Dict[str, Any]:
        """Get device inventory configuration"""
        return {
            'database': self.config.get('devices', 'database', fallback='data/devices.db'),
            'default_group': self.config.get('devices', 'default_group', fallback='default')
        }

    def get_admin_auth_config(self) -> Dict[str, Any]:
        """Get admin authentication configuration"""
        section = self.config['admin'] if 'admin' in self.config else {}
        return {
            'username': section.get('username', 'admin'),
            'password_hash': section.get('password_hash', ''),
            'session_timeout_minutes': int(section.get('session_timeout_minutes', 60)),
        }

    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration"""
        allowed_clients = self.config.get('security', 'allowed_clients')
        denied_clients = self.config.get('security', 'denied_clients')
        return {'max_auth_attempts': self.config.getint('security', 'max_auth_attempts'), 'auth_timeout': self.config.getint('security', 'auth_timeout'), 'encryption_required': self.config.getboolean('security', 'encryption_required'), 'allowed_clients': [ip.strip() for ip in allowed_clients.split(',') if ip.strip()], 'denied_clients': [ip.strip() for ip in denied_clients.split(',') if ip.strip()]}

    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return {'log_file': self.config.get('logging', 'log_file'), 'log_format': self.config.get('logging', 'log_format'), 'log_rotation': self.config.getboolean('logging', 'log_rotation'), 'max_log_size': self.config.get('logging', 'max_log_size'), 'backup_count': self.config.getint('logging', 'backup_count'), 'log_level': self.config.get('server', 'log_level')}

    def update_server_config(self, **kwargs):
        """Update server configuration"""
        for key, value in kwargs.items():
            self.config['server'][key] = str(value)
        self.save_config()

    def update_auth_config(self, **kwargs):
        """Update authentication configuration"""
        for key, value in kwargs.items():
            self.config['auth'][key] = str(value)
        self.save_config()

    def update_ldap_config(self, **kwargs):
        """Update LDAP configuration"""
        for key, value in kwargs.items():
            self.config['ldap'][key] = str(value)
        self.save_config()

    def validate_config(self) -> List[str]:
        """Validate configuration and return list of issues."""

        try:
            config_dict: Dict[str, Dict[str, str]] = {
                'server': dict(self.config['server']),
                'auth': dict(self.config['auth']),
                'security': dict(self.config['security']),
            }

            if 'ldap' in self.config:
                config_dict['ldap'] = dict(self.config['ldap'])
            if 'okta' in self.config:
                config_dict['okta'] = dict(self.config['okta'])

            validated: TacacsConfigSchema = validate_config_file(config_dict)
            logger.info("✓ Configuration validation passed")

            auth_db_path = validated.auth.local_auth_db
            auth_db_dir = os.path.dirname(auth_db_path)
            issues: List[str] = []
            if auth_db_dir and not os.path.exists(auth_db_dir):  # pragma: no cover - filesystem check
                issues.append(f"Local auth database directory does not exist: {auth_db_dir}")

            db_file = self.config.get('database', 'accounting_db')
            db_dir = os.path.dirname(db_file)
            if db_dir and not os.path.exists(db_dir):  # pragma: no cover - filesystem check
                issues.append(f"Database directory does not exist: {db_dir}")

            return issues
        except ValueError as exc:
            logger.error("✗ Configuration validation failed: %s", exc)
            return [str(exc)]

    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for display"""
        summary = {
            'server': dict(self.config['server']),
            'auth': dict(self.config['auth']),
            'ldap': dict(self.config['ldap']),
            'database': dict(self.config['database']),
            'security': dict(self.config['security']),
            'logging': dict(self.config['logging'])
        }
        if 'admin' in self.config:
            summary['admin'] = dict(self.config['admin'])
        if 'devices' in self.config:
            summary['devices'] = dict(self.config['devices'])
        if 'radius' in self.config:
            summary['radius'] = dict(self.config['radius'])
        return summary

    def get_radius_config(self) -> Dict[str, Any]:
        """Get RADIUS server configuration"""
        return {
            'enabled': self.config.getboolean('radius', 'enabled'),
            'auth_port': self.config.getint('radius', 'auth_port'),
            'acct_port': self.config.getint('radius', 'acct_port'),
            'host': self.config.get('radius', 'host'),
            'share_backends': self.config.getboolean('radius', 'share_backends'),
            'share_accounting': self.config.getboolean('radius', 'share_accounting')
        }

    @staticmethod
    def _is_url(source: str) -> bool:
        parsed = urlparse(source)
        return parsed.scheme in {'http', 'https', 'file'}

    def _load_from_url(self, source: str) -> None:
        try:
            with urlopen(source) as response:
                payload = response.read().decode('utf-8')
        except Exception as exc:
            logger.exception('Failed to load configuration from %s: %s', source, exc)
            return
        self.config.read_string(payload)
    
    
def _parse_size(size_str: str) -> int:
    """Parse human readable size strings like '10MB' -> bytes"""
    try:
        s = size_str.strip().upper()
        if s.endswith('KB'):
            return int(float(s[:-2]) * 1024)
        if s.endswith('MB'):
            return int(float(s[:-2]) * 1024 * 1024)
        if s.endswith('GB'):
            return int(float(s[:-2]) * 1024 * 1024 * 1024)
        return int(s)
    except Exception:
        return 10 * 1024 * 1024

def setup_logging(config: TacacsConfig):
    """Setup logging based on configuration"""
    log_config = config.get_logging_config()
    log_file = log_config['log_file']
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and (not os.path.exists(log_dir)):
            os.makedirs(log_dir, exist_ok=True)
    log_level = getattr(logging, log_config['log_level'].upper(), logging.INFO)
    log_format = log_config['log_format']
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(log_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    if log_file:
        try:
            if log_config.get('log_rotation', False):
                max_bytes = _parse_size(log_config.get('max_log_size', '10MB'))
                backup_count = int(log_config.get('backup_count', 5))
                file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
            else:
                file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(console_formatter)
            root_logger.addHandler(file_handler)
        except Exception:
            logger.exception('Failed to create file log handler for %s', log_file)
    root_logger.setLevel(log_level)
    logger.info(f"Logging configured - Level: {log_config['log_level']}, File: {log_file or 'Console only'}")
