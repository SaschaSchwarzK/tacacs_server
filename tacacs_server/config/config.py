"""
Configuration Management for TACACS+ Server
"""
import configparser
import logging
import os
import time
from logging.handlers import RotatingFileHandler
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen

from tacacs_server.auth.ldap_auth import LDAPAuthBackend
from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.utils.logger import configure as configure_logging
from tacacs_server.utils.logger import get_logger

from .schema import TacacsConfigSchema, validate_config_file

logger = get_logger(__name__)

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
        self.config_file = (
            None if self._is_url(self.config_source) else self.config_source
        )
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
            logger.exception(
                'Failed to load configuration (%s). Using defaults.', e
            )

    def _set_defaults(self):
        """Set default configuration values"""
        self.config['server'] = {
            'host': '0.0.0.0', 
            'port': '49', 
            'secret_key': os.environ.get('TACACS_SECRET', 'CHANGE_ME_IN_PRODUCTION'), 
            'log_level': 'INFO', 
            'max_connections': '50', 
            'socket_timeout': '30'
        }
        self.config['auth'] = {
            'backends': 'local',
            'local_auth_db': 'data/local_auth.db',
            'require_all_backends': 'false'
        }
        self.config['ldap'] = {
            'server': 'ldap://localhost:389', 
            'base_dn': 'ou=people,dc=example,dc=com', 
            'user_attribute': 'uid', 
            'bind_dn': '', 
            'bind_password': '', 
            'use_tls': 'false', 
            'timeout': '10'
        }
        self.config['database'] = {
            'accounting_db': 'data/tacacs_accounting.db', 
            'cleanup_days': '90', 
            'auto_cleanup': 'true',
            'metrics_history_db': 'data/metrics_history.db',
            'audit_trail_db': 'data/audit_trail.db',
            'metrics_retention_days': '30',
            'audit_retention_days': '90'
        }
        self.config['security'] = {
            'max_auth_attempts': '3', 
            'auth_timeout': '300', 
            'encryption_required': 'true', 
            'allowed_clients': '', 
            'denied_clients': '',
            'rate_limit_requests': '60',
            'rate_limit_window': '60'
        }
        self.config['logging'] = {
            'log_file': 'logs/tacacs.log', 
            'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
            'log_rotation': 'true', 
            'max_log_size': '10MB', 
            'backup_count': '5'
        }
        self.config['admin'] = {
            'username': os.environ.get('ADMIN_USERNAME', 'admin'),
            'password_hash': os.environ.get('ADMIN_PASSWORD_HASH', ''),
            'session_timeout_minutes': '60'
        }
        self.config['devices'] = {
            'database': 'data/devices.db', 'default_group': 'default'
        }
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
        
        if not self.config_file:
            raise ValueError('No configuration file path specified')
        
        try:
            cfg_dir = os.path.dirname(self.config_file)
            if cfg_dir and (not os.path.exists(cfg_dir)):
                os.makedirs(cfg_dir, exist_ok=True)
            with open(self.config_file, 'w') as fh:
                self.config.write(fh)
        except OSError as e:
            logger.error('Failed to save configuration to %s: %s', self.config_file, e)
            raise RuntimeError(f'Configuration save failed: {e}') from e
        except Exception as e:
            logger.exception('Unexpected error saving configuration: %s', e)
            raise

    def get_server_config(self) -> dict[str, Any]:
        """Get server configuration (excluding sensitive values)"""
        return {
            'host': self.config.get('server', 'host'), 
            'port': self.config.getint('server', 'port'), 
            # secret_key intentionally omitted to avoid accidental leakage
            'max_connections': self.config.getint('server', 'max_connections'), 
            'socket_timeout': self.config.getint('server', 'socket_timeout')
        }

    def get_auth_backends(self) -> list[str]:
        """Get list of enabled authentication backends"""
        backends_str = self.config.get('auth', 'backends', fallback='local')
        backend_list = backends_str.split(',')
        return [backend.strip() for backend in backend_list if backend.strip()]

    def get_local_auth_db(self) -> str:
        if self.config.has_option('auth', 'local_auth_db'):
            return self.config.get('auth', 'local_auth_db')
        return 'data/local_auth.db'

    def create_auth_backends(self) -> list:
        """Create authentication backend instances"""
        backends = []
        backend_names = self.get_auth_backends()
        
        for backend_name in backend_names:
            backend = self._create_single_backend(backend_name)
            if backend:
                backends.append(backend)
        
        if not backends:
            fallback_backend = self._create_fallback_backend()
            if fallback_backend:
                backends.append(fallback_backend)
        
        return backends
    
    def _create_single_backend(self, backend_name: str):
        """Create a single authentication backend instance"""
        try:
            normalized_name = _normalize_backend_name(backend_name)
            backend_type = normalized_name.lower()
            
            if backend_type == 'local':
                return LocalAuthBackend(self.get_local_auth_db())
            elif backend_type == 'ldap':
                return self._create_ldap_backend()
            else:
                logger.warning("Unknown auth backend '%s' configured", backend_name)
                return None
        except (KeyError, ValueError) as e:
            logger.error(
                "Configuration error for auth backend '%s': %s", backend_name, e
            )
            return None
        except Exception as e:
            logger.exception(
                "Failed to initialize auth backend '%s': %s", backend_name, e
            )
            return None
    
    def _create_ldap_backend(self):
        """Create LDAP backend if configuration exists"""
        if 'ldap' not in self.config:
            logger.error("LDAP backend configured but no [ldap] section found")
            return None
        return LDAPAuthBackend(dict(self.config['ldap']))
    
    def _create_fallback_backend(self):
        """Create fallback local authentication backend"""
        try:
            return LocalAuthBackend(self.get_local_auth_db())
        except Exception:
            logger.exception('Failed to initialize fallback local auth backend')
            return None

    def get_database_config(self) -> dict[str, Any]:
        """Get database configuration"""
        return {
            'accounting_db': self.config.get('database', 'accounting_db'), 
            'cleanup_days': self.config.getint('database', 'cleanup_days'), 
            'auto_cleanup': self.config.getboolean('database', 'auto_cleanup'),
            'metrics_history_db': self.config.get('database', 'metrics_history_db'),
            'audit_trail_db': self.config.get('database', 'audit_trail_db'),
            'metrics_retention_days': self.config.getint(
                'database', 'metrics_retention_days'
            ),
            'audit_retention_days': self.config.getint(
                'database', 'audit_retention_days'
            )
        }

    def get_device_store_config(self) -> dict[str, Any]:
        """Get device inventory configuration"""
        return {
            'database': self.config.get(
                'devices', 'database', fallback='data/devices.db'
            ),
            'default_group': self.config.get(
                'devices', 'default_group', fallback='default'
            )
        }

    def get_admin_auth_config(self) -> dict[str, Any]:
        """Get admin authentication configuration"""
        section = self.config['admin'] if 'admin' in self.config else {}
        return {
            'username': section.get('username', 'admin'),
            'password_hash': section.get('password_hash', ''),
            'session_timeout_minutes': int(
                section.get('session_timeout_minutes', 60)
            ),
        }

    def get_security_config(self) -> dict[str, Any]:
        """Get security configuration"""
        allowed_clients_str = self.config.get('security', 'allowed_clients')
        denied_clients_str = self.config.get('security', 'denied_clients')
        
        allowed_clients = self._parse_client_list(allowed_clients_str)
        denied_clients = self._parse_client_list(denied_clients_str)
        
        return {
            'max_auth_attempts': self.config.getint('security', 'max_auth_attempts'), 
            'auth_timeout': self.config.getint('security', 'auth_timeout'), 
            'encryption_required': self.config.getboolean(
                'security', 'encryption_required'
            ),
            'allowed_clients': allowed_clients,
            'denied_clients': denied_clients,
            'rate_limit_requests': self.config.getint(
                'security', 'rate_limit_requests'
            ),
            'rate_limit_window': self.config.getint('security', 'rate_limit_window')
        }
    
    def _parse_client_list(self, clients_str: str) -> list[str]:
        """Parse comma-separated client IP list"""
        if not clients_str:
            return []
        client_list = clients_str.split(',')
        return [ip.strip() for ip in client_list if ip.strip()]

    def get_logging_config(self) -> dict[str, Any]:
        """Get logging configuration"""
        return {
            'log_file': self.config.get('logging', 'log_file'), 
            'log_format': self.config.get('logging', 'log_format'), 
            'log_rotation': self.config.getboolean('logging', 'log_rotation'), 
            'max_log_size': self.config.get('logging', 'max_log_size'), 
            'backup_count': self.config.getint('logging', 'backup_count'), 
            'log_level': self.config.get('server', 'log_level')
        }

    def update_server_config(self, **kwargs):
        """Update server configuration with validation"""
        temp_config = self._create_temp_config_with_updates('server', kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates('server', kwargs)

    def update_auth_config(self, **kwargs):
        """Update authentication configuration with validation"""
        temp_config = self._create_temp_config_with_updates('auth', kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates('auth', kwargs)

    def update_ldap_config(self, **kwargs):
        """Update LDAP configuration with validation"""
        temp_config = self._create_temp_config_with_updates('ldap', kwargs)
        self._validate_temp_config(temp_config)
        self._apply_config_updates('ldap', kwargs)
    
    def _create_temp_config_with_updates(
        self, section: str, updates: dict
    ) -> configparser.ConfigParser:
        """Create temporary config with updates for validation"""
        temp_config = configparser.ConfigParser(interpolation=None)
        temp_config.read_dict(dict(self.config))
        
        for key, value in updates.items():
            temp_config[section][key] = str(value)
        
        return temp_config
    
    def _validate_temp_config(self, temp_config: configparser.ConfigParser):
        """Validate temporary configuration"""
        temp_tacacs_config = TacacsConfig.__new__(TacacsConfig)
        temp_tacacs_config.config = temp_config
        temp_tacacs_config.config_file = self.config_file
        temp_tacacs_config.config_source = self.config_source
        
        issues = temp_tacacs_config.validate_config()
        if issues:
            raise ValueError(f"Configuration validation failed: {'; '.join(issues)}")
    
    def _apply_config_updates(self, section: str, updates: dict):
        """Apply configuration updates and save"""
        for key, value in updates.items():
            self.config[section][key] = str(value)
        self.save_config()

    def validate_config(self) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        try:
            config_dict: dict[str, dict[str, str]] = {
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

            # Directory existence checks
            auth_db_path = validated.auth.local_auth_db
            auth_db_dir = os.path.dirname(auth_db_path)
            if auth_db_dir and not os.path.exists(auth_db_dir):
                issues.append(
                    f"Local auth database directory does not exist: {auth_db_dir}"
                )

            db_file = self.config.get('database', 'accounting_db')
            db_dir = os.path.dirname(db_file)
            if db_dir and not os.path.exists(db_dir):
                issues.append(f"Database directory does not exist: {db_dir}")
            
            # Additional validation checks
            issues.extend(self._validate_server_config())
            issues.extend(self._validate_auth_config())
            issues.extend(self._validate_security_config())
            
        except ValueError as exc:
            logger.error("✗ Configuration validation failed: %s", exc)
            issues.append(str(exc))
        
        return issues
    
    def _validate_server_config(self) -> list[str]:
        """Validate server configuration section"""
        issues = []
        
        # Port validation
        port = self.config.getint('server', 'port')
        if port < 1 or port > 65535:
            issues.append(f"Invalid server port: {port} (must be 1-65535)")
        
        # Secret key validation
        secret = self.config.get('server', 'secret_key')
        if secret == 'CHANGE_ME_IN_PRODUCTION':
            issues.append("Default secret key detected - change in production")
        elif len(secret) < 8:
            issues.append("Secret key too short (minimum 8 characters)")
        
        # Connection limits
        max_conn = self.config.getint('server', 'max_connections')
        if max_conn < 1 or max_conn > 1000:
            issues.append(f"Invalid max_connections: {max_conn} (must be 1-1000)")
        
        return issues
    
    def _validate_auth_config(self) -> list[str]:
        """Validate authentication configuration section"""
        issues = []
        
        # Backend validation
        backends = self.get_auth_backends()
        if not backends:
            issues.append("No authentication backends configured")
        
        for backend in backends:
            backend_name = _normalize_backend_name(backend)
            if backend_name.lower() not in ['local', 'ldap', 'okta']:
                issues.append(f"Unknown authentication backend: {backend_name}")
        
        # Database file validation
        auth_db = self.get_local_auth_db()
        if not auth_db:
            issues.append("Local auth database path not configured")
        
        return issues
    
    def _validate_security_config(self) -> list[str]:
        """Validate security configuration section"""
        issues = []
        
        # Auth attempts validation
        max_attempts = self.config.getint('security', 'max_auth_attempts')
        if max_attempts < 1 or max_attempts > 10:
            issues.append(f"Invalid max_auth_attempts: {max_attempts} (must be 1-10)")
        
        # Timeout validation
        timeout = self.config.getint('security', 'auth_timeout')
        if timeout < 30 or timeout > 3600:
            issues.append(f"Invalid auth_timeout: {timeout} (must be 30-3600 seconds)")
        
        return issues
    
    def validate_and_backup_config(self) -> tuple[bool, list[str]]:
        """Validate configuration and create backup if valid"""
        issues = self.validate_config()
        
        if not issues:
            # Create backup before any changes
            try:
                if self.config_file and os.path.exists(self.config_file):
                    backup_file = f"{self.config_file}.backup"
                    import shutil
                    shutil.copy2(self.config_file, backup_file)
                    logger.info(f"Configuration backup created: {backup_file}")
            except Exception as e:
                issues.append(f"Failed to create config backup: {e}")
                return False, issues
        
        return len(issues) == 0, issues

    def get_config_summary(self) -> dict[str, Any]:
        """Get configuration summary for display with validation status"""
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
        
        # Add validation status
        validation_issues = self.validate_config()
        summary['_validation'] = {
            'valid': len(validation_issues) == 0,
            'issues': validation_issues,
            'last_checked': time.time()
        }
        
        return summary

    def get_radius_config(self) -> dict[str, Any]:
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
        """Load configuration from URL with security validation"""
        if not self._is_url_safe(source):
            return
        
        try:
            payload = self._fetch_url_content(source)
            if payload:
                self.config.read_string(payload)
        except Exception as exc:
            logger.exception('Failed to load configuration from %s: %s', source, exc)
    
    def _is_url_safe(self, source: str) -> bool:
        """Validate URL safety to prevent SSRF attacks"""
        parsed = urlparse(source)
        
        if parsed.scheme not in {'https'}:
            logger.error('Only HTTPS URLs are allowed for configuration loading')
            return False
        
        hostname = parsed.hostname
        if self._is_private_network(hostname):
            logger.error('Local/private network URLs are not allowed')
            return False
        
        return True
    
    def _is_private_network(self, hostname: str) -> bool:
        """Check if hostname is in private network range"""
        if not hostname:
            return True
        
        private_hosts = {'localhost', '127.0.0.1', '0.0.0.0'}
        private_prefixes = ('192.168.', '10.', '172.')
        
        return hostname in private_hosts or hostname.startswith(private_prefixes)
    
    def _fetch_url_content(self, source: str) -> str | None:
        """Fetch and validate URL content"""
        max_size = 1024 * 1024  # 1MB limit
        
        with urlopen(source, timeout=10) as response:
            if response.length and response.length > max_size:
                logger.error('Configuration file too large')
                return None
            return response.read().decode('utf-8')
    
    
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
    handlers: list[logging.Handler] = []

    console_handler = logging.StreamHandler()
    handlers.append(console_handler)

    if log_file:
        try:
            if log_config.get('log_rotation', False):
                max_bytes = _parse_size(log_config.get('max_log_size', '10MB'))
                backup_count = int(log_config.get('backup_count', 5))
                file_handler = RotatingFileHandler(
                    log_file, maxBytes=max_bytes, backupCount=backup_count
                )
            else:
                file_handler = logging.FileHandler(log_file)
            handlers.append(file_handler)
        except Exception:
            logger.exception(
                'Failed to create file log handler for %s', log_file
            )

    configure_logging(level=log_level, handlers=handlers)

    if (log_config.get('log_format') and 
        log_config['log_format'].lower() not in {'', 'json', 'structured'}):
        logger.warning(
            'Ignoring configured log_format in favour of structured JSON output', 
            configured_format=log_config['log_format']
        )

    logger.info(
        'Logging configured', 
        log_level=log_config['log_level'], 
        log_file=log_file or 'console-only'
    )
