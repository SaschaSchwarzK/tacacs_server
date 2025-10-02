import argparse
import signal
import sys
import textwrap
from collections import Counter
from pathlib import Path
from typing import Any

from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.auth.local_store import LocalAuthStore
from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.auth.local_user_group_service import LocalUserGroupService
from tacacs_server.config.config import TacacsConfig, setup_logging
from tacacs_server.devices.service import DeviceService
from tacacs_server.devices.store import DeviceStore
from tacacs_server.tacacs.server import TacacsServer
from tacacs_server.utils.logger import get_logger
from tacacs_server.web.admin.auth import (
    AdminAuthConfig,
    AdminSessionManager,
    get_admin_auth_dependency,
)
from tacacs_server.web.monitoring import (
    set_admin_auth_dependency,
    set_admin_session_manager,
    set_config as monitoring_set_config,
    set_device_service,
    set_local_user_group_service,
    set_local_user_service,
)

logger = get_logger(__name__)

class TacacsServerManager:
    """TACACS+ Server Manager"""

    def __init__(self, config_file: str='config/tacacs.conf'):
        self.config = TacacsConfig(config_file)
        monitoring_set_config(self.config)
        self.server = None
        self.radius_server = None
        self.device_store = None
        self.device_service = None
        self.local_auth_store: LocalAuthStore | None = None
        self.local_user_service = None
        self.local_user_group_service = None
        self.admin_session_manager = None
        self.device_store_config: dict[str, Any] = {}
        self.running = False
        self._device_change_unsubscribe = None
        self._pending_radius_refresh = False

    def setup(self):
        """Setup server components"""
        setup_logging(self.config)
        issues = self.config.validate_config()
        if issues:
            logger.error('Configuration validation failed:')
            for issue in issues:
                logger.error(f'  - {issue}')
            return False
        server_config = self.config.get_server_config()
        self.server = TacacsServer(
            host=server_config['host'],
            port=server_config['port'],
            secret_key=server_config['secret_key'],
        )

        # Initialize device inventory
        try:
            self.device_store_config = self.config.get_device_store_config()
            self.device_store = DeviceStore(self.device_store_config['database'])
            default_group = self.device_store_config.get('default_group')
            if default_group:
                self.device_store.ensure_group(
                    default_group, description="Default device group"
                )
            self.device_service = DeviceService(self.device_store)
            set_device_service(self.device_service)
            self._device_change_unsubscribe = self.device_service.add_change_listener(
                self._handle_device_change
            )
            # Expose store on server for future integrations
            if hasattr(self.server, 'device_store'):
                self.server.device_store = self.device_store
        except Exception as exc:
            logger.exception("Failed to initialise device store: %s", exc)
            self.device_store = None
            self.device_service = None
            set_device_service(None)

        # Initialize local authentication store and services
        auth_db_path = self.config.get_local_auth_db()

        local_store: LocalAuthStore | None = None
        try:
            local_store = LocalAuthStore(auth_db_path)
            self.local_auth_store = local_store
        except Exception as exc:
            logger.exception("Failed to initialise local auth store: %s", exc)
            self.local_auth_store = None

        if local_store is None:
            self.local_user_service = None
            self.local_user_group_service = None
            set_local_user_service(None)
            set_local_user_group_service(None)
            if self.server and hasattr(self.server, 'handlers'):
                self.server.handlers.set_local_user_group_service(None)
        else:
            try:
                self.local_user_service = LocalUserService(
                    auth_db_path,
                    store=local_store,
                )
                set_local_user_service(self.local_user_service)
            except Exception as exc:
                logger.exception("Failed to initialise local user service: %s", exc)
                self.local_user_service = None
                set_local_user_service(None)

            try:
                self.local_user_group_service = LocalUserGroupService(
                    auth_db_path,
                    store=local_store,
                )
                set_local_user_group_service(self.local_user_group_service)
                if self.server and hasattr(self.server, 'handlers'):
                    self.server.handlers.set_local_user_group_service(
                        self.local_user_group_service
                    )
            except Exception as exc:
                logger.exception(
                    "Failed to initialise local user group service: %s", exc
                )
                self.local_user_group_service = None
                set_local_user_group_service(None)
                if self.server and hasattr(self.server, 'handlers'):
                    self.server.handlers.set_local_user_group_service(None)

        # Register pending refresh if radius server not yet initialised
        if self.device_store and not self.radius_server:
            self._pending_radius_refresh = True

        # Configure admin authentication
        try:
            admin_auth_cfg = self.config.get_admin_auth_config()
            username = admin_auth_cfg.get('username', 'admin')
            password_hash = admin_auth_cfg.get('password', '')
            if password_hash:
                auth_config = AdminAuthConfig(
                    username=username,
                    password_hash=password_hash,
                    session_timeout_minutes=admin_auth_cfg.get(
                        'session_timeout_minutes', 60
                    ),
                )
                self.admin_session_manager = AdminSessionManager(auth_config)
                set_admin_session_manager(self.admin_session_manager)
                dependency = get_admin_auth_dependency(self.admin_session_manager)
                set_admin_auth_dependency(dependency)
            else:
                logger.warning(
                    "Admin password hash not configured; "
                    "admin routes will be unauthenticated"
                )
                set_admin_session_manager(None)
                set_admin_auth_dependency(None)
        except Exception as exc:
            logger.exception("Failed to configure admin authentication: %s", exc)
            self.admin_session_manager = None
            set_admin_session_manager(None)
            set_admin_auth_dependency(None)
        # Setup RADIUS server if enabled
        radius_config = self.config.get_radius_config()
        if radius_config['enabled']:
            self._setup_radius_server(radius_config)
        auth_backends = self.config.create_auth_backends()
        for backend in auth_backends:
            if isinstance(backend, LocalAuthBackend) and self.local_user_service:
                backend.set_user_service(self.local_user_service)
            self.server.add_auth_backend(backend)
            if self.radius_server and radius_config.get('share_backends', False):
                if backend not in getattr(self.radius_server, 'auth_backends', []):
                    self.radius_server.add_auth_backend(backend)

        if self.radius_server and radius_config.get('share_backends', False):
            shared = len(getattr(self.radius_server, 'auth_backends', []))
            logger.info("RADIUS: Sharing %d auth backends with TACACS+", shared)
        # Enable monitoring if configured (tolerate missing section)
        # read monitoring section safely: prefer helper API, fallback to RawConfigParser
        # items()
        try:
            if hasattr(self.config, "get_monitoring_config"):
                monitoring_config = self.config.get_monitoring_config() or {}
            else:
                # self.config.config is a ConfigParser/RawConfigParser
                try:
                    monitoring_config = dict(
                        getattr(self.config, "config").items("monitoring")
                    )
                except Exception:
                    monitoring_config = {}
        except Exception:
            monitoring_config = {}

        if str(monitoring_config.get("enabled", "false")).lower() == "true":
            web_host = monitoring_config.get("web_host", "127.0.0.1")
            web_port = int(monitoring_config.get("web_port", "8080"))
            logger.info(
                "Monitoring configured -> attempting to enable web monitoring on %s:%s",
                web_host,
                web_port,
            )
            try:
                started = self.server.enable_web_monitoring(
                    web_host, web_port, radius_server=self.radius_server
                )
                if started:
                    logger.info(
                        "Monitoring successfully started at http://%s:%s",
                        web_host,
                        web_port,
                    )
                else:
                    logger.error(
                        "Monitoring failed to start "
                        "(enable_web_monitoring returned False)"
                    )
            except Exception as e:
                logger.exception("Exception while enabling monitoring: %s", e)
        return True

    def _handle_device_change(self) -> None:
        try:
            self._refresh_radius_clients()
        except Exception:
            logger.exception(
                "Failed to refresh RADIUS clients after device inventory change"
            )

    def _refresh_radius_clients(self) -> None:
        if not self.device_store:
            return
        try:
            client_configs = self.device_store.iter_radius_clients()
        except Exception as exc:
            logger.exception("Failed to build RADIUS client list: %s", exc)
            return
        if not self.radius_server:
            self._pending_radius_refresh = True
            return
        self.radius_server.refresh_clients(client_configs)
        self._pending_radius_refresh = False

    def _setup_radius_server(self, radius_config: dict[str, Any]):
        """Setup RADIUS server"""
        try:
            from tacacs_server.radius.server import RADIUSServer
            
            self.radius_server = RADIUSServer(
                host=radius_config['host'],
                port=radius_config['auth_port'],
                accounting_port=radius_config['acct_port']
            )
            self.radius_server.device_store = self.device_store
            if self.local_user_group_service:
                self.radius_server.set_local_user_group_service(self.local_user_group_service)

            # Configure RADIUS client devices from the device store when available
            initial_clients = []
            if self.device_store:
                try:
                    initial_clients = self.device_store.iter_radius_clients()
                except Exception as exc:
                    logger.exception(
                        "Failed to load clients from device store: %s", exc
                    )
                    initial_clients = []

            self.radius_server.refresh_clients(initial_clients)
            configured_clients = len(initial_clients)
            if not initial_clients:
                logger.info("RADIUS: no clients defined in device store")

            # Share authentication backends with TACACS+
            if radius_config['share_backends']:
                shared_initial = 0
                for backend in self.server.auth_backends:
                    if backend not in getattr(self.radius_server, 'auth_backends', []):
                        self.radius_server.add_auth_backend(backend)
                        shared_initial += 1
                if shared_initial:
                    logger.info(
                        "RADIUS: Sharing %d auth backends with TACACS+",
                        len(self.radius_server.auth_backends),
                    )
            
            # Share accounting database with TACACS+
            if radius_config['share_accounting']:
                self.radius_server.set_accounting_logger(self.server.db_logger)
                logger.info("RADIUS: Sharing accounting database with TACACS+")
            
            logger.info("RADIUS server configured with %d clients", configured_clients)

            if self._pending_radius_refresh:
                self._refresh_radius_clients()

        except Exception as e:
            logger.error(f"Failed to setup RADIUS server: {e}")
            self.radius_server = None

    def start(self):
        """Start the TACACS+ server"""
        if not self.setup():
            return False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        try:
            self.running = True
            logger.info('=' * 50)
            logger.info("TACACS+ & RADIUS Server Starting")
            logger.info('=' * 50)
            self._print_startup_info()
            # Start RADIUS server if configured
            if self.radius_server:
                self.radius_server.start()
            # Start TACACS+ server 
            self.server.start()
        except KeyboardInterrupt:
            logger.info('Received interrupt signal')
        except Exception as e:
            logger.error(f'Server error: {e}')
            return False
        finally:
            self.stop()
        return True

    def stop(self):
        """Stop the TACACS+ server"""
        if self.server and self.running:
            logger.info('Shutting down down servers...')
            self.running = False
            # Stop RADIUS server
            if self.radius_server:
                self.radius_server.stop()
            if self._device_change_unsubscribe:
                try:
                    self._device_change_unsubscribe()
                except Exception:
                    logger.exception("Failed to detach device change listener")
                finally:
                    self._device_change_unsubscribe = None
            # Stop TACACS+ server
            self.server.stop()
            logger.info('Servers stopped successfully')

    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        logger.info(f'Received signal {signum}')
        self.stop()

    def _print_startup_info(self):
        """Print server startup information"""
        server_config = self.config.get_server_config()
        auth_backends = [b.name for b in self.server.auth_backends]
        db_config = self.config.get_database_config()
        logger.info(f"Server Address: {server_config['host']}:{server_config['port']}")
        logger.info(f"Secret Key: {'*' * len(server_config['secret_key'])}")
        logger.info(f"Authentication Backends: {', '.join(auth_backends)}")
        logger.info(f"Database: {db_config['accounting_db']}")
        source = getattr(self.config, 'config_source', self.config.config_file)
        logger.info(f'Configuration: {source}')
        logger.info('')
        logger.info('Testing authentication backends:')
        for backend in self.server.auth_backends:
            status = '✓ Available' if backend.is_available() else '✗ Unavailable'
            logger.info(f'  {backend.name}: {status}')
        # Add RADIUS info
        if self.radius_server:
            logger.info("")
            logger.info("RADIUS Server:")
            logger.info(f"  Authentication Port: {self.radius_server.port}")
            logger.info(f"  Accounting Port: {self.radius_server.accounting_port}")
            client_list = getattr(self.radius_server, 'clients', [])
            logger.info(f"  Configured Clients: {len(client_list)}")
            if client_list:
                if isinstance(client_list, dict):
                    entries = list(client_list.values())
                else:
                    entries = list(client_list)

                try:
                    group_counts = Counter(
                        (entry.get('group') 
                         if isinstance(entry, dict) 
                         else getattr(entry, 'group', None)) or 'ungrouped'
                        for entry in entries
                    )
                    summary = ", ".join(
                        f"{group}({count})" 
                        for group, count in group_counts.most_common(5)
                    )
                    if len(group_counts) > 5:
                        summary += ", ..."
                    logger.info("  Client Groups: %s", summary)
                except Exception:
                    # If summarising fails just skip detailed output
                    pass
        logger.info('')
        logger.info('Server ready - waiting for connections...')
        logger.info('Press Ctrl+C to stop')

def create_test_client_script():
    """Create test client script"""
    test_client_code = textwrap.dedent('''\
        #!/usr/bin/env python3
        """Simple TACACS+ PAP client for quick end-to-end checks."""

        from __future__ import annotations

        import argparse
        import hashlib
        import socket
        import struct
        import sys
        import time
        from dataclasses import dataclass
        from typing import Optional


        def md5_pad(
            session_id: int, key: str, version: int, seq_no: int, length: int
        ) -> bytes:
            pad = bytearray()
            session_id_bytes = struct.pack("!L", session_id)
            key_bytes = key.encode("utf-8")
            version_byte = bytes([version])
            seq_byte = bytes([seq_no])

            while len(pad) < length:
                if not pad:
                    md5_input = session_id_bytes + key_bytes + version_byte + seq_byte
                else:
                    md5_input = (
                        session_id_bytes + key_bytes + version_byte + seq_byte + pad
                    )
                pad.extend(hashlib.md5(md5_input).digest())

            return bytes(pad[:length])


        def transform_body(
            body: bytes, session_id: int, key: str, version: int, seq_no: int
        ) -> bytes:
            if not key:
                return body
            pad = md5_pad(session_id, key, version, seq_no, len(body))
            return bytes(a ^ b for a, b in zip(body, pad))


        @dataclass
        class PapResult:
            success: bool
            status: int
            server_message: Optional[str]
            detail: str


        def pap_authentication(
            host: str = "localhost",
            port: int = 49,
            key: str = "tacacs123",
            username: str = "admin",
            password: str = "admin123",
        ) -> PapResult:
            print("\n=== TACACS+ PAP Authentication Test ===\n")
            print(f"Target        : {host}:{port}")
            print(f"Username      : {username}")
            obscured = "*" * len(password) if password else "(empty)"
            print(f"Password      : {obscured}")
            print(f"Shared Secret : {key}\n")

            sock: Optional[socket.socket] = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((host, port))

                session_id = int(time.time()) & 0xFFFFFFFF
                user_bytes = username.encode("utf-8")
                port_bytes = b"console"
                rem_addr_bytes = b"127.0.0.1"
                data_bytes = password.encode("utf-8")

                body = struct.pack(
                    "!BBBBBBBB",
                    1,
                    15,
                    2,
                    1,
                    len(user_bytes),
                    len(port_bytes),
                    len(rem_addr_bytes),
                    len(data_bytes),
                )
                body += user_bytes + port_bytes + rem_addr_bytes + data_bytes

                version = 0xC0
                seq_no = 1
                encrypted_body = transform_body(body, session_id, key, version, seq_no)
                header = struct.pack(
                    "!BBBBLL", version, 1, seq_no, 0, session_id, len(encrypted_body)
                )

                print("Sending PAP authentication request...")
                sock.sendall(header + encrypted_body)

                response_header = sock.recv(12)
                if len(response_header) != 12:
                    return PapResult(False, -1, None, "invalid response header")

                r_version, r_type, r_seq, _, r_session, r_length = struct.unpack(
                    "!BBBBLL", response_header
                )
                print(f"Received header: type={r_type}, seq={r_seq}, length={r_length}")

                response_body = sock.recv(r_length) if r_length else b""
                if len(response_body) < r_length:
                    return PapResult(False, -1, None, "truncated response body")

                decrypted = transform_body(
                    response_body, r_session, key, r_version, r_seq
                )
                if len(decrypted) < 6:
                    return PapResult(False, -1, None, "response too short")

                status, _flags, msg_len, data_len = struct.unpack(
                    "!BBHH", decrypted[:6]
                )
                offset = 6
                server_message = None
                if msg_len:
                    server_message = decrypted[offset:offset + msg_len].decode(
                        "utf-8", errors="replace"
                    )
                    offset += msg_len

                success = status == 1
                detail = {
                    1: "authentication accepted",
                    2: "authentication rejected",
                    0: "user continues",
                }.get(status, f"status={status}")

                print()
                if success:
                    print("Result        : ✅ Authentication accepted")
                else:
                    print("Result        : ❌ Authentication rejected")
                print(f"Status Detail : {detail}")
                if server_message:
                    print(f"Server Message: {server_message}")
                if data_len:
                    attr_data = decrypted[offset:offset + data_len]
                    print(f"Additional Data ({data_len} bytes): {attr_data.hex()}")

                return PapResult(success, status, server_message, detail)

            except OSError as exc:
                print(f"✗ Network error: {exc}")
                return PapResult(False, -1, None, "network error")
            except Exception as exc:
                print(f"✗ Unexpected error: {exc}")
                return PapResult(False, -1, None, "unexpected error")
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass


        def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
            parser = argparse.ArgumentParser(description="Simple TACACS+ PAP client")
            parser.add_argument(
                "host", nargs="?", default="localhost", help="Server host (default: localhost)"
            )
            parser.add_argument(
                "port", nargs="?", type=int, default=49, help="Server port (default: 49)"
            )
            parser.add_argument(
                "secret", nargs="?", default="tacacs123", help="Shared secret"
            )
            parser.add_argument("username", nargs="?", default="admin", help="Username")
            parser.add_argument(
                "password", nargs="?", default="admin123", help="Password"
            )
            return parser.parse_args(argv)


        def main(argv: Optional[list[str]] = None) -> int:
            args = parse_args(argv)
            result = pap_authentication(
                args.host, args.port, args.secret, args.username, args.password
            )
            return 0 if result.success else 1


        if __name__ == "__main__":
            sys.exit(main())
    ''')
    import os
    import stat
    os.makedirs('scripts', exist_ok=True)
    script_path = 'scripts/tacacs_client.py'
    with open(script_path, 'w') as f:
        f.write(test_client_code)
    st = os.stat(script_path)
    os.chmod(script_path, st.st_mode | stat.S_IEXEC)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='TACACS+ Server')
    parser.add_argument(
        '-c', '--config', default='config/tacacs.conf', help='Configuration file path'
    )
    parser.add_argument(
        '--create-test-client',
        action='store_true',
        help='Create test client script and exit',
    )
    parser.add_argument(
        '--validate-config', action='store_true', help='Validate configuration and exit'
    )
    parser.add_argument('--version', action='version', version='TACACS+ Server 1.0')
    args = parser.parse_args()
    for directory in ['config', 'data', 'logs', 'tests', 'scripts']:
        Path(directory).mkdir(exist_ok=True)
    if args.create_test_client:
        try:
            create_test_client_script()
            print('Test client created: scripts/tacacs_client.py')
            print(
                'Usage: python scripts/tacacs_client.py [host] [port] [secret] [username] [password]'
            )
        except Exception as e:
            print(f'Error creating test client: {e}')
            return 1
        return 0
    if args.validate_config:
        try:
            config = TacacsConfig(args.config)
            issues = config.validate_config()
            if issues:
                print('Configuration validation failed:')
                for issue in issues:
                    print(f'  - {issue}')
                return 1
            else:
                print('Configuration is valid')
                return 0
        except Exception as e:
            print(f'Error validating configuration: {e}')
            return 1
    try:
        server_manager = TacacsServerManager(args.config)
        success = server_manager.start()
        return 0 if success else 1
    except Exception as e:
        print(f'Failed to start server: {e}')
        return 1
if __name__ == '__main__':
    sys.exit(main())
