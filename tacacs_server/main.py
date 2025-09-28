"""
TACACS+ Server - Main Entry Point
"""
import sys
import signal
import logging
import argparse
from pathlib import Path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))
from config.config import TacacsConfig, setup_logging
from tacacs_server.tacacs.server import TacacsServer
from accounting.database import DatabaseLogger
logger = logging.getLogger(__name__)

class TacacsServerManager:
    """TACACS+ Server Manager"""

    def __init__(self, config_file: str='config/tacacs.conf'):
        self.config = TacacsConfig(config_file)
        self.server = None
        self.running = False

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
        self.server = TacacsServer(host=server_config['host'], port=server_config['port'], secret_key=server_config['secret_key'])
        auth_backends = self.config.create_auth_backends()
        for backend in auth_backends:
            self.server.add_auth_backend(backend)
        # Enable monitoring if configured (tolerate missing section)
        # read monitoring section safely: prefer helper API, fallback to RawConfigParser items()
        try:
            if hasattr(self.config, "get_monitoring_config"):
                monitoring_config = self.config.get_monitoring_config() or {}
            else:
                # self.config.config is a ConfigParser/RawConfigParser
                try:
                    monitoring_config = dict(getattr(self.config, "config").items("monitoring"))
                except Exception:
                    monitoring_config = {}
        except Exception:
            monitoring_config = {}

        if str(monitoring_config.get("enabled", "false")).lower() == "true":
            web_host = monitoring_config.get("web_host", "127.0.0.1")
            web_port = int(monitoring_config.get("web_port", "8080"))
            logger.info("Monitoring configured -> attempting to enable web monitoring on %s:%s", web_host, web_port)
            try:
                started = self.server.enable_web_monitoring(web_host, web_port)
                if started:
                    logger.info("Monitoring successfully started at http://%s:%s", web_host, web_port)
                else:
                    logger.error("Monitoring failed to start (enable_web_monitoring returned False)")
            except Exception as e:
                logger.exception("Exception while enabling monitoring: %s", e)
        return True

    def start(self):
        """Start the TACACS+ server"""
        if not self.setup():
            return False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        try:
            self.running = True
            logger.info('=' * 50)
            logger.info('TACACS+ Server Starting')
            logger.info('=' * 50)
            self._print_startup_info()
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
            logger.info('Shutting down TACACS+ server...')
            self.running = False
            self.server.stop()
            logger.info('Server stopped successfully')

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
        logger.info(f'Configuration: {self.config.config_file}')
        logger.info('')
        logger.info('Testing authentication backends:')
        for backend in self.server.auth_backends:
            status = '✓ Available' if backend.is_available() else '✗ Unavailable'
            logger.info(f'  {backend.name}: {status}')
        logger.info('')
        logger.info('Server ready - waiting for connections...')
        logger.info('Press Ctrl+C to stop')

def create_test_client_script():
    """Create test client script"""
    test_client_code = '#!/usr/bin/env python3\n"""\nTACACS+ Test Client\nUsage: python test_client.py [host] [port] [secret] [username] [password]\n"""\n\nimport socket\nimport struct\nimport hashlib\nimport sys\nimport time\n\ndef md5_pad(session_id, key, version, seq_no, length):\n    """Generate MD5 encryption pad"""\n    pad = b\'\'\n    session_id_bytes = struct.pack(\'!L\', session_id)\n    key_bytes = key.encode(\'utf-8\')\n    version_bytes = bytes([version])\n    seq_no_bytes = bytes([seq_no])\n    \n    while len(pad) < length:\n        if len(pad) == 0:\n            md5_input = session_id_bytes + key_bytes + version_bytes + seq_no_bytes\n        else:\n            md5_input = session_id_bytes + key_bytes + version_bytes + seq_no_bytes + pad\n        pad += hashlib.md5(md5_input).digest()\n    \n    return pad[:length]\n\ndef encrypt_body(body, session_id, key, version, seq_no):\n    """Encrypt packet body"""\n    if not key:\n        return body\n    pad = md5_pad(session_id, key, version, seq_no, len(body))\n    return bytes(a ^ b for a, b in zip(body, pad))\n\ndef decrypt_body(body, session_id, key, version, seq_no):\n    """Decrypt packet body"""\n    if not key:\n        return body\n    pad = md5_pad(session_id, key, version, seq_no, len(body))\n    return bytes(a ^ b for a, b in zip(body, pad))\n\ndef test_pap_authentication(host=\'localhost\', port=49, key=\'tacacs123\', \n                           username=\'admin\', password=\'admin123\'):\n    """Test TACACS+ PAP authentication"""\n    print(f"Testing TACACS+ PAP authentication:")\n    print(f"  Server: {host}:{port}")\n    print(f"  Username: {username}")\n    print(f"  Password: {\'*\' * len(password)}")\n    print()\n    \n    try:\n        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        sock.settimeout(10)\n        sock.connect((host, port))\n        \n        # Create authentication request (PAP)\n        session_id = int(time.time()) & 0xFFFFFFFF\n        \n        # Prepare packet data\n        user_bytes = username.encode(\'utf-8\')\n        port_bytes = b"console"\n        rem_addr_bytes = b"127.0.0.1"\n        data_bytes = password.encode(\'utf-8\')\n        \n        body = struct.pack(\'!BBBBBBBB\',\n                          1,  # action: LOGIN\n                          15, # priv_lvl\n                          2,  # authen_type: PAP\n                          1,  # service: LOGIN\n                          len(user_bytes),\n                          len(port_bytes),\n                          len(rem_addr_bytes),\n                          len(data_bytes))\n        \n        body += user_bytes + port_bytes + rem_addr_bytes + data_bytes\n        \n        # Encrypt body\n        version = 0xc0\n        seq_no = 1\n        encrypted_body = encrypt_body(body, session_id, key, version, seq_no)\n        \n        # Create packet header\n        header = struct.pack(\'!BBBBLL\',\n                           version,     # version\n                           1,          # type: Authentication\n                           seq_no,     # seq_no\n                           0,          # flags\n                           session_id, # session_id\n                           len(encrypted_body))  # length\n        \n        # Send packet\n        print("Sending authentication request...")\n        sock.send(header + encrypted_body)\n        \n        # Receive response\n        response_header = sock.recv(12)\n        if len(response_header) == 12:\n            r_version, r_type, r_seq, r_flags, r_session, r_length = struct.unpack(\'!BBBBLL\', response_header)\n            print(f"Response received: type={r_type}, seq={r_seq}, length={r_length}")\n            \n            if r_length > 0:\n                response_body = sock.recv(r_length)\n                if len(response_body) >= r_length:\n                    # Decrypt response body\n                    decrypted = decrypt_body(response_body, r_session, key, r_version, r_seq)\n                    \n                    if len(decrypted) >= 4:\n                        status, flags, msg_len, data_len = struct.unpack(\'!BBHH\', decrypted[:6])\n                        \n                        if status == 1:  # PASS\n                            print("✓ Authentication PASSED")\n                            result = True\n                        elif status == 2:  # FAIL\n                            print("✗ Authentication FAILED")\n                            result = False\n                        else:\n                            print(f"Authentication status: {status}")\n                            result = False\n                        \n                        # Print server message if present\n                        if msg_len > 0 and len(decrypted) > 6:\n                            server_msg = decrypted[6:6+msg_len].decode(\'utf-8\', errors=\'replace\')\n                            print(f"Server message: {server_msg}")\n                        \n                        return result\n            else:\n                print("Empty response body")\n                return False\n        else:\n            print("Invalid response header")\n            return False\n            \n    except Exception as e:\n        print(f"Test error: {e}")\n        return False\n    finally:\n        try:\n            sock.close()\n        except:\n            pass\n\ndef main():\n    """Main test function"""\n    # Parse command line arguments\n    host = sys.argv[1] if len(sys.argv) > 1 else \'localhost\'\n    port = int(sys.argv[2]) if len(sys.argv) > 2 else 49\n    key = sys.argv[3] if len(sys.argv) > 3 else \'tacacs123\'\n    username = sys.argv[4] if len(sys.argv) > 4 else \'admin\'\n    password = sys.argv[5] if len(sys.argv) > 5 else \'admin123\'\n    \n    success = test_pap_authentication(host, port, key, username, password)\n    sys.exit(0 if success else 1)\n\nif __name__ == "__main__":\n    main()\n'
    import os
    import stat
    os.makedirs('scripts', exist_ok=True)
    script_path = 'scripts/test_client.py'
    with open(script_path, 'w') as f:
        f.write(test_client_code)
    st = os.stat(script_path)
    os.chmod(script_path, st.st_mode | stat.S_IEXEC)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='TACACS+ Server')
    parser.add_argument('-c', '--config', default='config/tacacs.conf', help='Configuration file path')
    parser.add_argument('--create-test-client', action='store_true', help='Create test client script and exit')
    parser.add_argument('--validate-config', action='store_true', help='Validate configuration and exit')
    parser.add_argument('--version', action='version', version='TACACS+ Server 1.0')
    args = parser.parse_args()
    for directory in ['config', 'data', 'logs', 'tests', 'scripts']:
        Path(directory).mkdir(exist_ok=True)
    if args.create_test_client:
        try:
            create_test_client_script()
            print('Test client created: scripts/test_client.py')
            print('Usage: python scripts/test_client.py [host] [port] [secret] [username] [password]')
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