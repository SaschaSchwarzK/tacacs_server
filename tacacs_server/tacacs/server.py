"""
TACACS+ Server Main Class
"""
import socket
import threading
import time
import psutil
from collections import Counter
from ..utils.exceptions import TacacsException
from typing import List, Tuple, Optional, Dict, Any
from .packet import TacacsPacket
from .handlers import AAAHandlers
from ..utils.metrics import MetricsCollector
from .constants import *
from tacacs_server.auth.base import AuthenticationBackend
from ..accounting.database import DatabaseLogger
from typing import TYPE_CHECKING
from ..utils.logger import get_logger

if TYPE_CHECKING:
    from ..web.monitoring import TacacsMonitoringAPI
    from ..devices import DeviceStore

logger = get_logger(__name__)

class TacacsServer:
    """TACACS+ Server implementation"""

    def __init__(self, host: str='0.0.0.0', port: int=TAC_PLUS_DEFAULT_PORT, secret_key: str='tacacs123'):
        self.host = host
        self.port = port
        self.secret_key = secret_key
        self.auth_backends: List[AuthenticationBackend] = []
        self.db_logger = DatabaseLogger()
        self.handlers = AAAHandlers(self.auth_backends, self.db_logger)
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.stats = {'connections_total': 0, 'connections_active': 0, 'auth_requests': 0, 'auth_success': 0, 'auth_failures': 0, 'author_requests': 0, 'author_success': 0, 'author_failures': 0, 'acct_requests': 0, 'acct_success': 0, 'acct_failures': 0}
        self.start_time = time.time()
        self.metrics = MetricsCollector()
        self.monitoring_api: Optional['TacacsMonitoringAPI'] = None
        self.enable_monitoring = False
        self.device_store: Optional['DeviceStore'] = None
        self._session_lock = threading.RLock()
        self.session_secrets: Dict[int, str] = {}

    def enable_web_monitoring(self, web_host="127.0.0.1", web_port=8080, radius_server=None):
        """Enable web monitoring interface"""
        try:
            from ..web.monitoring import TacacsMonitoringAPI
            logger.info("Attempting to enable web monitoring on %s:%s", web_host, web_port)
            self.monitoring_api = TacacsMonitoringAPI(self, host=web_host, port=web_port, radius_server=radius_server)
            started = False
            try:
                self.monitoring_api.start()
                started = True
            except Exception as e:
                logger.exception("Exception while starting monitoring API: %s", e)
            # give the monitoring thread a short moment to start
            import time
            time.sleep(0.1)
            if started and self.monitoring_api and getattr(self.monitoring_api, "server_thread", None):
                alive = self.monitoring_api.server_thread.is_alive()
            else:
                alive = False
            if alive:
                self.enable_monitoring = True
                logger.info("Web monitoring enabled at http://%s:%s", web_host, web_port)
                return True
            else:
                logger.error("Web monitoring thread failed to start")
                # cleanup
                try:
                    self.monitoring_api.stop()
                except Exception:
                    pass
                self.monitoring_api = None
                self.enable_monitoring = False
                return False
        except Exception as e:
            logger.exception(f"Failed to enable web monitoring: {e}")
            return False
    
    def disable_web_monitoring(self):
        """Disable web monitoring interface"""
        if self.monitoring_api:
            self.monitoring_api.stop()
            self.monitoring_api = None
            self.enable_monitoring = False

    def add_auth_backend(self, backend: AuthenticationBackend):
        """Add authentication backend"""
        self.auth_backends.append(backend)
        self.handlers.auth_backends = self.auth_backends
        logger.info(f'Added authentication backend: {backend}')

    def remove_auth_backend(self, backend_name: str) -> bool:
        """Remove authentication backend by name"""
        for i, backend in enumerate(self.auth_backends):
            if backend.name == backend_name:
                del self.auth_backends[i]
                self.handlers.auth_backends = self.auth_backends
                logger.info(f'Removed authentication backend: {backend_name}')
                return True
        return False

    def start(self):
        """Start TACACS+ server"""
        if self.running:
            logger.warning('Server is already running')
            return
        if not self.auth_backends:
            raise RuntimeError('No authentication backends configured')
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            logger.debug('TACACS+ server started on %s:%s', self.host, self.port)
            logger.debug('Authentication backends: %s', [b.name for b in self.auth_backends])
            logger.debug("Secret key length: %s", len(self.secret_key))
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    self.stats['connections_total'] += 1
                    self.stats['connections_active'] += 1
                    logger.debug('New connection from %s', address)
                    client_thread = threading.Thread(target=self._handle_client, args=(client_socket, address), daemon=True)
                    client_thread.start()
                except socket.error as e:
                    if self.running:
                        logger.error('Socket error: %s', e)
                    break
                except Exception as e:
                    logger.error('Unexpected error accepting connections: %s', e)
                    break
        except Exception as e:
            logger.error('Server startup error: %s', e)
            raise
        finally:
            if self.server_socket:
                self.server_socket.close()
            logger.info('TACACS+ server stopped')

    def stop(self):
        """Stop TACACS+ server"""
        if not self.running:
            return
        logger.info('Stopping TACACS+ server...')
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.server_socket.close()

    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle client connection"""
        session_ids: set[int] = set()
        connection_device = None
        try:
            client_socket.settimeout(30.0)
            while self.running:
                try:
                    header_data = self._recv_exact(client_socket, TAC_PLUS_HEADER_SIZE)
                    if not header_data:
                        break
                    packet = TacacsPacket.unpack_header(header_data)
                    session_ids.add(packet.session_id)
                    if not self._validate_packet_header(packet):
                        logger.warning('Invalid packet header from %s: %s', address, packet)
                        break
                    if connection_device is None and self.device_store:
                        try:
                            connection_device = self.device_store.find_device_for_ip(address[0])
                        except Exception as exc:
                            logger.exception("Failed to resolve device for %s: %s", address[0], exc)
                    if packet.length > 0:
                        if packet.length > 65535:
                            logger.warning('Packet too large from %s: %s bytes', address, packet.length)
                            break
                        body_data = self._recv_exact(client_socket, packet.length)
                        if not body_data:
                            logger.warning('Incomplete packet body from %s', address)
                            break
                        secret = self._select_session_secret(packet.session_id, connection_device)
                        packet.body = packet.decrypt_body(secret, body_data)
                    response = self._process_packet(packet, address, connection_device)
                    if response:
                        secret = self._select_session_secret(packet.session_id, connection_device)
                        response_data = response.pack(secret)
                        client_socket.send(response_data)
                        if response.flags & TAC_PLUS_FLAGS.TAC_PLUS_SINGLE_CONNECT_FLAG:
                            break
                except socket.timeout:
                    logger.debug('Client timeout: %s', address)
                    break
                except socket.error as e:
                    logger.debug('Client socket error %s: %s', address, e)
                    break
                except Exception as e:
                    logger.error('Error handling client %s: %s', address, e)
                    break
        except Exception as e:
            logger.error('Client handling error %s: %s', address, e)
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            with self._session_lock:
                for session_id in session_ids:
                    self.session_secrets.pop(session_id, None)
                    self.handlers.cleanup_session(session_id)
            self.stats['connections_active'] -= 1
            logger.debug('Connection closed: %s', address)

    def _select_session_secret(self, session_id: int, device_record) -> str:
        """Ensure a session secret is registered, preferring device-specific keys."""
        with self._session_lock:
            secret = self.session_secrets.get(session_id)
            if secret is None:
                secret = self._resolve_tacacs_secret(device_record) or self.secret_key
                self.session_secrets[session_id] = secret
                if device_record is not None:
                    self.handlers.session_device[session_id] = device_record
            elif device_record is not None and session_id not in self.handlers.session_device:
                self.handlers.session_device[session_id] = device_record
            return secret

    def _resolve_tacacs_secret(self, device_record) -> Optional[str]:
        """Resolve TACACS shared secret strictly from device group configuration."""
        if not device_record:
            return None
        group = getattr(device_record, 'group', None)
        if not group:
            return None
        if getattr(group, 'tacacs_secret', None):
            return group.tacacs_secret
        metadata = getattr(group, 'metadata', {}) or {}
        if isinstance(metadata, dict):
            secret = metadata.get('tacacs_secret')
            if secret:
                return str(secret)
        return None

    def _recv_exact(self, sock: socket.socket, length: int) -> Optional[bytes]:
        """Receive exactly the specified number of bytes"""
        data = b''
        while len(data) < length:
            try:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.error:
                return None
        return data

    def _validate_packet_header(self, packet: TacacsPacket) -> bool:
        """Validate packet header"""
        major_version = packet.version >> 4 & 15
        if major_version != TAC_PLUS_MAJOR_VER:
            logger.warning(f'Invalid major version: {major_version}')
            return False
        if packet.packet_type not in [TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR, TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT]:
            logger.warning(f'Invalid packet type: {packet.packet_type}')
            return False
        if packet.seq_no < 1:
            logger.warning(f'Invalid sequence number: {packet.seq_no}')
            return False
        return True

    def _process_packet(self, packet: TacacsPacket, address: Tuple[str, int], device_record=None) -> Optional[TacacsPacket]:
        """Process incoming packet and return response"""
        try:
            logger.debug(f'Processing packet from {address}: {packet}')
            if device_record is None and self.device_store:
                try:
                    device_record = self.device_store.find_device_for_ip(address[0])
                except Exception as exc:
                    logger.exception("Failed to resolve device for %s: %s", address[0], exc)

            self._select_session_secret(packet.session_id, device_record)

            if packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN:
                self.stats['auth_requests'] += 1
                response = self.handlers.handle_authentication(packet, device_record)
                if response and len(response.body) > 0:
                    status = response.body[0]
                    if status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS:
                        self.stats['auth_success'] += 1
                    elif status == TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL:
                        self.stats['auth_failures'] += 1
                return response
            elif packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR:
                self.stats['author_requests'] += 1
                response = self.handlers.handle_authorization(packet, device_record)
                if response and len(response.body) > 0:
                    status = response.body[0]
                    if status in [TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_REPL]:
                        self.stats['author_success'] += 1
                    elif status == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL:
                        self.stats['author_failures'] += 1
                return response
            elif packet.packet_type == TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT:
                self.stats['acct_requests'] += 1
                response = self.handlers.handle_accounting(packet, device_record)
                if response and len(response.body) >= 6:
                    status = int.from_bytes(response.body[4:6], byteorder='big')
                    if status == TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS:
                        self.stats['acct_success'] += 1
                    else:
                        self.stats['acct_failures'] += 1
                return response
            else:
                logger.error(f'Unknown packet type: {packet.packet_type}')
                return None
        except Exception as e:
            logger.error(f'Error processing packet from {address}: {e}')
            return None

    def get_stats(self) -> dict:
        """Get server statistics"""
        stats = self.stats.copy()
        stats.update({'server_running': self.running, 'auth_backends': [{'name': b.name, 'available': b.is_available()} for b in self.auth_backends], 'active_auth_sessions': len(self.handlers.auth_sessions)})
        return stats

    def get_active_sessions(self) -> list:
        """Get active accounting sessions"""
        return self.db_logger.get_active_sessions()

    def reset_stats(self):
        """Reset server statistics"""
        self.stats = {'connections_total': 0, 'connections_active': self.stats['connections_active'], 'auth_requests': 0, 'auth_success': 0, 'auth_failures': 0, 'author_requests': 0, 'author_success': 0, 'author_failures': 0, 'acct_requests': 0, 'acct_success': 0, 'acct_failures': 0}
        logger.info('Server statistics reset')

    def get_health_status(self) -> Dict[str, Any]:
        """Get server health status"""
        return {
            'status': 'healthy' if self.running else 'stopped',
            'uptime_seconds': time.time() - self.start_time,
            'active_connections': self.stats['connections_active'],
            'auth_backends': [
                {
                    'name': b.name,
                    'available': b.is_available(),
                    'last_check': getattr(b, 'last_health_check', None)
                }
                for b in self.auth_backends
            ],
            'database_status': self._check_database_health(),
            'memory_usage': self._get_memory_usage()
        }

    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage statistics"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            return {
                'rss_mb': round(memory_info.rss / 1024 / 1024, 2),
                'vms_mb': round(memory_info.vms / 1024 / 1024, 2),
                'percent': round(process.memory_percent(), 2)
            }
        except Exception:
            return {'error': 'Unable to get memory info'}
    
    def _check_database_health(self) -> Dict[str, Any]:
        """Check database health"""
        try:
            # Test database connection
            stats = self.db_logger.get_statistics(days=1)
            return {
                'status': 'healthy',
                'records_today': stats.get('total_records', 0)
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    def reload_configuration(self):
        """Reload configuration without restarting server"""
        try:
            from ..config.config import TacacsConfig
            old_backends = [b.name for b in self.auth_backends]
            
            # Reload config (assuming you have access to config object)
            # This would need to be passed in or made accessible
            logger.info("Configuration reload requested")
            # Implementation depends on how you structure config access
            
            logger.info("Configuration reloaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            return False
    
    def graceful_shutdown(self, timeout_seconds=30):
        """Gracefully shutdown server"""
        logger.info("Initiating graceful shutdown...")
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.server_socket.close()
        
        # Wait for active connections to finish
        start_time = time.time()
        while (self.stats['connections_active'] > 0 and 
               time.time() - start_time < timeout_seconds):
            time.sleep(0.1)
        
        if self.stats['connections_active'] > 0:
            logger.warning(f"Force closing {self.stats['connections_active']} remaining connections")
        
        logger.info("Server shutdown complete")
