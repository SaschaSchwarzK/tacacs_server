"""
TACACS+ AAA Request Handlers
"""
import struct
import logging
from typing import List, Dict, Any, Optional
from .packet import TacacsPacket
from .constants import *
from ..accounting.models import AccountingRecord
from tacacs_server.auth.base import AuthenticationBackend
from ..utils.security import validate_username, sanitize_command, AuthRateLimiter
from ..utils.exceptions import AuthenticationError, AuthorizationError
from ..web.monitoring import PrometheusIntegration

logger = logging.getLogger(__name__)

class AAAHandlers:
    """TACACS+ Authentication, Authorization, and Accounting handlers"""

    def __init__(self, auth_backends: List[AuthenticationBackend], db_logger):
        self.auth_backends = auth_backends
        self.db_logger = db_logger
        self.auth_sessions = {}
        self.rate_limiter = AuthRateLimiter()

    def handle_authentication(self, packet: TacacsPacket) -> TacacsPacket:
        """Handle authentication request with metrics"""
        try:
            if len(packet.body) < 8:
                logger.error('Invalid authentication packet body length')
                return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR)
            action, priv_lvl, authen_type, service, user_len, port_len, rem_addr_len, data_len = struct.unpack('!BBBBBBBB', packet.body[:8])
            offset = 8
            user = self._extract_string(packet.body, offset, user_len)
            offset += user_len
            port = self._extract_string(packet.body, offset, port_len)
            offset += port_len
            rem_addr = self._extract_string(packet.body, offset, rem_addr_len)
            offset += rem_addr_len
            data = packet.body[offset:offset + data_len] if data_len > 0 else b''
            logger.info(f'Authentication request: user={user}, type={authen_type}, action={action}, seq={packet.seq_no}')
            if packet.seq_no == 1:
                return self._handle_auth_start(packet, action, authen_type, user, port, rem_addr, data, priv_lvl)
            else:
                return self._handle_auth_continue(packet, user, data)
        except Exception as e:
            logger.error(f'Authentication error: {e}')
            return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR, 'Internal server error')

    def handle_authorization(self, packet: TacacsPacket) -> TacacsPacket:
        """Handle authorization request"""
        try:
            if len(packet.body) < 8:
                logger.error('Invalid authorization packet body length')
                return self._create_author_response(packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR)
            authen_method, priv_lvl, authen_type, authen_service, user_len, port_len, rem_addr_len, arg_cnt = struct.unpack('!BBBBBBBB', packet.body[:8])
            offset = 8
            arg_lengths = []
            for _ in range(arg_cnt):
                if offset >= len(packet.body):
                    break
                arg_lengths.append(packet.body[offset])
                offset += 1
            user = self._extract_string(packet.body, offset, user_len)
            offset += user_len
            port = self._extract_string(packet.body, offset, port_len)
            offset += port_len
            rem_addr = self._extract_string(packet.body, offset, rem_addr_len)
            offset += rem_addr_len
            args = {}
            for arg_len in arg_lengths:
                if offset + arg_len > len(packet.body):
                    break
                arg_str = self._extract_string(packet.body, offset, arg_len)
                if '=' in arg_str:
                    key, value = arg_str.split('=', 1)
                    args[key] = value
                else:
                    args[arg_str] = ''
                offset += arg_len
            logger.info(f'Authorization request: user={user}, service={authen_service}, args={args}')
            return self._process_authorization(packet, user, authen_service, priv_lvl, args)
        except Exception as e:
            logger.error(f'Authorization error: {e}')
            return self._create_author_response(packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR, 'Internal server error')

    def handle_accounting(self, packet: TacacsPacket) -> TacacsPacket:
        """Handle accounting request"""
        try:
            if len(packet.body) < 9:
                logger.error('Invalid accounting packet body length')
                return self._create_acct_response(packet, TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR)
            flags, authen_method, priv_lvl, authen_type, authen_service, user_len, port_len, rem_addr_len, arg_cnt = struct.unpack('!BBBBBBBBB', packet.body[:9])
            offset = 9
            arg_lengths = []
            for _ in range(arg_cnt):
                if offset >= len(packet.body):
                    break
                arg_lengths.append(packet.body[offset])
                offset += 1
            user = self._extract_string(packet.body, offset, user_len)
            offset += user_len
            port = self._extract_string(packet.body, offset, port_len)
            offset += port_len
            rem_addr = self._extract_string(packet.body, offset, rem_addr_len)
            offset += rem_addr_len
            args = {}
            for arg_len in arg_lengths:
                if offset + arg_len > len(packet.body):
                    break
                arg_str = self._extract_string(packet.body, offset, arg_len)
                if '=' in arg_str:
                    key, value = arg_str.split('=', 1)
                    args[key] = value
                else:
                    args[arg_str] = ''
                offset += arg_len
            logger.info(f'Accounting request: user={user}, flags={flags}, args={args}')
            return self._process_accounting(packet, user, port, rem_addr, flags, authen_service, priv_lvl, args)
        except Exception as e:
            logger.error(f'Accounting error: {e}')
            return self._create_acct_response(packet, TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR, 'Internal server error')

    def _handle_auth_start(self, packet: TacacsPacket, action: int, authen_type: int, user: str, port: str, rem_addr: str, data: bytes, priv_lvl: int) -> TacacsPacket:
        """Handle initial authentication request"""
        if authen_type == TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP:
            password = data.decode('utf-8', errors='replace')
            if self._authenticate_user(user, password):
                return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS, 'Authentication successful')
            else:
                return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL, 'Authentication failed')
        elif authen_type == TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_ASCII:
            session_key = f'{packet.session_id}_{packet.seq_no}'
            if not user:
                self.auth_sessions[session_key] = {'step': 'username'}
                return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETUSER, 'Username: ')
            else:
                self.auth_sessions[session_key] = {'step': 'password', 'username': user}
                return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ')
        elif authen_type == TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_CHAP:
            return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR, 'CHAP authentication not implemented')
        else:
            return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR, f'Unsupported authentication type: {authen_type}')

    def _handle_auth_continue(self, packet: TacacsPacket, user: str, data: bytes) -> TacacsPacket:
        """Handle authentication continuation"""
        session_key = f'{packet.session_id}_{packet.seq_no - 2}'
        session_info = self.auth_sessions.get(session_key)
        if not session_info:
            return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR, 'Invalid session')
        if session_info['step'] == 'username':
            username = data.decode('utf-8', errors='replace').strip()
            session_info['username'] = username
            session_info['step'] = 'password'
            return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETPASS, 'Password: ')
        elif session_info['step'] == 'password':
            password = data.decode('utf-8', errors='replace').strip()
            username = session_info['username']
            del self.auth_sessions[session_key]
            if self._authenticate_user(username, password):
                return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS, 'Authentication successful')
            else:
                return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL, 'Authentication failed')
        else:
            return self._create_auth_response(packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR, 'Invalid authentication step')

    def _process_authorization(self, packet: TacacsPacket, user: str, service: int, priv_lvl: int, args: Dict[str, str]) -> TacacsPacket:
        """Process authorization request"""
        user_attrs = None
        for backend in self.auth_backends:
            try:
                user_attrs = backend.get_user_attributes(user)
                if user_attrs:
                    logger.debug(f'Got user attributes from {backend.name}: {user_attrs}')
                    break
            except Exception as e:
                logger.error(f'Error getting attributes from {backend.name}: {e}')
                continue
        if not user_attrs:
            return self._create_author_response(packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL, 'User not found or no attributes available')
        if not user_attrs.get('enabled', True):
            return self._create_author_response(packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL, 'User account is disabled')
        command = args.get('cmd', args.get('service', ''))
        user_priv = user_attrs.get('privilege_level', 1)
        if priv_lvl > user_priv:
            return self._create_author_response(packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL, f'Insufficient privilege level (required: {priv_lvl}, user: {user_priv})')
        allowed_commands = user_attrs.get('shell_command', [])
        if command and allowed_commands:
            command_authorized = False
            for allowed_cmd in allowed_commands:
                if command.startswith(allowed_cmd):
                    command_authorized = True
                    break
            if not command_authorized and user_priv < 15:
                return self._create_author_response(packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL, f"Command '{command}' not authorized")
        auth_attrs = self._build_authorization_attributes(user_attrs, args)
        return self._create_author_response(packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD, 'Authorization successful', auth_attrs)

    def _process_accounting(self, packet: TacacsPacket, user: str, port: str, rem_addr: str, flags: int, service: int, priv_lvl: int, args: Dict[str, str]) -> TacacsPacket:
        """Process accounting request"""
        if flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START:
            status = 'START'
        elif flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP:
            status = 'STOP'
        elif flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_WATCHDOG:
            status = 'UPDATE'
        else:
            status = 'UNKNOWN'
        record = AccountingRecord(username=user, session_id=packet.session_id, status=status, service=args.get('service', 'unknown'), command=args.get('cmd', args.get('service', 'unknown')), client_ip=rem_addr, port=port, start_time=args.get('start_time'), stop_time=args.get('stop_time'), bytes_in=int(args.get('bytes_in', 0)), bytes_out=int(args.get('bytes_out', 0)), elapsed_time=int(args.get('elapsed_time', 0)), privilege_level=priv_lvl, authentication_method=args.get('authen_method'), nas_port=args.get('nas-port'), nas_port_type=args.get('nas-port-type'), task_id=args.get('task_id'), timezone=args.get('timezone'))
        if self.db_logger.log_accounting(record):
            return self._create_acct_response(packet, TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS, 'Accounting record logged successfully')
        else:
            return self._create_acct_response(packet, TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR, 'Failed to log accounting record')

    def _authenticate_user(self, username: str, password: str, client_ip: str = None) -> bool:
        """Authenticate user against all backends with rate limiting"""

        # Add validation
        if not validate_username(username):
            logger.warning(f"Invalid username format: {username}")
            return False
    
        # Add rate limiting
        if client_ip and not self.rate_limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return False

        # Record attempt
        if client_ip:
            self.rate_limiter.record_attempt(client_ip)

        for backend in self.auth_backends:
            try:
                if backend.authenticate(username, password):
                    logger.info(f'Authentication successful for {username} via {backend.name}')
                    return True
            except AuthenticationError as e:
                logger.warning(f"Auth error with {backend.name} for {username}: {e}")
            except Exception as e:
                logger.error(f"Unexpected authentication error with {backend.name}: {e}")
        logger.info(f'Authentication failed for {username} - no backend accepted credentials')
        return False

    def _build_authorization_attributes(self, user_attrs: Dict[str, Any], request_args: Dict[str, str]) -> Dict[str, Any]:
        """Build authorization response attributes"""
        auth_attrs = {}
        if 'privilege_level' in user_attrs:
            auth_attrs['priv-lvl'] = str(user_attrs['privilege_level'])
        if 'service' in user_attrs:
            auth_attrs['service'] = user_attrs['service']
        if 'shell_command' in user_attrs:
            commands = user_attrs['shell_command']
            if isinstance(commands, list):
                auth_attrs['cmd'] = '|'.join(commands)
        if 'timeout' in user_attrs:
            auth_attrs['timeout'] = str(user_attrs['timeout'])
        if 'idle_timeout' in user_attrs:
            auth_attrs['idletime'] = str(user_attrs['idle_timeout'])
        return auth_attrs

    def _extract_string(self, data: bytes, offset: int, length: int) -> str:
        """Safely extract string from packet data"""
        if offset + length > len(data):
            return ''
        return data[offset:offset + length].decode('utf-8', errors='replace')

    def _create_auth_response(self, request_packet: TacacsPacket, status: int, server_msg: str='', data: str='') -> TacacsPacket:
        """Create authentication response packet"""
        server_msg_bytes = server_msg.encode('utf-8')
        data_bytes = data.encode('utf-8')
        body = struct.pack('!BBHH', status, 0, len(server_msg_bytes), len(data_bytes))
        body += server_msg_bytes + data_bytes
        return TacacsPacket(version=request_packet.version, packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN, seq_no=request_packet.seq_no + 1, flags=request_packet.flags, session_id=request_packet.session_id, length=len(body), body=body)

    def _create_author_response(self, request_packet: TacacsPacket, status: int, server_msg: str='', attrs: Optional[Dict[str, Any]]=None) -> TacacsPacket:
        """Create authorization response packet"""
        server_msg_bytes = server_msg.encode('utf-8')
        args = []
        if attrs:
            for key, value in attrs.items():
                if key != 'password':
                    args.append(f'{key}={value}'.encode('utf-8'))
        arg_cnt = len(args)
        body = struct.pack('!BBHH', status, arg_cnt, len(server_msg_bytes), 0)
        for arg in args:
            body += struct.pack('!B', len(arg))
        body += server_msg_bytes
        for arg in args:
            body += arg
        return TacacsPacket(version=request_packet.version, packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR, seq_no=request_packet.seq_no + 1, flags=request_packet.flags, session_id=request_packet.session_id, length=len(body), body=body)

    def _create_acct_response(self, request_packet: TacacsPacket, status: int, server_msg: str='') -> TacacsPacket:
        """Create accounting response packet"""
        server_msg_bytes = server_msg.encode('utf-8')
        body = struct.pack('!HHH', len(server_msg_bytes), 0, status)
        body += server_msg_bytes
        return TacacsPacket(version=request_packet.version, packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT, seq_no=request_packet.seq_no + 1, flags=request_packet.flags, session_id=request_packet.session_id, length=len(body), body=body)