"""
TACACS+ AAA Request Handlers
"""
import struct
from typing import Any

from tacacs_server.auth.base import AuthenticationBackend

from ..accounting.models import AccountingRecord
from ..utils.exceptions import AuthenticationError
from ..utils.logger import get_logger
from ..utils.policy import PolicyContext, PolicyResult, evaluate_policy
from ..utils.security import AuthRateLimiter, validate_username
from .constants import (
    TAC_PLUS_ACCT_FLAG,
    TAC_PLUS_ACCT_STATUS,
    TAC_PLUS_AUTHEN_STATUS,
    TAC_PLUS_AUTHEN_TYPE,
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_PACKET_TYPE,
)
from .packet import TacacsPacket

logger = get_logger(__name__)


class AAAHandlers:
    """TACACS+ Authentication, Authorization, and Accounting handlers"""

    def __init__(self, auth_backends: list[AuthenticationBackend], db_logger):
        self.auth_backends = auth_backends
        self.db_logger = db_logger
        self.auth_sessions = {}
        self.rate_limiter = AuthRateLimiter()
        self.session_device: dict[int, Any] = {}
        self.session_usernames: dict[int, str] = {}
        self.local_user_group_service = None

    def set_local_user_group_service(self, service) -> None:
        self.local_user_group_service = service

    @staticmethod
    def _safe_user(user: str | None) -> str:
        return user if user else '<unknown>'

    def _remember_username(self, session_id: int, username: str | None) -> None:
        if username:
            self.session_usernames[session_id] = username

    def cleanup_session(self, session_id: int) -> None:
        """Remove cached state associated with a TACACS session."""
        self.session_device.pop(session_id, None)
        self.session_usernames.pop(session_id, None)
        stale_keys = [
            key for key in self.auth_sessions if key.startswith(f'{session_id}_')
        ]
        for key in stale_keys:
            self.auth_sessions.pop(key, None)

    def _log_auth_result(
        self,
        session_id: int,
        username: str | None,
        device: Any | None,
        success: bool,
        detail: str | None = None,
    ) -> None:
        cached_user = self.session_usernames.get(session_id)
        resolved_user = username if username else cached_user
        safe_user = self._safe_user(resolved_user)
        device_name = getattr(device, 'name', None)
        group_name = getattr(getattr(device, 'group', None), 'name', None)
        context = group_name or device_name or 'unknown'
        if success:
            logger.info(
                'TACACS authentication success: user=%s detail=%s device=%s',
                safe_user,
                detail or 'backend=unknown',
                context,
            )
        else:
            logger.warning(
                'TACACS authentication failed: user=%s reason=%s device=%s',
                safe_user,
                detail or 'unknown',
                context,
            )

    def handle_authentication(
        self, packet: TacacsPacket, device: Any | None = None
    ) -> TacacsPacket:
        """Handle authentication request with metrics"""
        try:
            if len(packet.body) < 8:
                logger.error('Invalid authentication packet body length')
                response = self._create_auth_response(
                    packet, TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR
                )
                self.cleanup_session(packet.session_id)
                return response
            (
                action,
                priv_lvl,
                authen_type,
                service,
                user_len,
                port_len,
                rem_addr_len,
                data_len,
            ) = struct.unpack('!BBBBBBBB', packet.body[:8])
            offset = 8
            user = self._extract_string(packet.body, offset, user_len)
            offset += user_len
            port = self._extract_string(packet.body, offset, port_len)
            offset += port_len
            rem_addr = self._extract_string(packet.body, offset, rem_addr_len)
            offset += rem_addr_len
            data = packet.body[offset : offset + data_len] if data_len > 0 else b''
            safe_user = self._safe_user(user)
            logger.debug(
                'TACACS auth request: user=%s, type=%s, action=%s, seq=%s',
                safe_user,
                authen_type,
                action,
                packet.seq_no,
            )
            self._remember_username(packet.session_id, user)
            if packet.seq_no == 1:
                return self._handle_auth_start(
                    packet,
                    action,
                    authen_type,
                    user,
                    port,
                    rem_addr,
                    data,
                    priv_lvl,
                    device,
                )
            else:
                return self._handle_auth_continue(packet, user, data)
        except Exception as e:
            logger.error(f'Authentication error: {e}')
            response = self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                'Internal server error',
            )
            self.cleanup_session(packet.session_id)
            return response

    def handle_authorization(
        self, packet: TacacsPacket, device: Any | None = None
    ) -> TacacsPacket:
        """Handle authorization request"""
        try:
            if len(packet.body) < 8:
                logger.error('Invalid authorization packet body length')
                return self._create_author_response(
                    packet, TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR
                )
            (
                authen_method,
                priv_lvl,
                authen_type,
                authen_service,
                user_len,
                port_len,
                rem_addr_len,
                arg_cnt,
            ) = struct.unpack('!BBBBBBBB', packet.body[:8])

            # Initialize offset and read user, port, rem_addr
            offset = 8
            user = self._extract_string(packet.body, offset, user_len)
            offset += user_len
            _ = self._extract_string(packet.body, offset, port_len)  # port not used
            offset += port_len
            _ = self._extract_string(
                packet.body, offset, rem_addr_len
            )  # rem_addr not used
            offset += rem_addr_len

            # Read argument lengths
            arg_lengths = []
            for _ in range(arg_cnt):
                if offset >= len(packet.body):
                    break
                arg_lengths.append(packet.body[offset])
                offset += 1

            # Parse arguments
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
            logger.info(
                'Authorization request: user=%s, service=%s, args=%s',
                self._safe_user(user),
                authen_service,
                args,
            )
            return self._process_authorization(
                packet, user, authen_service, priv_lvl, args, device
            )
        except Exception as e:
            logger.error(f'Authorization error: {e}')
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_ERROR,
                'Internal server error',
            )

    def handle_accounting(
        self, packet: TacacsPacket, device: Any | None = None
    ) -> TacacsPacket:
        """Handle accounting request"""
        try:
            if len(packet.body) < 9:
                logger.error('Invalid accounting packet body length')
                return self._create_acct_response(
                    packet, TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR
                )
            (
                flags,
                authen_method,
                priv_lvl,
                authen_type,
                authen_service,
                user_len,
                port_len,
                rem_addr_len,
                arg_cnt,
            ) = struct.unpack('!BBBBBBBBB', packet.body[:9])
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
            logger.debug(
                'TACACS accounting request: user=%s, flags=%s, args=%s',
                self._safe_user(user),
                flags,
                args,
            )
            return self._process_accounting(
                packet,
                user,
                port,
                rem_addr,
                flags,
                authen_service,
                priv_lvl,
                args,
                device,
            )
        except Exception as e:
            logger.error(f'Accounting error: {e}')
            return self._create_acct_response(
                packet,
                TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR,
                'Internal server error',
            )

    def _handle_auth_start(
        self,
        packet: TacacsPacket,
        action: int,
        authen_type: int,
        user: str,
        port: str,
        rem_addr: str,
        data: bytes,
        priv_lvl: int,
        device: Any | None,
    ) -> TacacsPacket:
        """Handle initial authentication request"""
        self.session_device[packet.session_id] = device
        if authen_type == TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_PAP:
            password = data.decode('utf-8', errors='replace')
            authenticated, detail = self._authenticate_user(user, password)
            if authenticated:
                self._remember_username(packet.session_id, user)
                self._log_auth_result(packet.session_id, user, device, True, detail)
                return self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS,
                    'Authentication successful',
                )
            else:
                self._log_auth_result(packet.session_id, user, device, False, detail)
                response = self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL,
                    'Authentication failed',
                )
                self.cleanup_session(packet.session_id)
                return response
        elif authen_type == TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_ASCII:
            session_key = f'{packet.session_id}_{packet.seq_no}'
            if not user:
                self.auth_sessions[session_key] = {'step': 'username'}
                return self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETUSER,
                    'Username: ',
                )
            else:
                self.auth_sessions[session_key] = {
                    'step': 'password',
                    'username': user,
                }
                return self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETPASS,
                    'Password: ',
                )
        elif authen_type == TAC_PLUS_AUTHEN_TYPE.TAC_PLUS_AUTHEN_TYPE_CHAP:
            self._log_auth_result(
                packet.session_id,
                user,
                device,
                False,
                'CHAP authentication not implemented',
            )
            response = self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                'CHAP authentication not implemented',
            )
            self.cleanup_session(packet.session_id)
            return response
        else:
            self._log_auth_result(
                packet.session_id,
                user,
                device,
                False,
                f'Unsupported authentication type {authen_type}',
            )
            response = self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                f'Unsupported authentication type: {authen_type}',
            )
            self.cleanup_session(packet.session_id)
            return response

    def _handle_auth_continue(
        self, packet: TacacsPacket, user: str, data: bytes
    ) -> TacacsPacket:
        """Handle authentication continuation"""
        session_key = f'{packet.session_id}_{packet.seq_no - 2}'
        session_info = self.auth_sessions.get(session_key)
        if not session_info:
            return self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                'Invalid session',
            )
        if session_info['step'] == 'username':
            username = data.decode('utf-8', errors='replace').strip()
            session_info['username'] = username
            session_info['step'] = 'password'
            self._remember_username(packet.session_id, username)
            return self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_GETPASS,
                'Password: ',
            )
        elif session_info['step'] == 'password':
            password = data.decode('utf-8', errors='replace').strip()
            username = session_info['username']
            del self.auth_sessions[session_key]
            authenticated, detail = self._authenticate_user(username, password)
            if authenticated:
                device = self.session_device.get(packet.session_id)
                self._remember_username(packet.session_id, username)
                self._log_auth_result(
                    packet.session_id, username, device, True, detail
                )
                return self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_PASS,
                    'Authentication successful',
                )
            else:
                device = self.session_device.get(packet.session_id)
                self._log_auth_result(
                    packet.session_id, username, device, False, detail
                )
                response = self._create_auth_response(
                    packet,
                    TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_FAIL,
                    'Authentication failed',
                )
                self.cleanup_session(packet.session_id)
                return response
        else:
            response = self._create_auth_response(
                packet,
                TAC_PLUS_AUTHEN_STATUS.TAC_PLUS_AUTHEN_STATUS_ERROR,
                'Invalid authentication step',
            )
            self.cleanup_session(packet.session_id)
            return response

    def _process_authorization(
        self,
        packet: TacacsPacket,
        user: str,
        service: int,
        priv_lvl: int,
        args: dict[str, str],
        device: Any | None,
    ) -> TacacsPacket:
        """Process authorization request"""
        user_attrs = None
        for backend in self.auth_backends:
            try:
                user_attrs = backend.get_user_attributes(user)
                if user_attrs:
                    logger.debug(
                        f'Got user attributes from {backend.name}: {user_attrs}'
                    )
                    break
            except Exception as e:
                logger.error(f'Error getting attributes from {backend.name}: {e}')
                continue
        if not user_attrs:
            self.cleanup_session(packet.session_id)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                'User not found or no attributes available',
            )
        if not user_attrs.get('enabled', True):
            self.cleanup_session(packet.session_id)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                'User account is disabled',
            )

        device_record = device or self.session_device.get(packet.session_id)
        device_group = getattr(device_record, 'group', None) if device_record else None
        if device_group:
            allowed_groups = getattr(device_group, 'allowed_user_groups', [])
            device_group_name = getattr(device_group, 'name', None)
        else:
            allowed_groups = []
            device_group_name = None

        context = PolicyContext(
            device_group_name=device_group_name,
            allowed_user_groups=allowed_groups,
            user_groups=user_attrs.get('groups', []) or [],
            fallback_privilege=user_attrs.get('privilege_level', 1),
        )

        def _lookup_privilege(group_name: str) -> int | None:
            if not self.local_user_group_service:
                return None
            record = self.local_user_group_service.get_group(group_name)
            return getattr(record, 'privilege_level', None)

        result: PolicyResult = evaluate_policy(context, _lookup_privilege)
        user_priv = result.privilege_level
        user_attrs['privilege_level'] = user_priv
        if not result.allowed:
            self.cleanup_session(packet.session_id)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                result.denial_message or 'User not permitted on this device',
            )

        command = args.get('cmd', args.get('service', ''))
        if priv_lvl > user_priv:
            self.cleanup_session(packet.session_id)
            return self._create_author_response(
                packet,
                TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                f'Insufficient privilege level (required: {priv_lvl}, '
                f'user: {user_priv})',
            )
        allowed_commands = user_attrs.get('shell_command', [])
        if command and allowed_commands:
            command_authorized = False
            for allowed_cmd in allowed_commands:
                if command.startswith(allowed_cmd):
                    command_authorized = True
                    break
            if not command_authorized and user_priv < 15:
                self.cleanup_session(packet.session_id)
                return self._create_author_response(
                    packet,
                    TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL,
                    f"Command '{command}' not authorized",
                )
        auth_attrs = self._build_authorization_attributes(user_attrs, args)
        self.cleanup_session(packet.session_id)
        return self._create_author_response(
            packet,
            TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            'Authorization successful',
            auth_attrs,
        )

    def _process_accounting(
        self,
        packet: TacacsPacket,
        user: str,
        port: str,
        rem_addr: str,
        flags: int,
        service: int,
        priv_lvl: int,
        args: dict[str, str],
        device: Any | None,
    ) -> TacacsPacket:
        """Process accounting request"""
        if flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_START:
            status = 'START'
        elif flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_STOP:
            status = 'STOP'
        elif flags & TAC_PLUS_ACCT_FLAG.TAC_PLUS_ACCT_FLAG_WATCHDOG:
            status = 'UPDATE'
        else:
            status = 'UNKNOWN'
        record = AccountingRecord(
            username=user,
            session_id=packet.session_id,
            status=status,
            service=args.get('service', 'unknown'),
            command=args.get('cmd', args.get('service', 'unknown')),
            client_ip=rem_addr,
            port=port,
            start_time=args.get('start_time'),
            stop_time=args.get('stop_time'),
            bytes_in=int(args.get('bytes_in', 0)),
            bytes_out=int(args.get('bytes_out', 0)),
            elapsed_time=int(args.get('elapsed_time', 0)),
            privilege_level=priv_lvl,
            authentication_method=args.get('authen_method'),
            nas_port=args.get('nas-port'),
            nas_port_type=args.get('nas-port-type'),
            task_id=args.get('task_id'),
            timezone=args.get('timezone'),
        )
        if self.db_logger.log_accounting(record):
            response = self._create_acct_response(
                packet,
                TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_SUCCESS,
                'Accounting record logged successfully',
            )
        else:
            response = self._create_acct_response(
                packet,
                TAC_PLUS_ACCT_STATUS.TAC_PLUS_ACCT_STATUS_ERROR,
                'Failed to log accounting record',
            )
        self.cleanup_session(packet.session_id)
        return response

    def _authenticate_user(
        self, username: str, password: str, client_ip: str | None = None
    ) -> tuple[bool, str]:
        """Authenticate user against all backends with rate limiting."""

        if not validate_username(username):
            return False, 'invalid username format'

        if client_ip and not self.rate_limiter.is_allowed(client_ip):
            return False, f'rate limit exceeded for {client_ip}'

        if client_ip:
            self.rate_limiter.record_attempt(client_ip)

        last_error: str | None = None
        for backend in self.auth_backends:
            try:
                if backend.authenticate(username, password):
                    return True, f'backend={backend.name}'
            except AuthenticationError as exc:
                last_error = f'backend={backend.name} error={exc}'
                logger.warning(
                    "Auth error with %s for %s: %s", backend.name, username, exc
                )
            except Exception as exc:
                last_error = f'backend={backend.name} error={exc}'
                logger.error(
                    "Unexpected authentication error with %s: %s", backend.name, exc
                )

        if last_error:
            return False, last_error

        if not self.auth_backends:
            return False, 'no authentication backends configured'

        return False, 'no backend accepted credentials'

    def _build_authorization_attributes(
        self, user_attrs: dict[str, Any], request_args: dict[str, str]
    ) -> dict[str, Any]:
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
        return data[offset : offset + length].decode('utf-8', errors='replace')

    def _create_auth_response(
        self,
        request_packet: TacacsPacket,
        status: int,
        server_msg: str = '',
        data: str = '',
    ) -> TacacsPacket:
        """Create authentication response packet"""
        server_msg_bytes = server_msg.encode('utf-8')
        data_bytes = data.encode('utf-8')
        body = struct.pack('!BBHH', status, 0, len(server_msg_bytes), len(data_bytes))
        body += server_msg_bytes + data_bytes
        return TacacsPacket(
            version=request_packet.version,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHEN,
            seq_no=request_packet.seq_no + 1,
            flags=request_packet.flags,
            session_id=request_packet.session_id,
            length=len(body),
            body=body,
        )

    def _create_author_response(
        self,
        request_packet: TacacsPacket,
        status: int,
        server_msg: str = '',
        attrs: dict[str, Any] | None = None,
    ) -> TacacsPacket:
        """Create authorization response packet"""
        server_msg_bytes = server_msg.encode('utf-8')
        args = []
        if attrs:
            for key, value in attrs.items():
                if key != 'password':
                    args.append(f'{key}={value}'.encode())
        arg_cnt = len(args)
        body = struct.pack('!BBHH', status, arg_cnt, len(server_msg_bytes), 0)
        for arg in args:
            body += struct.pack('!B', len(arg))
        body += server_msg_bytes
        for arg in args:
            body += arg
        return TacacsPacket(
            version=request_packet.version,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
            seq_no=request_packet.seq_no + 1,
            flags=request_packet.flags,
            session_id=request_packet.session_id,
            length=len(body),
            body=body,
        )

    def _create_acct_response(
        self, request_packet: TacacsPacket, status: int, server_msg: str = ''
    ) -> TacacsPacket:
        """Create accounting response packet"""
        server_msg_bytes = server_msg.encode('utf-8')
        body = struct.pack('!HHH', len(server_msg_bytes), 0, status)
        body += server_msg_bytes
        return TacacsPacket(
            version=request_packet.version,
            packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_ACCT,
            seq_no=request_packet.seq_no + 1,
            flags=request_packet.flags,
            session_id=request_packet.session_id,
            length=len(body),
            body=body,
        )