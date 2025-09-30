import ipaddress
import logging
from types import SimpleNamespace

from tacacs_server.auth.base import AuthenticationBackend
from tacacs_server.auth.local import LocalAuthBackend
from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.devices.store import DeviceGroup, DeviceRecord
from tacacs_server.tacacs.constants import (
    TAC_PLUS_AUTHOR_STATUS,
    TAC_PLUS_PACKET_TYPE,
)
from tacacs_server.tacacs.handlers import AAAHandlers
from tacacs_server.tacacs.packet import TacacsPacket
from tacacs_server.tacacs.server import TacacsServer

def test_local_auth_backend_basic(tmp_path):
    db_path = tmp_path / 'local_auth.db'
    service = LocalUserService(db_path)
    service.create_user('admin', password='admin123')
    backend = LocalAuthBackend(str(db_path))
    assert getattr(backend, 'name', '') == 'local'
    stats = backend.get_stats()
    assert isinstance(stats, dict)
    assert 'total_users' in stats
    assert stats['total_users'] >= 0

def test_local_auth_backend_rejects_wrong_password(tmp_path):
    db_path = tmp_path / 'local_auth.db'
    service = LocalUserService(db_path)
    service.create_user('admin', password='admin123')
    backend = LocalAuthBackend(str(db_path))
    assert backend.authenticate('admin', 'wrongpassword') is False


def test_local_auth_backend_cache_invalidation(tmp_path):
    db_path = tmp_path / 'local_auth.db'
    service = LocalUserService(db_path)
    service.create_user('alice', password='password1')
    backend = LocalAuthBackend(str(db_path), service=service)

    assert backend.authenticate('alice', 'password1') is True

    service.set_password('alice', 'password2', store_hash=True)

    assert backend.authenticate('alice', 'password2') is True
    assert backend.authenticate('alice', 'password1') is False


class StaticBackend(AuthenticationBackend):
    def __init__(self, attrs):
        super().__init__("static")
        self._attrs = attrs

    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        return True

    def get_user_attributes(self, username: str) -> dict:
        return dict(self._attrs)


def _make_device(allowed_groups, tacacs_secret: str | None = None):
    group = DeviceGroup(
        id=1,
        name="firewall",
        description=None,
        tacacs_profile={},
        radius_profile={},
        metadata={},
        tacacs_secret=tacacs_secret,
        radius_secret=None,
        device_config={},
        allowed_user_groups=allowed_groups,
    )
    return DeviceRecord(
        id=1,
        name="fw1",
        network=ipaddress.ip_network("192.0.2.1/32"),
        group=group,
        tacacs_secret=tacacs_secret,
        radius_secret=None,
        metadata={},
    )


def _build_authorization_packet(session_id: int = 1234) -> TacacsPacket:
    return TacacsPacket(
        version=0xC0,
        packet_type=TAC_PLUS_PACKET_TYPE.TAC_PLUS_AUTHOR,
        seq_no=1,
        flags=0,
        session_id=session_id,
        length=0,
        body=b'',
    )


def test_tacacs_authorization_requires_device_user_group():
    backend = StaticBackend(
        {
            'groups': ['firewall-admins'],
            'privilege_level': 1,
            'enabled': True,
        }
    )
    handlers = AAAHandlers([backend], db_logger=None)
    handlers.set_local_user_group_service(
        SimpleNamespace(get_group=lambda name: SimpleNamespace(privilege_level=12))
    )
    device = _make_device(['firewall-admins'])
    packet = _build_authorization_packet()

    response = handlers._process_authorization(
        packet,
        user='alice',
        service=1,
        priv_lvl=10,
        args={'cmd': 'show'},
        device=device,
    )

    assert response.body[0] == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_PASS_ADD


def test_tacacs_authorization_denies_unmatched_group():
    backend = StaticBackend(
        {
            'groups': ['datacenter'],
            'privilege_level': 15,
            'enabled': True,
        }
    )
    handlers = AAAHandlers([backend], db_logger=None)
    handlers.set_local_user_group_service(
        SimpleNamespace(get_group=lambda name: SimpleNamespace(privilege_level=5))
    )
    device = _make_device(['firewall-admins'])
    packet = _build_authorization_packet(session_id=5678)

    response = handlers._process_authorization(
        packet,
        user='bob',
        service=1,
        priv_lvl=5,
        args={'cmd': 'show'},
        device=device,
    )

    assert response.body[0] == TAC_PLUS_AUTHOR_STATUS.TAC_PLUS_AUTHOR_STATUS_FAIL


def test_tacacs_resolves_device_secret():
    server = TacacsServer()
    device = _make_device(['firewall'], tacacs_secret='device-secret')
    assert server._resolve_tacacs_secret(device) == 'device-secret'


def test_tacacs_session_secret_prefers_device_secret():
    server = TacacsServer(secret_key='fallback')
    group = SimpleNamespace(tacacs_secret='device-secret', metadata={})
    device = SimpleNamespace(group=group, metadata={}, name='test-device')

    secret = server._select_session_secret(123, device)

    assert secret == 'device-secret'
    assert server.session_secrets[123] == 'device-secret'
    assert server.handlers.session_device[123] is device


def test_tacacs_session_secret_falls_back_when_group_missing():
    server = TacacsServer(secret_key='fallback')
    device = SimpleNamespace(group=None, metadata={}, name='test-device')

    secret = server._select_session_secret(456, device)

    assert secret == 'fallback'
    assert server.session_secrets[456] == 'fallback'


def test_tacacs_logs_cached_username_on_failure(caplog):
    handlers = AAAHandlers([], db_logger=None)
    session_id = 42
    handlers.session_usernames[session_id] = 'admin'
    device = SimpleNamespace(name='firewall', group=None)

    with caplog.at_level(logging.WARNING, logger='tacacs_server.tacacs.handlers'):
        handlers._log_auth_result(session_id, '', device, success=False)

    assert any('admin' in record.message for record in caplog.records)
