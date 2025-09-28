import json
import tempfile
from tacacs_server.auth.local import LocalAuthBackend

def test_local_auth_backend_basic(tmp_path):
    users_file = tmp_path / 'users.json'
    users = {'admin': {'password': 'admin123', 'enabled': True}}
    users_file.write_text(json.dumps(users))
    backend = LocalAuthBackend(str(users_file))
    assert getattr(backend, 'name', '') == 'local'
    stats = backend.get_stats()
    assert isinstance(stats, dict)
    assert 'total_users' in stats
    assert stats['total_users'] >= 0

def test_local_auth_backend_rejects_wrong_password(tmp_path):
    users_file = tmp_path / 'users.json'
    users = {'admin': {'password': 'admin123', 'enabled': True}}
    users_file.write_text(json.dumps(users))
    backend = LocalAuthBackend(str(users_file))
    assert backend.authenticate('admin', 'wrongpassword') is False