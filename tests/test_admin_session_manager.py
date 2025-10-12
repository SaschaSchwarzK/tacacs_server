import pytest


def _bcrypt_hash(pwd: str) -> str:
    try:
        import bcrypt

        return bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt()).decode()
    except Exception:  # pragma: no cover - environment without bcrypt
        pytest.skip("bcrypt not available for admin session tests")


def test_admin_session_manager_accepts_only_configured_user():
    from tacacs_server.web.admin.auth import AdminAuthConfig, AdminSessionManager

    pwd = "AdminPass123!"
    hash_ = _bcrypt_hash(pwd)

    cfg = AdminAuthConfig(
        username="admin", password_hash=hash_, session_timeout_minutes=60
    )
    mgr = AdminSessionManager(cfg)

    # Correct username/password works
    token = mgr.login("admin", pwd)
    assert isinstance(token, str) and len(token) > 0

    # Wrong username rejected
    with pytest.raises(Exception):
        mgr.login("user", pwd)


def test_admin_session_manager_rejects_wrong_password():
    from tacacs_server.web.admin.auth import AdminAuthConfig, AdminSessionManager

    pwd = "AdminPass123!"
    hash_ = _bcrypt_hash(pwd)

    cfg = AdminAuthConfig(
        username="admin", password_hash=hash_, session_timeout_minutes=60
    )
    mgr = AdminSessionManager(cfg)

    with pytest.raises(Exception):
        mgr.login("admin", "WrongPass")
