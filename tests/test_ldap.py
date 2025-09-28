import importlib
import sys
import types
import inspect
import pytest

def _inject_fake_ldap3(monkeypatch):
    fake = types.ModuleType("ldap3")

    class FakeServer:
        def __init__(self, uri, *args, **kwargs):
            self.uri = uri

    class FakeConnection:
        def __init__(self, server, user=None, password=None, auto_bind=False, *args, **kwargs):
            self.server = server
            self.user = user
            self.password = password
            # Simulate successful bind only for password == "validpass"
            self.bound = (password == "validpass")
            self.entries = []

        def bind(self):
            return self.bound

        def unbind(self):
            self.bound = False

        def search(self, *args, **kwargs):
            return True

        # Support context manager protocol used by auth.ldap_auth
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            try:
                self.unbind()
            except Exception:
                pass
            # don't suppress exceptions
            return False

    fake.Server = FakeServer
    fake.Connection = FakeConnection
    fake.ALL = "ALL"

    # Provide core.exceptions.LDAPException used in exception handling
    core_mod = types.SimpleNamespace()
    core_mod.exceptions = types.SimpleNamespace(LDAPException=Exception)
    fake.core = core_mod

    monkeypatch.setitem(sys.modules, "ldap3", fake)
    return fake

def _make_backend(ldap_mod, cfg):
    cls = ldap_mod.LDAPAuthBackend
    try:
        return cls(cfg)
    except TypeError:
        pass

    sig = inspect.signature(cls.__init__)
    params = list(sig.parameters.keys())[1:]

    kwargs = {}
    mapping = {
        "server": cfg.get("server"),
        "base_dn": cfg.get("base_dn"),
        "user_attribute": cfg.get("user_attribute"),
        "bind_dn": cfg.get("bind_dn"),
        "bind_password": cfg.get("bind_password"),
        "timeout": int(cfg.get("timeout")) if cfg.get("timeout") else None,
    }
    for name in params:
        if name in mapping and mapping[name] is not None:
            kwargs[name] = mapping[name]

    if kwargs:
        try:
            return cls(**kwargs)
        except TypeError:
            pass

    try:
        return cls(cfg["server"], cfg["base_dn"])
    except Exception as e:
        raise RuntimeError(f"Could not instantiate LDAPAuthBackend with available signatures: {e}")

def test_ldap_auth_success(monkeypatch):
    _inject_fake_ldap3(monkeypatch)
    ldap_mod = importlib.import_module("tacacs_server.auth.ldap_auth")
    importlib.reload(ldap_mod)

    cfg = {
        "server": "ldap://localhost:389",
        "base_dn": "ou=people,dc=example,dc=com",
        "user_attribute": "uid",
        "bind_dn": "",
        "bind_password": "",
        "timeout": "5",
    }

    backend = _make_backend(ldap_mod, cfg)
    assert backend.authenticate("jdoe", "validpass") is True

def test_ldap_auth_fail_wrong_password(monkeypatch):
    _inject_fake_ldap3(monkeypatch)
    ldap_mod = importlib.import_module("tacacs_server.auth.ldap_auth")
    importlib.reload(ldap_mod)

    cfg = {
        "server": "ldap://localhost:389",
        "base_dn": "ou=people,dc=example,dc=com",
        "user_attribute": "uid",
        "bind_dn": "",
        "bind_password": "",
        "timeout": "5",
    }

    backend = _make_backend(ldap_mod, cfg)
    assert backend.authenticate("jdoe", "badpass") is False