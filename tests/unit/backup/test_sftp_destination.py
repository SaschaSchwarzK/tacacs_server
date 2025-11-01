from __future__ import annotations

import io
import stat as statmod
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tacacs_server.backup.destinations.sftp import SFTPBackupDestination


class _MemSFTP:
    """In-memory SFTP mock implementing minimal API used by destination."""

    def __init__(self):
        self.fs: dict[str, bytes] = {}
        self.cwd_path = "/"

    class _File:
        def __init__(self, sftp: _MemSFTP, path: str, mode: str):
            self.sftp = sftp
            self.path = path
            self.mode = mode
            self.buf = io.BytesIO()

        def write(self, data: bytes):
            return self.buf.write(data)

        def read(self) -> bytes:
            return self.sftp.fs[self.path]

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if "w" in self.mode:
                self.sftp.fs[self.path] = self.buf.getvalue()
            self.buf.close()
            return False

    def file(self, path: str, mode: str):
        p = path if path.startswith("/") else f"{self.cwd_path.rstrip('/')}/{path}"
        return _MemSFTP._File(self, p, mode)

    def put(self, local_path: str, remote_path: str, callback=None):
        with open(local_path, "rb") as f:
            data = f.read()
        self.fs[remote_path] = data
        if callback:
            callback(len(data), len(data))

    def get(self, remote_path: str, local_path: str):
        with open(local_path, "wb") as f:
            f.write(self.fs[remote_path])

    def listdir_attr(self, dirpath: str):
        items = []
        # Normalize path for comparison
        prefix = dirpath.rstrip("/")
        if prefix and not prefix.startswith("/"):
            prefix = "/" + prefix
        prefix = prefix + "/" if prefix else "/"

        seen_dirs = set()
        for p, data in self.fs.items():
            # Ensure path starts with /
            full_path = p if p.startswith("/") else "/" + p

            if full_path.startswith(prefix):
                name = full_path[len(prefix) :]
                if "/" in name:
                    # Return first level directory
                    dirname = name.split("/")[0]
                    if dirname not in seen_dirs:
                        seen_dirs.add(dirname)
                        items.append(
                            SimpleNamespace(
                                filename=dirname,
                                st_mode=statmod.S_IFDIR,
                                st_size=0,
                                st_mtime=0,
                            )
                        )
                else:
                    items.append(
                        SimpleNamespace(
                            filename=name,
                            st_mode=statmod.S_IFREG,
                            st_size=len(data),
                            st_mtime=0,
                        )
                    )
        return items

    def stat(self, path: str):
        data = self.fs[path]
        return SimpleNamespace(st_size=len(data), st_mtime=0)

    def remove(self, path: str):
        self.fs.pop(path, None)

    def mkdir(self, path: str):
        return None

    def chmod(self, path: str, mode: int):
        return None

    def chdir(self, path: str):
        self.cwd_path = path


def _make_dest(
    monkeypatch: pytest.MonkeyPatch, **cfg_overrides: Any
) -> SFTPBackupDestination:
    original_validate = SFTPBackupDestination.validate_config
    monkeypatch.setattr(SFTPBackupDestination, "validate_config", lambda self: None)
    cfg = {
        "host": "sftp.example.com",
        "port": 22,
        "username": "user",
        "authentication": "password",
        "password": "pass",
        "base_path": "/backups",
    }
    cfg.update(cfg_overrides)
    d = SFTPBackupDestination(cfg)
    d.host = str(cfg.get("host", ""))
    d.port = int(cfg.get("port", 22))
    d.username = str(cfg.get("username", ""))
    d.authentication = str(cfg.get("authentication", "password")).lower()
    d.password = cfg.get("password")
    d.private_key = cfg.get("private_key")
    d.private_key_passphrase = cfg.get("private_key_passphrase")
    d.base_path = str(cfg.get("base_path", "/"))
    d.timeout = int(cfg.get("timeout", 30))
    d.host_key_verify = bool(cfg.get("host_key_verify", True))
    monkeypatch.setattr(SFTPBackupDestination, "validate_config", original_validate)
    return d


def test_validation_password_auth(monkeypatch: pytest.MonkeyPatch):
    d = _make_dest(monkeypatch)
    d.validate_config()


def test_validation_key_auth_content(monkeypatch: pytest.MonkeyPatch):
    d = _make_dest(
        monkeypatch,
        authentication="key",
        private_key="-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n",
    )
    d.validate_config()


def test_validation_missing_auth(monkeypatch: pytest.MonkeyPatch):
    d = _make_dest(monkeypatch, authentication="invalid", password=None)
    with pytest.raises(ValueError):
        d.validate_config()


def test_file_operations_with_mocked_sftp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    mem = _MemSFTP()

    from contextlib import contextmanager

    @contextmanager
    def _cm(self):
        yield mem

    monkeypatch.setattr(SFTPBackupDestination, "_get_sftp_client", _cm)
    d = _make_dest(monkeypatch)

    src = tmp_path / "file.tar.gz"
    content = b"hello sftp"
    src.write_bytes(content)

    remote_path = d.upload_backup(str(src), "foo/bar/file.tar.gz")
    assert remote_path.endswith("/foo/bar/file.tar.gz")

    dl = tmp_path / "dl.tar.gz"
    ok = d.download_backup(remote_path, str(dl))
    assert ok and dl.read_bytes() == content

    items = d.list_backups()
    assert any(it.filename == "file.tar.gz" for it in items)

    assert d.delete_backup(remote_path) is True


def test_password_auth_connect_flow(monkeypatch: pytest.MonkeyPatch):
    class _FakeSSH:
        def __init__(self):
            self.kw = None

        def load_host_keys(self, *_):
            return None

        def set_missing_host_key_policy(self, *_):
            return None

        def connect(self, **kwargs):
            self.kw = kwargs

        def get_transport(self):
            class _T:
                def set_keepalive(self, *_):
                    return None

            return _T()

        def open_sftp(self):
            return _MemSFTP()

        def close(self):
            return None

    fake_paramiko = SimpleNamespace(
        SSHClient=lambda: _FakeSSH(),
        AutoAddPolicy=lambda: object(),
        RSAKey=SimpleNamespace(
            from_private_key=lambda *a, **k: object(),
            from_private_key_file=lambda *a, **k: object(),
        ),
        AuthenticationException=Exception,
        SSHException=Exception,
    )

    import sys

    sys.modules["paramiko"] = fake_paramiko

    d = _make_dest(monkeypatch)
    ok, _ = d.test_connection()
    assert ok is True
