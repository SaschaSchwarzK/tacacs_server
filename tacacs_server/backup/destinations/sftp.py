from __future__ import annotations

import io
import os
import re
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.retry import retry

from .base import BackupDestination, BackupMetadata

_logger = get_logger(__name__)


class SFTPConnection:
    """Context manager for SFTP connections.

    Handles SSH authentication (password or key), host key policy, known_hosts,
    keepalive, and socket timeouts. Returns a paramiko.SFTPClient.
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.ssh_client = None
        self.sftp_client = None

    def __enter__(self):  # -> paramiko.SFTPClient
        try:
            import importlib
            from typing import Any as _Any

            paramiko_mod: _Any = importlib.import_module("paramiko")
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"Paramiko unavailable: {exc}")
        ssh = paramiko_mod.SSHClient()
        known_hosts_file = self.config.get("known_hosts_file")
        host_key_verify = bool(self.config.get("host_key_verify", True))
        if known_hosts_file:
            try:
                ssh.load_host_keys(known_hosts_file)
            except Exception:
                _logger.warning("Failed to load known_hosts file: %s", known_hosts_file)
        # Enforce host key verification by default
        if host_key_verify:
            # Reject unknown hosts unless explicitly disabled
            try:
                ssh.set_missing_host_key_policy(paramiko_mod.RejectPolicy())
            except Exception:
                # Fallback to default policy
                pass
        else:
            # Disallow disabling host key verification to meet security policy
            raise ValueError(
                "SFTP host key verification cannot be disabled (host_key_verify=false)"
            )

        connect_kwargs: dict[str, Any] = {
            "hostname": self.config.get("host"),
            "port": int(self.config.get("port", 22)),
            "username": self.config.get("username"),
            "timeout": int(self.config.get("timeout", 30)),
            "banner_timeout": int(self.config.get("timeout", 30)),
            "auth_timeout": int(self.config.get("timeout", 30)),
        }
        if str(self.config.get("authentication", "password")).lower() == "password":
            connect_kwargs["password"] = self.config.get("password")
        else:
            # Key-based auth
            pkey = None
            try:
                if (
                    str(self.config.get("private_key", ""))
                    .strip()
                    .startswith("-----BEGIN")
                ):
                    key_file = io.StringIO(str(self.config.get("private_key")))
                    pkey = paramiko_mod.RSAKey.from_private_key(
                        key_file, password=self.config.get("private_key_passphrase")
                    )
                else:
                    pkey = paramiko_mod.RSAKey.from_private_key_file(
                        str(self.config.get("private_key")),
                        password=self.config.get("private_key_passphrase"),
                    )
            except Exception as exc:
                raise ValueError(f"Invalid private key: {exc}")
            connect_kwargs["pkey"] = pkey

        try:
            ssh.connect(**connect_kwargs)
        except Exception as exc:
            # Avoid direct paramiko types to keep type-checkers happy without stubs
            msg = str(getattr(exc, "__class__", type(exc)).__name__)
            if "Authentication" in msg:
                raise RuntimeError(f"SFTP authentication failed: {exc}")
            raise RuntimeError(f"SFTP connection error: {exc}")

        self.ssh_client = ssh
        # Keepalive
        try:
            transport = ssh.get_transport()
            if transport:
                transport.set_keepalive(30)
        except Exception:
            pass
        # Open SFTP
        self.sftp_client = ssh.open_sftp()
        return self.sftp_client

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.sftp_client:
                self.sftp_client.close()
        except Exception:
            pass
        try:
            if self.ssh_client:
                self.ssh_client.close()
        except Exception:
            pass


class SFTPBackupDestination(BackupDestination):
    """Store backups on SFTP server using Paramiko."""

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.host: str = str(self.config.get("host", ""))
        self.port: int = int(self.config.get("port", 22))
        self.username: str = str(self.config.get("username", ""))
        self.authentication: str = str(
            self.config.get("authentication", "password")
        ).lower()
        self.password: str | None = self.config.get("password")
        self.private_key: str | None = self.config.get("private_key")
        self.private_key_passphrase: str | None = self.config.get(
            "private_key_passphrase"
        )
        self.base_path: str = str(self.config.get("base_path", "/"))
        self.timeout: int = int(self.config.get("timeout", 30))
        self.host_key_verify: bool = bool(self.config.get("host_key_verify", True))
        self.known_hosts_file: str | None = self.config.get("known_hosts_file")

    def validate_config(self) -> None:
        # Required common
        missing = [
            k for k in ("host", "username", "base_path") if not self.config.get(k)
        ]
        if missing:
            raise ValueError(f"Missing required config: {', '.join(missing)}")
        # Auth-specific
        auth = self.authentication
        if auth not in ("password", "key"):
            raise ValueError("authentication must be 'password' or 'key'")
        if auth == "password" and not self.password:
            raise ValueError("password required for password authentication")
        if auth == "key" and not self.private_key:
            raise ValueError("private_key required for key authentication")
        # Port
        if self.port < 1 or self.port > 65535:
            raise ValueError("Invalid SFTP port; must be 1-65535")
        # base path
        bp = self.base_path.replace("\\", "/")
        if ".." in bp or "\x00" in bp:
            raise ValueError("Invalid base_path")
        if not self.host_key_verify:
            _logger.warning("SFTP host_key_verify disabled — security risk")

    @contextmanager
    def _get_sftp_client(self):
        """Compatibility wrapper around SFTPConnection context manager."""
        with SFTPConnection(
            {
                "host": self.host,
                "port": self.port,
                "username": self.username,
                "authentication": self.authentication,
                "password": self.password,
                "private_key": self.private_key,
                "private_key_passphrase": self.private_key_passphrase,
                "timeout": self.timeout,
                "base_path": self.base_path,
                "host_key_verify": self.host_key_verify,
                "known_hosts_file": self.known_hosts_file,
            }
        ) as sftp:
            # Ensure base path exists and chdir for consumer operations
            try:
                self._sftp_makedirs(sftp, self.base_path)
                sftp.chdir(self.base_path)
            except Exception:
                pass
            yield sftp

    @staticmethod
    def _normalize_remote_path(path: str) -> str:
        p = path.replace("\\", "/")
        return p if p.startswith("/") else f"/{p}"

    def _safe_remote_path(self, path: str) -> str:
        """Build a safe absolute remote path under base_path.

        Accepts either a relative key (validated) or an absolute path that must
        be under the configured base_path. Rejects traversal and control chars.
        """
        base_abs = self._normalize_remote_path(self.base_path).rstrip("/")
        p = str(path or "").replace("\\", "/").strip()
        if not p:
            raise ValueError("Empty remote path")
        if "\x00" in p:
            raise ValueError("Invalid remote path")
        # Absolute path: ensure it resides under base_abs
        if p.startswith("/"):
            # Normalize duplicate slashes
            while "//" in p:
                p = p.replace("//", "/")
            if not p.startswith(base_abs + "/") and p != base_abs:
                raise ValueError("Remote path escapes base path")
            # Basic traversal guard
            if "/../" in p or p.endswith("/.."):
                raise ValueError("Path traversal detected")
            return p
        # Relative path: validate segments and join to base
        from .base import BackupDestination as _BD

        rel = _BD.validate_relative_path(p)
        return f"{base_abs}/{rel}"

    def _sftp_makedirs(self, sftp, remote_dir: str) -> None:
        parts = self._normalize_remote_path(remote_dir).strip("/").split("/")
        cur = ""
        for part in parts:
            cur = f"{cur}/{part}" if cur else f"/{part}"
            try:
                sftp.mkdir(cur)
            except OSError:
                # already exists
                pass

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def test_connection(self) -> tuple[bool, str]:
        try:
            with self._get_sftp_client() as sftp:
                # test write/read/delete
                test_name = ".connect_test"
                data = b"ok"
                with sftp.file(test_name, "wb") as f:
                    f.write(data)
                with sftp.file(test_name, "rb") as f:
                    if f.read() != data:
                        return False, "I/O verification failed"
                sftp.remove(test_name)
            return True, "Connected successfully"
        except Exception as exc:
            return False, str(exc)

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        # Validate and build safe remote path under base_path
        rp = self._safe_remote_path(remote_filename)
        with self._get_sftp_client() as sftp:
            dir_part = os.path.dirname(rp)
            self._sftp_makedirs(sftp, dir_part)
            size_local = os.path.getsize(local_file_path)

            last = 0

            def _cb(transferred, total):
                nonlocal last
                # Paramiko passes cumulative transferred
                if transferred - last >= 8192 * 128:
                    _logger.info("sftp_upload_progress", bytes_sent=transferred)
                    last = transferred

            try:
                sftp.put(local_file_path, rp, callback=_cb)
                sftp.chmod(rp, 0o644)
            except Exception as exc:
                # cleanup partial
                try:
                    sftp.remove(rp)
                except Exception:
                    pass
                raise RuntimeError(f"Upload failed: {exc}")
            # verify size
            try:
                st = sftp.stat(rp)
                if int(st.st_size) != int(size_local):
                    raise RuntimeError(
                        f"Upload verification failed: size mismatch ({st.st_size} != {size_local})"
                    )
            except Exception as exc:
                _logger.warning("sftp_upload_verify_failed", error=str(exc))
        return rp

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        try:
            rp = self._safe_remote_path(remote_path)
            Path(local_file_path).parent.mkdir(parents=True, exist_ok=True)
            with self._get_sftp_client() as sftp:
                sftp.get(rp, local_file_path)
            return True
        except Exception as exc:
            _logger.error(
                "sftp_download_failed", error=str(exc), remote_path=remote_path
            )
            return False

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def list_backups(self, prefix: str | None = None) -> list[BackupMetadata]:
        items: list[BackupMetadata] = []
        try:
            with self._get_sftp_client() as sftp:

                def _walk(dirpath: str):
                    try:
                        for entry in sftp.listdir_attr(dirpath):
                            p = f"{dirpath.rstrip('/')}/{entry.filename}"
                            if stat_is_dir(entry):
                                yield from _walk(p)
                            else:
                                yield p, entry
                    except OSError:
                        return

                def stat_is_dir(st):
                    import stat as _st

                    return _st.S_ISDIR(st.st_mode)

                base = self.base_path.rstrip("/")
                for p, entry in _walk(base):
                    if not re.search(r"(\.tar\.gz)$", p):
                        continue
                    ts = datetime.fromtimestamp(entry.st_mtime, UTC).isoformat()
                    items.append(
                        BackupMetadata(
                            filename=os.path.basename(p),
                            size_bytes=int(entry.st_size or 0),
                            timestamp=ts,
                            path=p,
                            checksum_sha256="",
                        )
                    )
        except Exception as exc:
            _logger.error("sftp_list_failed", error=str(exc))
            return []
        if prefix:
            items = [i for i in items if prefix in i.path]
        return sorted(items, key=lambda m: m.timestamp, reverse=True)

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def delete_backup(self, remote_path: str) -> bool:
        try:
            rp = self._safe_remote_path(remote_path)
            with self._get_sftp_client() as sftp:
                sftp.remove(rp)
                try:
                    sftp.remove(rp + ".manifest.json")
                except Exception:
                    pass
            return True
        except Exception as exc:
            _logger.warning(
                "sftp_delete_failed", error=str(exc), remote_path=remote_path
            )
            return False

    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        try:
            rp = self._safe_remote_path(remote_path)
            with self._get_sftp_client() as sftp:
                st = sftp.stat(rp)
                ts = datetime.fromtimestamp(st.st_mtime, UTC).isoformat()
                return BackupMetadata(
                    filename=os.path.basename(rp),
                    size_bytes=int(st.st_size or 0),
                    timestamp=ts,
                    path=rp,
                    checksum_sha256="",
                )
        except Exception as exc:
            _logger.error(
                "sftp_get_info_failed", error=str(exc), remote_path=remote_path
            )
            return None
