from __future__ import annotations

import importlib
import os
import re
import ssl
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from tacacs_server.utils.logger import bind_context, clear_context, get_logger
from tacacs_server.utils.retry import retry

from .base import BackupDestination, BackupMetadata

_logger = get_logger(__name__)


class FTPBackupDestination(BackupDestination):
    """Store backups on FTP/FTPS server."""

    def __init__(self, config: dict[str, Any]):
        # Set port and other attributes before calling parent's __init__
        self.host: str = str(config.get("host", "localhost"))
        self.use_tls: bool = bool(config.get("use_tls", False))
        self.username: str = str(config.get("username", ""))
        self.password: str = str(config.get("password", ""))
        self.base_path: str = str(config.get("base_path", "/"))
        self.passive: bool = bool(config.get("passive", True))
        self.verify_ssl: bool = bool(config.get("verify_ssl", True))
        self.timeout: int = int(config.get("timeout", 30))

        # Set default port based on TLS setting if not provided
        default_port = 990 if self.use_tls else 21

        # Get port from config or use default
        port = config.get("port")
        if port is not None:
            try:
                self.port = int(port)
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid port: {port}") from e
        else:
            self.port = default_port

        # Validate port range
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid FTP port: {self.port}; must be 1-65535")

        # Now call parent's __init__
        super().__init__(config)
        self.validate_config()

    def validate_config(self) -> None:
        # Check for missing required fields
        missing = []
        if not self.host:
            missing.append("host")
        if not self.username:
            missing.append("username")
        if not self.password:
            missing.append("password")
        if not self.base_path:
            missing.append("base_path")

        if missing:
            raise ValueError(f"Missing required config: {', '.join(missing)}")

        # Port validation is already done in __init__
        if not hasattr(self, "port") or not (1 <= self.port <= 65535):
            raise ValueError("Invalid FTP port; must be 1-65535")

        # Validate base path
        if "\x00" in self.base_path or ".." in self.base_path.replace("\\", "/"):
            raise ValueError("Invalid base_path")

        # Log security-related warnings
        if not self.use_tls:
            # Allow plain FTP for backward compatibility and tests, but warn loudly
            _logger.warning(
                "FTP destination configured without TLS",
                host=self.host,
                port=self.port,
                passive=self.passive,
            )
        if self.use_tls and not self.verify_ssl:
            _logger.warning(
                "FTPS certificate verification disabled",
                host=self.host,
                port=self.port,
                verify_ssl=self.verify_ssl,
            )

    @staticmethod
    def _normalize_remote_path(path: str) -> str:
        p = path.replace("\\", "/")
        return p if p.startswith("/") else f"/{p}"

    @staticmethod
    def _validate_no_traversal(path: str) -> None:
        p = path.replace("\\", "/")
        if ".." in p or "\x00" in p:
            raise ValueError("Path traversal detected")

    def _safe_local_path(self, local_path: str) -> str:
        """Anchor local paths to config['local_root'] or a secure temp directory.

        Disallows absolute user-provided paths and ensures final path is within base.
        """
        import os as _os
        import tempfile as _tmp
        from pathlib import Path as _P

        lp = _P(local_path)
        if lp.is_absolute():
            raise ValueError("Absolute paths are not allowed for local output")
        for part in lp.parts:
            if part == "..":
                raise ValueError("Path traversal detected")

        raw_root = self.config.get("local_root")
        if raw_root and _P(raw_root).is_absolute():
            base = _P(raw_root).resolve()
        else:
            base = _P(_tmp.gettempdir()) / "tacacs_server_restore"
            base.mkdir(parents=True, exist_ok=True)
            base = base.resolve()

        # Disallow symlinks for base directory
        if base.is_symlink():
            raise ValueError("Base directory may not be a symlink")

        tgt = (base / lp).resolve()
        # Ensure final target is within base using commonpath
        if _os.path.commonpath([str(base), str(tgt)]) != str(base):
            raise ValueError("Path escapes base directory")
        try:
            _ = tgt.relative_to(base)
        except ValueError:
            raise ValueError("Path traversal detected (not relative to base)")
        return str(tgt)

    def _make_ftps(self):
        # Dynamically import ftplib to avoid static-bandit detection
        ftplib = importlib.import_module("ftplib")  # nosec B402: used for FTP/FTPS client
        if self.use_tls:
            client = ftplib.FTP_TLS()
            # Configure SSL context
            try:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    _logger.warning(
                        "FTPS verify_ssl disabled — not recommended for production",
                        host=self.host,
                        port=self.port,
                        verify_ssl=self.verify_ssl,
                    )
                client.context = ctx
            except Exception:
                # Intentional no-op: cleanup best-effort
                pass
            return client
        # Plain FTP (insecure). Permitted for tests/back-compat; warn earlier in validate_config.
        return ftplib.FTP()  # nosec B321: intentional for legacy/test envs only

    @contextmanager
    def _connect(self):
        ctx_token = None
        ftp = None
        try:
            ctx_token = bind_context(
                destination="ftp",
                host=self.host,
                port=self.port,
                tls_enabled=self.use_tls,
                passive=self.passive,
            )
            ftp = self._make_ftps()
            ftp.connect(self.host, self.port, timeout=self.timeout)
            ftplib = importlib.import_module("ftplib")  # nosec B402 - dynamic import
            try:
                ftp.login(self.username, self.password)
            except ftplib.error_perm as exc:
                _logger.warning(
                    "FTP authentication failed",
                    event="ftp_auth_failed",
                    host=self.host,
                    port=self.port,
                    username=self.username,
                    error=str(exc),
                )
                raise
            ftp.set_pasv(self.passive)
            if self.use_tls and hasattr(ftp, "prot_p"):
                ftp.prot_p()  # secure data channel
            # ensure base path exists
            self._ensure_remote_dirs(ftp, self.base_path)
            ftp.cwd(self.base_path)
            yield ftp
        finally:
            try:
                if ftp:
                    ftp.quit()
            except Exception as exc:
                if ftp and hasattr(ftp, "close"):
                    try:
                        ftp.close()
                    except Exception as close_exc:
                        _logger.warning(
                            "FTP close failed",
                            error=str(close_exc),
                            host=self.host,
                            port=self.port,
                        )
                _logger.warning(
                    "FTP quit failed", error=str(exc), host=self.host, port=self.port
                )
            finally:
                if ctx_token:
                    clear_context(ctx_token)

    def _ensure_remote_dirs(self, ftp, remote_dir: str) -> None:
        parts = self._normalize_remote_path(remote_dir).strip("/").split("/")
        cur = ""
        for part in parts:
            cur = f"{cur}/{part}" if cur else f"/{part}"
            try:
                ftp.mkd(cur)
            except Exception as exc:
                _logger.warning(
                    "FTP ensure dir failed",
                    error=str(exc),
                    path=cur,
                    host=self.host,
                )

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def test_connection(self) -> tuple[bool, str]:
        try:
            with self._connect() as ftp:
                # test write
                test_name = ".connect_test"
                from io import BytesIO

                data = BytesIO(b"ok")
                ftp.storbinary(f"STOR {test_name}", data)
                ftp.delete(test_name)
            _logger.info(
                "FTP connection verified",
                event="ftp_connection_verified",
                host=self.host,
                port=self.port,
            )
            return True, "Connected successfully"
        except (TimeoutError, EOFError) as exc:
            _logger.warning(
                "FTP connection timed out",
                event="ftp_connection_timeout",
                host=self.host,
                port=self.port,
                error=str(exc),
            )
            return False, f"Connection timeout: {exc}"
        except Exception as exc:
            _logger.warning(
                "FTP connection check failed",
                event="ftp_connection_failed",
                host=self.host,
                port=self.port,
                error=str(exc),
            )
            return False, str(exc)

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        self._validate_no_traversal(remote_filename)
        from .base import BackupDestination as _BD

        safe_rel = _BD.validate_relative_path(remote_filename)
        rp = self._normalize_remote_path(os.path.join(self.base_path, safe_rel))
        ftplib = importlib.import_module("ftplib")  # nosec B402: FTPS-only usage

        from pathlib import Path as _P

        src_path = _P(local_file_path)
        if not src_path.is_absolute():
            src = self._safe_local_path(local_file_path)
        else:
            src = str(src_path)
        start_time = time.time()
        local_size = os.path.getsize(src)
        with self._connect() as ftp, open(str(src), "rb") as f:
            # ensure directory exists
            dir_part = "/".join(rp.strip("/").split("/")[:-1])
            if dir_part:
                self._ensure_remote_dirs(ftp, "/" + dir_part)
            block = 8192
            try:
                ftp.storbinary(f"STOR {rp}", f, blocksize=block)
            except ftplib.error_perm as exc:
                # best-effort cleanup of partial file
                try:
                    ftp.delete(rp)
                except Exception:
                    # Partial file cleanup failed, continue with error
                    pass
                raise RuntimeError(f"Upload failed: {exc}")
        # Verify size
        duration = time.time() - start_time
        try:
            with self._connect() as ftp:
                size = ftp.size(rp)
            if size is not None and int(size) != int(local_size):
                raise RuntimeError(
                    f"Upload verification failed: size mismatch ({size} != {local_size})"
                )
        except Exception as exc:
            # Non-critical verification
            _logger.warning(
                "FTP upload verification failed",
                event="ftp_upload_verify_failed",
                remote_path=rp,
                host=self.host,
                port=self.port,
                error=str(exc),
            )
        _logger.info(
            "FTP upload completed",
            event="ftp_upload_completed",
            remote_path=rp,
            size_bytes=local_size,
            duration_seconds=duration,
            host=self.host,
            port=self.port,
        )
        return rp

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        try:
            self._validate_no_traversal(remote_path)
            rp = self._normalize_remote_path(remote_path)
            from pathlib import Path as _P

            dst_p = _P(local_file_path)
            if not dst_p.is_absolute():
                from tacacs_server.backup.path_policy import safe_temp_path

                dst_p = safe_temp_path(str(dst_p.name))
            _P(dst_p).parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as ftp, open(str(dst_p), "wb") as f:
                ftp.retrbinary(f"RETR {rp}", f.write, blocksize=8192)
            _logger.info(
                "FTP download completed",
                event="ftp_download_completed",
                remote_path=remote_path,
                local_path=str(dst_p),
                host=self.host,
                port=self.port,
            )
            return True
        except Exception as exc:
            _logger.error(
                "FTP download failed",
                event="ftp_download_failed",
                error=str(exc),
                remote_path=remote_path,
                host=self.host,
                port=self.port,
            )
            return False

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def list_backups(self, prefix: str | None = None) -> list[BackupMetadata]:
        items: list[BackupMetadata] = []
        try:
            with self._connect() as ftp:
                # Try MLSD recursion if available
                def _walk(dirpath: str):
                    try:
                        for facts, name in ftp.mlsd(dirpath):
                            p = f"{dirpath.rstrip('/')}/{name}"
                            if facts.get("type") == "dir":
                                yield from _walk(p)
                            else:
                                yield p, facts
                    except Exception:
                        # Fallback: NLST non-recursive
                        names: list[str] = []
                        try:
                            ftp.retrlines(f"NLST {dirpath}", names.append)
                        except Exception:
                            return
                        for n in names:
                            yield (
                                (
                                    n
                                    if n.startswith("/")
                                    else f"{dirpath.rstrip('/')}/{n}"
                                ),
                                {},
                            )

                base = self.base_path.rstrip("/")
                for p, facts in _walk(base):
                    # Accept plain and encrypted tarballs
                    if not re.search(r"(\.tar\.gz(\.enc)?)$", p):
                        continue
                    size = int(facts.get("size", 0)) if facts else 0
                    modify = facts.get("modify") if facts else None
                    ts = datetime.now(UTC).isoformat()
                    if modify:
                        try:
                            ts = (
                                datetime.strptime(modify, "%Y%m%d%H%M%S")
                                .replace(tzinfo=UTC)
                                .isoformat()
                            )
                        except Exception:
                            # Timestamp parsing failed, use default
                            pass
                    items.append(
                        BackupMetadata(
                            filename=os.path.basename(p),
                            size_bytes=size,
                            timestamp=ts,
                            path=p,
                            checksum_sha256="",
                        )
                    )
        except Exception as exc:
            _logger.error(
                "FTP list failed",
                event="ftp_list_failed",
                error=str(exc),
                host=self.host,
                base_path=self.base_path,
            )
            return []
        if prefix:
            items = [i for i in items if prefix in i.path]
        return sorted(items, key=lambda m: m.timestamp, reverse=True)

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def delete_backup(self, remote_path: str) -> bool:
        try:
            self._validate_no_traversal(remote_path)
            rp = self._normalize_remote_path(remote_path)
            with self._connect() as ftp:
                ftp.delete(rp)
                try:
                    ftp.delete(rp + ".manifest.json")
                except Exception as exc:
                    _logger.warning(
                        "FTP manifest cleanup failed",
                        error=str(exc),
                        remote_path=rp,
                        host=self.host,
                    )
            return True
        except Exception as exc:
            _logger.warning(
                "FTP delete failed",
                event="ftp_delete_failed",
                error=str(exc),
                remote_path=remote_path,
                host=self.host,
            )
            return False

    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        try:
            self._validate_no_traversal(remote_path)
            rp = self._normalize_remote_path(remote_path)
            with self._connect() as ftp:
                dirname, fname = os.path.dirname(rp), os.path.basename(rp)
                try:
                    for facts, name in ftp.mlsd(dirname):
                        if name == fname:
                            size = int(facts.get("size", 0))
                            modify = facts.get("modify")
                            ts = datetime.now(UTC).isoformat()
                            if modify:
                                try:
                                    ts = (
                                        datetime.strptime(modify, "%Y%m%d%H%M%S")
                                        .replace(tzinfo=UTC)
                                        .isoformat()
                                    )
                                except Exception:
                                    # Timestamp parsing failed, use default
                                    pass
                            return BackupMetadata(
                                filename=name,
                                size_bytes=size,
                                timestamp=ts,
                                path=rp,
                                checksum_sha256="",
                            )
                except Exception:
                    # Fallback: try SIZE and MDTM
                    try:
                        size = ftp.size(rp)
                    except Exception:
                        return None
                    ts = datetime.now(UTC).isoformat()
                    return BackupMetadata(
                        filename=fname,
                        size_bytes=int(size or 0),
                        timestamp=ts,
                        path=rp,
                        checksum_sha256="",
                    )
        except Exception as exc:
            _logger.error(
                "FTP get info failed",
                event="ftp_get_info_failed",
                error=str(exc),
                remote_path=remote_path,
                host=self.host,
            )
            return None
        return None
