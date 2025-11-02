from __future__ import annotations

import importlib
import os
import re
import ssl
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from tacacs_server.utils.logger import get_logger
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

        # Now call parent's __init__ which will call validate_config()
        super().__init__(config)

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
                "FTP destination configured without TLS (use_tls=false) — insecure"
            )
        if self.use_tls and not self.verify_ssl:
            _logger.warning("FTPS certificate verification disabled (verify_ssl=false)")

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
        """Constrain local filesystem paths to an allowed root (defense-in-depth)."""
        from pathlib import Path as _P

        if not isinstance(local_path, str) or "\x00" in local_path:
            raise ValueError("Invalid local path")
        base = _P(str(self.config.get("local_root") or ".")).resolve()
        tgt = _P(local_path).resolve()
        try:
            _ = tgt.relative_to(base)
        except Exception:
            raise ValueError("Local path escapes allowed root")
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
                        "FTPS verify_ssl disabled — not recommended for production"
                    )
                client.context = ctx
            except Exception:
                pass
            return client
        # Plain FTP (insecure). Permitted for tests/back-compat; warn earlier in validate_config.
        return ftplib.FTP()

    @contextmanager
    def _connect(self):
        ftp = None
        try:
            ftp = self._make_ftps()
            ftp.connect(self.host, self.port, timeout=self.timeout)
            ftp.login(self.username, self.password)
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
            except Exception:
                try:
                    if ftp and hasattr(ftp, "close"):
                        ftp.close()
                except Exception:
                    pass

    def _ensure_remote_dirs(self, ftp, remote_dir: str) -> None:
        parts = self._normalize_remote_path(remote_dir).strip("/").split("/")
        cur = ""
        for part in parts:
            cur = f"{cur}/{part}" if cur else f"/{part}"
            try:
                ftp.mkd(cur)
            except Exception:
                pass

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
            return True, "Connected successfully"
        except (TimeoutError, EOFError) as exc:
            return False, f"Connection timeout: {exc}"
        except Exception as exc:
            return False, str(exc)

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        self._validate_no_traversal(remote_filename)
        from .base import BackupDestination as _BD

        safe_rel = _BD.validate_relative_path(remote_filename)
        rp = self._normalize_remote_path(os.path.join(self.base_path, safe_rel))
        ftplib = importlib.import_module("ftplib")  # nosec B402: FTPS-only usage

        src = self._safe_local_path(local_file_path)
        with self._connect() as ftp, open(src, "rb") as f:
            # ensure directory exists
            dir_part = "/".join(rp.strip("/").split("/")[:-1])
            if dir_part:
                self._ensure_remote_dirs(ftp, "/" + dir_part)
            sent = 0
            block = 8192
            try:

                def _cb(chunk):
                    nonlocal sent
                    sent += len(chunk)
                    if sent % (block * 128) == 0:
                        _logger.info("ftp_upload_progress", bytes_sent=sent)
                    return chunk

                ftp.storbinary(f"STOR {rp}", f, blocksize=block)
            except ftplib.error_perm as exc:
                # best-effort cleanup of partial file
                try:
                    ftp.delete(rp)
                except Exception:
                    pass
                raise RuntimeError(f"Upload failed: {exc}")
        # Verify size
        try:
            local_size = os.path.getsize(local_file_path)
            with self._connect() as ftp:
                size = ftp.size(rp)
            if size is not None and int(size) != int(local_size):
                raise RuntimeError(
                    f"Upload verification failed: size mismatch ({size} != {local_size})"
                )
        except Exception as exc:
            _logger.warning("ftp_upload_verify_failed", error=str(exc))
        return rp

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        try:
            self._validate_no_traversal(remote_path)
            rp = self._normalize_remote_path(remote_path)
            dst = self._safe_local_path(local_file_path)
            from pathlib import Path as _P

            _P(dst).parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as ftp, open(dst, "wb") as f:
                ftp.retrbinary(f"RETR {rp}", f.write, blocksize=8192)
            return True
        except Exception as exc:
            _logger.error(
                "ftp_download_failed", error=str(exc), remote_path=remote_path
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
                    if not re.search(r"(\.tar\.gz)$", p):
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
            _logger.error("ftp_list_failed", error=str(exc))
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
                except Exception:
                    pass
            return True
        except Exception as exc:
            _logger.warning(
                "ftp_delete_failed", error=str(exc), remote_path=remote_path
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
                "ftp_get_info_failed", error=str(exc), remote_path=remote_path
            )
            return None
        return None
