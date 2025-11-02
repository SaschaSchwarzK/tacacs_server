from __future__ import annotations

import os
import re
import time
from datetime import UTC, datetime
from typing import Any

from tacacs_server.utils.logger import get_logger
from tacacs_server.utils.retry import retry

from .base import BackupDestination, BackupMetadata

_logger = get_logger(__name__)


class AzureBlobBackupDestination(BackupDestination):
    """Store backups in Azure Blob Storage"""

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        # Use loose Any typing to avoid mypy issues when azure stubs are absent
        self.blob_service_client: Any | None = None
        self.container_client: Any | None = None

    # --- configuration / validation ---
    def validate_config(self) -> None:
        cfg = self.config or {}

        # Determine auth method
        has_conn_str = bool(cfg.get("connection_string"))
        has_account_key = bool(cfg.get("account_name") and cfg.get("account_key"))
        has_sas = bool(cfg.get("account_name") and cfg.get("sas_token"))
        has_mi = bool(cfg.get("account_name") and cfg.get("use_managed_identity"))

        methods = [has_conn_str, has_account_key, has_sas, has_mi]
        if sum(1 for m in methods if m) != 1:
            raise ValueError(
                "Exactly one authentication method must be configured: "
                "connection_string OR (account_name+account_key) OR (account_name+sas_token) OR managed identity"
            )

        # Required fields per method
        if has_conn_str:
            if not isinstance(cfg.get("connection_string"), str):
                raise ValueError("connection_string must be a string")
        else:
            if not isinstance(cfg.get("account_name"), str) or not cfg.get(
                "account_name"
            ):
                raise ValueError("account_name is required for this auth method")
            if has_account_key and not cfg.get("account_key"):
                raise ValueError("account_key is required for account key auth")
            if has_sas and not cfg.get("sas_token"):
                raise ValueError("sas_token is required for SAS auth")
            # Managed identity requires no extra secret

        # Common required
        container = str(cfg.get("container_name", ""))
        if not container:
            raise ValueError("container_name is required")
        # Validate container name: lowercase, alnum and hyphens, 3-63 chars, start/end alnum
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61})[a-z0-9]", container):
            raise ValueError(
                "Invalid container_name; must be lowercase alphanumeric and hyphens (3-63 chars)"
            )

        # Defaults
        if "max_concurrency" not in cfg:
            self.config["max_concurrency"] = 4
        if "timeout" not in cfg:
            self.config["timeout"] = 300
        if not cfg.get("endpoint_suffix"):
            self.config["endpoint_suffix"] = "core.windows.net"
        # Optional base_path for key prefix
        if cfg.get("base_path") is None:
            self.config["base_path"] = ""

    # --- client helpers ---
    def _ensure_clients(self) -> None:
        if self.container_client is not None:
            return
        cfg = self.config
        try:
            # Late import to avoid mandatory dependency when unused
            from azure.storage.blob import BlobServiceClient
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "azure-storage-blob package is required for Azure destination"
            ) from exc

        timeout = int(cfg.get("timeout", 300))
        endpoint_suffix = str(cfg.get("endpoint_suffix", "core.windows.net"))
        container_name = str(cfg.get("container_name"))

        # Initialize BlobServiceClient according to auth method
        if cfg.get("connection_string"):
            self.blob_service_client = BlobServiceClient.from_connection_string(
                cfg["connection_string"], connection_timeout=timeout
            )
        else:
            account_name = str(cfg.get("account_name"))
            account_url = f"https://{account_name}.blob.{endpoint_suffix}"
            credential: Any
            if cfg.get("account_key"):
                credential = cfg.get("account_key")
            elif cfg.get("sas_token"):
                credential = cfg.get("sas_token")
            else:
                try:
                    from azure.identity import DefaultAzureCredential
                except Exception as exc:  # pragma: no cover
                    raise RuntimeError(
                        "azure-identity package is required for managed identity auth"
                    ) from exc
                credential = DefaultAzureCredential()
            self.blob_service_client = BlobServiceClient(
                account_url=account_url, credential=credential
            )

        # Container client
        self.container_client = self.blob_service_client.get_container_client(
            container_name
        )

    # --- metadata / tags helpers ---
    def _build_blob_metadata(self, manifest: dict) -> dict[str, str]:
        """
        Build blob metadata from backup manifest.
        Metadata keys must be valid HTTP headers (alphanumeric + hyphens).
        """
        try:
            metadata = {
                "instance_id": str(manifest["backup_metadata"]["instance_id"]),
                "instance_name": str(manifest["backup_metadata"]["instance_name"]),
                "backup_type": str(manifest["backup_metadata"]["backup_type"]),
                "timestamp_utc": str(manifest["backup_metadata"]["timestamp_utc"]),
                "server_version": str(manifest["system_info"]["server_version"]),
                "total_size_bytes": str(manifest["total_size_bytes"]),
                "compressed_size_bytes": str(manifest.get("compressed_size_bytes", 0)),
                "encrypted": str(manifest.get("encrypted", False)).lower(),
            }
        except Exception as exc:
            _logger.debug("azure_build_metadata_failed", error=str(exc))
            return {}
        return metadata

    def _build_blob_tags(
        self, manifest: dict, custom_tags: dict | None = None
    ) -> dict[str, str]:
        """
        Build blob tags for efficient querying.
        Azure allows up to 10 tags per blob.
        """
        try:
            tags: dict[str, str] = {
                "instance_name": str(manifest["backup_metadata"]["instance_name"]),
                "backup_type": str(manifest["backup_metadata"]["backup_type"]),
                "encrypted": str(manifest.get("encrypted", False)).lower(),
            }
        except Exception as exc:
            _logger.debug("azure_build_tags_failed", error=str(exc))
            tags = {}

        # Add custom tags from configuration
        if custom_tags and isinstance(custom_tags, dict):
            for k, v in custom_tags.items():
                try:
                    tags[str(k)] = str(v)
                except Exception:
                    continue

        # Ensure we don't exceed 10 tags
        if len(tags) > 10:
            _logger.warning("Too many blob tags, truncating to 10")
            tags = dict(list(tags.items())[:10])

        return tags

    # --- API methods ---
    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def test_connection(self) -> tuple[bool, str]:
        try:
            # Initialize and ensure container exists
            self._ensure_clients()
            assert self.container_client is not None

            try:
                if not self.container_client.exists():
                    try:
                        # Private access by default
                        self.container_client.create_container()
                    except Exception as exc:
                        # If already exists, ignore
                        from azure.core.exceptions import ResourceExistsError

                        if not isinstance(exc, ResourceExistsError):
                            raise
            except Exception:
                # Fallback to best-effort create ignoring conflicts
                try:
                    self.container_client.create_container()
                except Exception:
                    pass

            # Test upload, download, delete
            test_blob = ".connect_test"
            blob_client = self.container_client.get_blob_client(test_blob)
            payload = b"ok"
            blob_client.upload_blob(
                payload,
                overwrite=True,
                max_concurrency=int(self.config.get("max_concurrency", 4)),
                timeout=int(self.config.get("timeout", 300)),
            )
            data = blob_client.download_blob(
                max_concurrency=int(self.config.get("max_concurrency", 4))
            ).readall()
            if data != payload:
                return False, "I/O verification failed"
            blob_client.delete_blob()
            # List operation
            list(self.container_client.list_blobs(name_starts_with=""))
            return True, "Connected successfully"
        except Exception as exc:
            return False, str(exc)

    # --- path helpers ---
    def _blob_name(self, remote_filename: str) -> str:
        # Validate the relative key path (allow subdirectories with safe segments)
        from .base import BackupDestination as _BD

        safe_rel = _BD.validate_relative_path(remote_filename)
        # Normalize/sanitize base_path into safe key prefix components
        base_raw = str(self.config.get("base_path", "")).strip("/")
        if base_raw:
            parts: list[str] = []
            for seg in base_raw.split("/"):
                if not seg:
                    continue
                parts.append(_BD.validate_path_segment(seg, allow_dot=False))
            base = "/".join(parts)
            return f"{base}/{safe_rel}" if base else safe_rel
        return safe_rel

    # --- operations ---
    def _safe_local_path(self, local_path: str):
        """Anchor local target path to config['local_root'] or a secure temp directory.

        Disallows absolute user-provided paths, suspicious segments, and ensures final path is within base.
        """
        import os as _os
        import tempfile as _tmp
        from pathlib import Path as _P

        lp = _P(local_path)
        if lp.is_absolute():
            raise ValueError("Absolute paths are not allowed for local output")

        allowed_temp_prefix = _P(_tmp.gettempdir()).resolve()
        raw_root = self.config.get("local_root")
        if raw_root and _P(raw_root).is_absolute() and _P(raw_root).resolve().is_dir():
            base = _P(raw_root).resolve()
            if not str(base).startswith(str(allowed_temp_prefix)):
                raise ValueError("Configured local_root outside allowed temp directory")
        else:
            base = allowed_temp_prefix / "tacacs_server_restore"
            base.mkdir(parents=True, exist_ok=True)
            base = base.resolve()

        for part in lp.parts:
            if part == "..":
                raise ValueError("Path traversal detected in local file path")

        tgt = (base / lp).resolve()
        if _os.path.commonpath([str(base), str(tgt)]) != str(base):
            raise ValueError("Local path escapes allowed root")
        # Ensure no symlinks in ancestors between base and tgt
        par = tgt
        while par != base:
            if par.is_symlink():
                raise ValueError(f"Symlink detected in output path: {par}")
            par = par.parent
            if par == par.parent:  # safeguard against infinite loop
                break
        if base.is_symlink():
            raise ValueError("Backup base directory may not be a symlink")
        # Optionally, error if tgt is a symlink (if already present)
        if tgt.exists() and tgt.is_symlink():
            raise ValueError("Target file may not be a symlink")
        return tgt

    def upload_backup(self, local_file_path: str, remote_filename: str) -> str:
        self._ensure_clients()
        assert self.container_client is not None
        blob_name = self._blob_name(remote_filename)
        blob_client = self.container_client.get_blob_client(blob_name)

        # Basic retry with exponential backoff for transient errors
        max_attempts = 3
        delay = 1.0
        for attempt in range(1, max_attempts + 1):
            try:
                with open(local_file_path, "rb") as data:
                    blob_client.upload_blob(
                        data,
                        overwrite=True,
                        max_concurrency=int(self.config.get("max_concurrency", 4)),
                        timeout=int(self.config.get("timeout", 300)),
                    )
                break
            except Exception as exc:
                if attempt >= max_attempts:
                    raise RuntimeError(f"Azure upload failed: {exc}")
                _logger.warning("azure_upload_retry", attempt=attempt, error=str(exc))
                time.sleep(delay)
                delay *= 2

        # Optional metadata and tags (best-effort; no extra context available here)
        try:
            # We propagate any provided metadata keys from config if present
            meta_cfg = self.config.get("default_metadata") or {}
            if isinstance(meta_cfg, dict) and meta_cfg:
                blob_client.set_blob_metadata(
                    {str(k): str(v) for k, v in meta_cfg.items()}
                )
        except Exception as exc:
            _logger.debug("azure_set_metadata_failed", error=str(exc))
        try:
            tags_cfg = self.config.get("default_tags") or {}
            if isinstance(tags_cfg, dict) and tags_cfg:
                blob_client.set_blob_tags({str(k): str(v) for k, v in tags_cfg.items()})
        except Exception as exc:
            _logger.debug("azure_set_tags_failed", error=str(exc))

        url = getattr(blob_client, "url", None)
        return str(url) if url is not None else f"/{blob_name}"

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def download_backup(self, remote_path: str, local_file_path: str) -> bool:
        try:
            self._ensure_clients()
            assert self.container_client is not None
            # Validate and normalize the remote path to a safe blob name
            from .base import BackupDestination as _BD

            blob_name = _BD.validate_relative_path(remote_path)
            blob_client = self.container_client.get_blob_client(blob_name)
            # Safely create destination directory under allowed local root
            dst_path = self._safe_local_path(local_file_path)
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            with open(dst_path, "wb") as file:
                download_stream = blob_client.download_blob(
                    max_concurrency=int(self.config.get("max_concurrency", 4))
                )
                file.write(download_stream.readall())
            # Verify size
            props = blob_client.get_blob_properties()
            size_remote = (
                int(getattr(props, "size", 0) or props.get("size", 0))
                if isinstance(props, dict)
                else int(props.size)
            )
            size_local = os.path.getsize(str(dst_path))
            return int(size_remote) == int(size_local)
        except Exception as exc:
            _logger.error(
                "azure_download_failed", error=str(exc), remote_path=remote_path
            )
            return False

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def list_backups(self, prefix: str | None = None) -> list[BackupMetadata]:
        items: list[BackupMetadata] = []
        try:
            self._ensure_clients()
            assert self.container_client is not None
            base_prefix = str(self.config.get("base_path", "")).strip("/")
            start = base_prefix
            if prefix:
                from .base import BackupDestination as _BD

                # Validate user-supplied prefix to avoid unintended key scans
                p = _BD.validate_relative_path(prefix)
                start = f"{base_prefix}/{p}" if base_prefix else p
            it = self.container_client.list_blobs(name_starts_with=start or None)
            for blob in it:
                name: str = getattr(blob, "name", "")
                if not name or not name.endswith(".tar.gz"):
                    continue
                size = int(getattr(blob, "size", 0) or 0)
                lm = getattr(blob, "last_modified", None)
                ts = (
                    lm.replace(tzinfo=UTC).isoformat()
                    if hasattr(lm, "replace") and lm
                    else datetime.now(UTC).isoformat()
                )
                items.append(
                    BackupMetadata(
                        filename=os.path.basename(name),
                        size_bytes=size,
                        timestamp=ts,
                        path=name,
                        checksum_sha256="",
                    )
                )
        except Exception as exc:
            _logger.error("azure_list_failed", error=str(exc))
            return []
        return sorted(items, key=lambda m: m.timestamp, reverse=True)

    @retry(max_retries=2, initial_delay=1.0, backoff=2.0)
    def delete_backup(self, remote_path: str) -> bool:
        try:
            self._ensure_clients()
            assert self.container_client is not None
            from .base import BackupDestination as _BD

            blob_name = _BD.validate_relative_path(remote_path)
            blob_client = self.container_client.get_blob_client(blob_name)
            blob_client.delete_blob()
            # Delete associated manifest if present
            try:
                man = f"{blob_name}.manifest.json"
                self.container_client.get_blob_client(man).delete_blob()
            except Exception:
                pass
            return True
        except Exception as exc:
            _logger.warning(
                "azure_delete_failed", error=str(exc), remote_path=remote_path
            )
            return False

    def get_backup_info(self, remote_path: str) -> BackupMetadata | None:
        try:
            self._ensure_clients()
            assert self.container_client is not None
            from .base import BackupDestination as _BD

            blob_name = _BD.validate_relative_path(remote_path)
            blob_client = self.container_client.get_blob_client(blob_name)
            props = blob_client.get_blob_properties()
            size = (
                int(getattr(props, "size", 0) or 0)
                if isinstance(props, dict)
                else int(props.size)
            )
            lm = (
                getattr(props, "last_modified", None)
                if not isinstance(props, dict)
                else props.get("last_modified")
            )
            ts = (
                lm.replace(tzinfo=UTC).isoformat()
                if hasattr(lm, "replace") and lm
                else datetime.now(UTC).isoformat()
            )
            return BackupMetadata(
                filename=os.path.basename(blob_name),
                size_bytes=size,
                timestamp=ts,
                path=blob_name,
                checksum_sha256="",
            )
        except Exception as exc:
            _logger.error(
                "azure_get_info_failed", error=str(exc), remote_path=remote_path
            )
            return None

    # Advanced: move older backups to Cool tier and then fall back to base delete policy
    def apply_retention_policy(
        self, retention_days: int | None = None, retention_rule: Any | None = None
    ) -> int:
        moved = 0
        try:
            self._ensure_clients()
            assert self.container_client is not None
            now = datetime.now(UTC)
            for meta in self.list_backups():
                try:
                    ts = datetime.fromisoformat(meta.timestamp)
                    age_days = (now - ts).days
                    if age_days > 90:
                        try:
                            bc = self.container_client.get_blob_client(meta.path)
                            bc.set_standard_blob_tier("Cool")
                            moved += 1
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception as exc:
            _logger.debug("azure_apply_retention_tiering_failed", error=str(exc))
        # Perform base deletion for items older than retention_days
        try:
            deleted = super().apply_retention_policy(retention_days, retention_rule)
        except Exception:
            deleted = 0
        return deleted
