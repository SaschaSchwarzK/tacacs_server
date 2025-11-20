from __future__ import annotations

import hashlib
import importlib
import json
import os
import platform
import shutil
import socket
import tarfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tacacs_server.utils.logger import bind_context, clear_context, get_logger

from .database_utils import (
    count_database_records as db_count_tables,
)
from .database_utils import (
    export_database_with_retry as db_export,
)
from .database_utils import (
    import_database as db_import,
)
from .database_utils import (
    verify_database_integrity as db_verify,
)
from .destinations import create_destination
from .encryption import BackupEncryption, decrypt_file

_logger = get_logger("tacacs_server.backup.service", component="backup")

# Try to import humanize, but provide fallback
try:
    import humanize

    HAS_HUMANIZE = True
except ImportError:
    HAS_HUMANIZE = False
    _logger.warning(
        "humanize library not available, size formatting will be basic",
        event="backup_humanize_unavailable",
    )


class BackupService:
    """Service for managing backups."""

    def __init__(self, config, execution_store):
        """Initialize the backup service.

        Args:
            config: Configuration object
            execution_store: Store for backup executions
        """
        self.config = config
        self.execution_store = execution_store

        # Use fixed temp root for all transient operations
        try:
            from tacacs_server.backup.path_policy import get_temp_root

            self.temp_dir = get_temp_root()
        except Exception as exc:
            _logger.warning(
                "Failed to determine temporary backup root, using default",
                error=str(exc),
                fallback="/var/run/tacacs/tmp",
            )
            self.temp_dir = Path("/var/run/tacacs/tmp")
        self._ensure_temp_dir()
        self.instance_name = (
            self.config.config_store.get_instance_name()
            if self.config.config_store is not None
            else "tacacs-server"
        )
        # Initialize scheduler (not started by default)
        self.scheduler: Any | None = None
        try:
            from .scheduler import BackupScheduler as _BackupScheduler

            self.scheduler = _BackupScheduler(self)
        except Exception as e:
            _logger.warning(
                "Scheduler initialization failed",
                error=str(e),
            )
            self.scheduler = None
        self.instance_id = (
            self.config.config_store.get_metadata("instance_id")
            if self.config.config_store is not None
            else None
        )

    def _ensure_temp_dir(self) -> None:
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    # --- helpers ---
    def _safe_local_path(self, path: str) -> str:
        """Ensure path stays within the service temp directory (hardened).

        - Disallow absolute user-provided paths
        - Reject ".." segments
        - Resolve and verify real-path containment using commonpath
        - Disallow symlink base directory
        """
        import os as _os
        from pathlib import Path as _P

        lp = _P(path)
        base = _P(str(self.temp_dir)).resolve()

        # If an absolute path is provided, allow it only if it resides under temp_dir
        if lp.is_absolute():
            tgt = lp.resolve()
            if _os.path.commonpath([str(base), str(tgt)]) != str(base):
                raise ValueError("Path escapes temp directory")
            return str(tgt)

        # Relative paths: validate and anchor to temp_dir
        for part in lp.parts:
            if part == "..":
                raise ValueError("Path traversal detected")
        if base.is_symlink():
            raise ValueError("Temp base directory may not be a symlink")
        tgt = (base / lp).resolve()
        if _os.path.commonpath([str(base), str(tgt)]) != str(base):
            raise ValueError("Path escapes temp directory")
        return str(tgt)

    def _export_database(self, src_path: str, dst_path: str) -> None:
        """Export a SQLite database from src_path to dst_path with verification.

        Args:
            src_path: Source database path
            dst_path: Destination path for the exported database
        """
        try:
            # First verify source database is valid
            if not db_verify(src_path)[0]:
                _logger.warning(
                    "Source database failed integrity check, attempting export anyway",
                    source_path=src_path,
                )

            db_export(src_path, dst_path)

            if not os.path.exists(dst_path):
                raise RuntimeError(f"Export failed: {dst_path} was not created")

            # Verify exported database
            ok, msg = db_verify(dst_path)
            if not ok:
                _logger.warning(
                    "Exported database integrity issue",
                    error=msg,
                    source_path=src_path,
                    dest_path=dst_path,
                )
                # Don't fail - continue with backup

        except Exception as e:
            _logger.error(
                "Database export failed",
                error=str(e),
                source_path=src_path,
                dest_path=dst_path,
            )

    def _create_manifest(
        self, backup_dir: str, backup_type: str, triggered_by: str
    ) -> dict[str, Any]:
        """Create a backup manifest.

        Args:
            backup_dir: Directory containing the backup files
            backup_type: Reason/type for backup (e.g. "manual", "scheduled")
            triggered_by: Initiator for audit trail

        Returns:
            Manifest dictionary suitable for JSON serialization
        """
        contents: list[dict[str, Any]] = []
        manifest: dict[str, Any] = {
            "backup_metadata": {
                "instance_id": self.instance_id,
                "instance_name": self.instance_name,
                "hostname": socket.gethostname(),
                "backup_type": backup_type,
                "timestamp_utc": datetime.now(UTC).isoformat(),
                "triggered_by": triggered_by,
                "backup_version": "1.0",
            },
            "system_info": {
                "server_version": self._get_server_version(),
                "python_version": platform.python_version(),
                "platform": platform.platform(),
            },
            "config_info": {
                "config_source": "url" if self.config.is_url_config() else "file",
                "config_hash": self._hash_dict(self.config._export_full_config()),
                "has_overrides": len(getattr(self.config, "overridden_keys", {}) or {})
                > 0,
            },
            "contents": contents,
            "total_size_bytes": 0,
            # Encryption fields (populated when encryption is applied)
            "encrypted": False,
            "encryption_algorithm": None,
            "encryption_metadata": None,
        }

        # Scan backup directory and add file entries to manifest
        for filename in os.listdir(backup_dir):
            if filename == "manifest.json":
                continue
            filepath = os.path.join(backup_dir, filename)
            if not os.path.isfile(filepath):
                continue
            try:
                file_size = os.path.getsize(filepath)
            except Exception:
                file_size = 0
            checksum = self._calculate_sha256(filepath)
            ftype = self._classify_file(filename)
            entry: dict[str, Any] = {
                "file": filename,
                "size_bytes": file_size,
                "checksum_sha256": checksum,
                "type": ftype,
            }
            if ftype == "database":
                try:
                    entry["records"] = sum(db_count_tables(filepath).values())
                except Exception:
                    entry["records"] = 0
            contents.append(entry)
            manifest["total_size_bytes"] = int(
                manifest.get("total_size_bytes", 0)
            ) + int(file_size)

        return manifest

    def _cleanup_sidecars(self, backup_dir: str, phase: str) -> None:
        """Remove SQLite -wal/-shm files created during backup operations."""
        try:
            for fname in os.listdir(backup_dir):
                if not (fname.endswith("-wal") or fname.endswith("-shm")):
                    continue
                path = os.path.join(backup_dir, fname)
                try:
                    os.remove(path)
                except Exception as exc:
                    _logger.warning(
                        "Failed to remove sidecar",
                        phase=phase,
                        path=path,
                        error=str(exc),
                    )
        except Exception as exc:
            _logger.warning(
                "Failed to enumerate sidecars",
                phase=phase,
                error=str(exc),
            )

    @staticmethod
    def _calculate_sha256(filepath: str) -> str:
        h = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    @staticmethod
    def _hash_dict(d: dict) -> str:
        try:
            data = json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")
            return hashlib.sha256(data).hexdigest()
        except Exception:
            return ""

    @staticmethod
    def _classify_file(filename: str) -> str:
        name = filename.lower()
        if name.endswith(".db"):
            return "database"
        if name in ("tacacs.conf", "config_export.json"):
            return "config"
        if name == "manifest.json":
            return "metadata"
        return "data"

    @staticmethod
    def _count_db_records(db_path: str) -> int:
        try:
            return sum(db_count_tables(db_path).values())
        except Exception:
            return 0

    @staticmethod
    def _get_server_version() -> str:
        try:
            from tacacs_server import __version__

            return str(__version__)
        except Exception:
            return "unknown"

    def _create_tarball(self, src_dir: str, archive_path: str) -> int:
        """Create a tarball from the source directory.

        Args:
            src_dir: Source directory to compress
            archive_path: Path where the tarball will be created

        Returns:
            int: Size of the created tarball in bytes
        """
        try:
            raw_cfg: Any = getattr(self.config, "get_backup_config", lambda: {})()
            cfg: dict[str, Any] = raw_cfg if isinstance(raw_cfg, dict) else {}
            compression_level = int(cfg.get("compression_level", 6))
        except Exception:
            compression_level = 6

        # Ensure directory exists
        Path(archive_path).parent.mkdir(parents=True, exist_ok=True)

        # Create the tarball
        with tarfile.open(
            archive_path, "w:gz", compresslevel=int(compression_level)
        ) as tar:
            tar.add(src_dir, arcname=".")
        return os.path.getsize(archive_path)

    def _upload_with_progress(
        self,
        local_path: str,
        destination: Any,
        remote_filename: str,
        execution_id: str,
    ) -> str:
        """Upload a file to the destination and log duration/size."""
        file_size = os.path.getsize(local_path)
        start_time = time.time()
        success = False
        try:
            if hasattr(destination, "upload"):
                result = str(
                    destination.upload(
                        local_path,
                        remote_filename=remote_filename,
                    )
                )
            elif hasattr(destination, "upload_backup"):
                result = str(
                    destination.upload_backup(
                        local_path, remote_filename=remote_filename
                    )
                )
            else:
                _logger.warning(
                    "Destination doesn't support upload callbacks, falling back to default upload",
                    event="backup_upload_callback_missing",
                    remote_filename=remote_filename,
                )
                if hasattr(destination, "upload"):
                    result = str(destination.upload(local_path, remote_filename))
                else:
                    result = str(destination.upload_backup(local_path, remote_filename))
            success = True
            return result
        except Exception as exc:
            _logger.error(
                "Upload failed",
                event="backup_upload_failed",
                error=str(exc),
                remote_filename=remote_filename,
            )
            raise
        finally:
            duration = time.time() - start_time
            if HAS_HUMANIZE:
                size_label = humanize.naturalsize(file_size, binary=True)
            else:
                size_label = f"{file_size} bytes"
            if success:
                _logger.info(
                    "Backup upload completed",
                    event="backup_upload_completed",
                    execution_id=execution_id,
                    duration_seconds=duration,
                    size_bytes=file_size,
                    size_label=size_label,
                )
            else:
                _logger.warning(
                    "Backup upload failed",
                    event="backup_upload_failed",
                    duration_seconds=duration,
                )

    def execute_backup(
        self,
        destination_id: str,
        triggered_by: str,
        backup_type: str = "manual",
        execution_id: str | None = None,
    ) -> str:
        """Execute a backup operation.

        Args:
            destination_id: ID of the destination where the backup will be stored
            triggered_by: Identifier for who/what triggered the backup
            backup_type: Type of backup (e.g., 'manual', 'scheduled')
            execution_id: Optional ID for this backup execution (will generate one if not provided)

        Returns:
            str: The execution ID of the backup

        Raises:
            ValueError: If any of the input parameters are invalid
        """
        if not isinstance(destination_id, str) or not destination_id.strip():
            raise ValueError("destination_id must be a non-empty string")
        if not isinstance(triggered_by, str) or not triggered_by.strip():
            raise ValueError("triggered_by must be a non-empty string")
        if not isinstance(backup_type, str) or not backup_type.strip():
            raise ValueError("backup_type must be a non-empty string")

        execution_id = execution_id or str(uuid.uuid4())
        # Build a validated workspace under the temp root
        from tacacs_server.backup.destinations.base import (
            BackupDestination as _BD_valid,
        )
        from tacacs_server.backup.path_policy import join_safe_temp as _join_temp

        safe_exec = _BD_valid.validate_path_segment(
            execution_id, allow_dot=False, max_len=64
        )
        backup_dir = str(_join_temp(safe_exec))
        archive_path = None
        t0 = datetime.now(UTC)

        ctx_token = bind_context(
            execution_id=execution_id,
            destination_id=destination_id,
            backup_type=backup_type,
        )
        try:
            # Step 1: Initialize execution tracking
            self.execution_store.create_execution(
                execution_id=execution_id,
                destination_id=destination_id,
                triggered_by=triggered_by,
            )
            _logger.info(
                "Backup started",
                event="backup_started",
                execution_id=execution_id,
                destination_id=destination_id,
                triggered_by=triggered_by,
                backup_type=backup_type,
            )

            # Step 2: Create temporary workspace
            os.makedirs(backup_dir, exist_ok=True)

            # Step 3: Export all databases
            databases_to_backup = [
                ("config_overrides.db", "data/config_overrides.db"),
                ("devices.db", self.config.get_device_store_config()["database"]),
                ("local_auth.db", self.config.get_local_auth_db()),
                (
                    "tacacs_accounting.db",
                    self.config.get_database_config()["accounting_db"],
                ),
                (
                    "metrics_history.db",
                    self.config.get_database_config()["metrics_history_db"],
                ),
                ("audit_trail.db", self.config.get_database_config()["audit_trail_db"]),
            ]
            databases_exported = 0
            for backup_name, source_path in databases_to_backup:
                try:
                    if source_path and os.path.exists(source_path):
                        self._export_database(
                            source_path, os.path.join(backup_dir, backup_name)
                        )
                        databases_exported += 1
                except Exception as exc:
                    # Log but don't fail entire backup
                    _logger.warning(
                        "Failed to export database",
                        event="backup_db_export_failed",
                        db=backup_name,
                        error=str(exc),
                    )

            if databases_exported == 0:
                raise RuntimeError("No databases were successfully exported")

            # Step 4: Export configuration
            try:
                if not self.config.is_url_config() and getattr(
                    self.config, "config_file", None
                ):
                    if os.path.exists(self.config.config_file):
                        shutil.copy2(
                            self.config.config_file,
                            os.path.join(backup_dir, "tacacs.conf"),
                        )
            except Exception as exc:
                _logger.warning(
                    "Backup config copy failed",
                    event="backup_config_copy_failed",
                    error=str(exc),
                )

            config_dict = self.config._export_full_config()
            with open(
                os.path.join(backup_dir, "config_export.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(config_dict, f, indent=2)

            # Step 5: Remove transient SQLite sidecar files to stabilize archive
            self._cleanup_sidecars(backup_dir, "pre-manifest cleanup")

            # Step 6: Create manifest
            manifest = self._create_manifest(backup_dir, backup_type, triggered_by)
            with open(
                os.path.join(backup_dir, "manifest.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(manifest, f, indent=2)

            # Step 7: Remove any sidecars that may have been created during manifest DB reads
            self._cleanup_sidecars(backup_dir, "post-manifest cleanup")

            # Step 8: Create compressed archive
            timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
            # Sanitize components used in the archive and remote paths
            from tacacs_server.backup.destinations.base import (
                BackupDestination as _BD,
            )

            safe_instance = _BD.validate_path_segment(
                str(self.instance_name), allow_dot=False, max_len=64
            )
            safe_type = _BD.validate_path_segment(
                str(backup_type), allow_dot=False, max_len=32
            )
            filename = f"backup-{safe_instance}-{timestamp}-{safe_type}.tar.gz"
            from tacacs_server.backup.path_policy import safe_temp_path as _safe_temp

            archive_path = str(_safe_temp(filename))
            self._create_tarball(backup_dir, archive_path)

            # Get encryption settings from config
            encryption_enabled = False
            passphrase_cfg = None

            # Try to get config from different possible locations
            try:
                backup_cfg = self.config.get_backup_config()
                encryption_enabled = backup_cfg.get("encryption_enabled", False)
                if isinstance(encryption_enabled, str):
                    encryption_enabled = encryption_enabled.lower() == "true"
                passphrase_cfg = backup_cfg.get("encryption_passphrase")
            except Exception as e:
                _logger.debug(
                    "Encryption config not available",
                    error=str(e),
                )

            if encryption_enabled:
                if not passphrase_cfg:
                    raise ValueError("Encryption enabled but no passphrase configured")
                _logger.info(
                    "Encrypting backup archive",
                    event="backup_encrypting",
                    execution_id=execution_id,
                    file=filename,
                )

                from tacacs_server.backup.path_policy import (
                    safe_temp_path as _safe_temp,
                )

                enc_name = os.path.basename(archive_path) + ".enc"
                encrypted_path = str(_safe_temp(enc_name))
                enc_info = BackupEncryption.encrypt_file(
                    archive_path, encrypted_path, passphrase_cfg
                )

                # Update manifest with encryption info
                try:
                    manifest["encrypted"] = True
                    encryption_algorithm = "Fernet-AES128-CBC"
                    manifest["encryption_algorithm"] = encryption_algorithm
                    manifest["original_checksum"] = enc_info.get("original_checksum")
                    manifest["encryption_metadata"] = {
                        "salt_hex": enc_info.get("salt_hex"),
                        "encrypted_size_bytes": enc_info.get("encrypted_size"),
                    }
                    # Also track compressed size pre-encryption for reporting
                    manifest["compressed_size_bytes"] = os.path.getsize(archive_path)
                except Exception as exc:
                    _logger.warning(
                        "Failed to update manifest after encryption",
                        error=str(exc),
                    )

                # Replace archive with encrypted version
                try:
                    os.remove(archive_path)
                except Exception as exc:
                    _logger.warning(
                        "Failed to remove plain archive after encryption",
                        error=str(exc),
                    )
                archive_path = encrypted_path
                # Ensure filename has .enc extension
                if not filename.endswith(".enc"):
                    filename = f"{filename}.enc"

                _logger.info(
                    "Backup encrypted",
                    event="backup_encrypted",
                    execution_id=execution_id,
                    original_size=enc_info.get("original_size"),
                    encrypted_size=enc_info.get("encrypted_size"),
                    size_increase_percent=round(
                        (
                            enc_info.get("encrypted_size", 0)
                            / max(1, enc_info.get("original_size", 1))
                            - 1
                        )
                        * 100,
                        2,
                    ),
                )

            # Step 7: Upload to destination
            dest_config = self.execution_store.get_destination(destination_id)
            if not dest_config:
                raise ValueError("Destination not found")
            destination = create_destination(
                dest_config["type"], json.loads(dest_config["config_json"])
            )
            ok, msg = destination.test_connection()
            if not ok:
                raise RuntimeError(f"Destination test failed: {msg}")

            # Update filename to include .enc extension if encrypted
            if encryption_enabled and not filename.endswith(".enc"):
                filename = f"{filename}.enc"

            # Build remote path from sanitized segments only
            remote_path = f"{safe_instance}/{safe_type}/{filename}"
            uploaded_path = self._upload_with_progress(
                archive_path, destination, remote_path, execution_id
            )

            # Step 8: Update execution record
            archive_size = (
                os.path.getsize(archive_path) if os.path.exists(archive_path) else 0
            )

            # Ensure backup_filename has .enc extension if encrypted
            backup_filename = filename
            if encryption_enabled and not backup_filename.endswith(".enc"):
                backup_filename = f"{backup_filename}.enc"

            self.execution_store.update_execution(
                execution_id,
                backup_filename=backup_filename,
                backup_path=uploaded_path,
                status="completed",
                size_bytes=manifest["total_size_bytes"],
                compressed_size_bytes=archive_size,
                files_included=len(manifest["contents"]),
                completed_at=datetime.now(UTC).isoformat(),
                manifest_json=json.dumps(manifest),
            )
            self.execution_store.set_last_backup(destination_id, status="success")
            dur = (datetime.now(UTC) - t0).total_seconds()
            size = int(manifest.get("total_size_bytes", archive_size) or archive_size)
            comp = int(archive_size)
            ratio = (comp / size) if size else None
            _logger.info(
                "Backup completed",
                event="backup_completed",
                execution_id=execution_id,
                duration_seconds=dur,
                size_bytes=size,
                compressed_size_bytes=comp,
                compression_ratio=ratio,
                files_count=int(len(manifest.get("contents", []))),
            )
            return execution_id
        except Exception as exc:
            _logger.exception(
                "Backup failed",
                event="backup_failed",
                execution_id=execution_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            try:
                self.execution_store.update_execution(
                    execution_id, status="failed", error_message=str(exc)
                )
                self.execution_store.set_last_backup(destination_id, status="failed")
            except Exception as update_exc:
                _logger.warning(
                    "Failed to update execution status after failure",
                    error=str(update_exc),
                )
            return execution_id
        finally:
            # Step 9: Cleanup
            try:
                if backup_dir and os.path.isdir(backup_dir):
                    shutil.rmtree(backup_dir, ignore_errors=True)
            except Exception as cleanup_exc:
                _logger.warning(
                    "Failed to remove backup workspace",
                    error=str(cleanup_exc),
                    path=backup_dir,
                )
            try:
                if archive_path and os.path.exists(archive_path):
                    os.remove(archive_path)
            except Exception as cleanup_exc:
                _logger.warning(
                    "Failed to remove temporary archive",
                    error=str(cleanup_exc),
                    path=archive_path,
                )
            # Step 10: Apply retention policy (best-effort)
            try:
                dest_config = self.execution_store.get_destination(destination_id)
                if dest_config:
                    destination = create_destination(
                        dest_config["type"], json.loads(dest_config["config_json"])
                    )
                    # Prefer advanced retention strategy if configured
                    strat = str(dest_config.get("retention_strategy", "simple")).lower()
                    cfg_raw = dest_config.get("retention_config_json") or "{}"
                    try:
                        retention_cfg = (
                            json.loads(cfg_raw)
                            if isinstance(cfg_raw, str)
                            else (cfg_raw or {})
                        )
                    except Exception as parse_exc:
                        _logger.warning(
                            "Failed to parse retention config",
                            event="retention_config_parse_failed",
                            destination_id=destination_id,
                            error=str(parse_exc),
                        )
                        retention_cfg = {}
                    try:
                        from tacacs_server.backup.retention import (
                            RetentionRule as _Rule,
                        )
                        from tacacs_server.backup.retention import (
                            RetentionStrategy as _Strat,
                        )

                        rule = _Rule(strategy=_Strat(strat), **retention_cfg)
                        destination.apply_retention_policy(retention_rule=rule)
                    except Exception as rule_exc:
                        _logger.warning(
                            "Advanced retention enforcement failed",
                            event="retention_apply_failed",
                            destination_id=destination_id,
                            error=str(rule_exc),
                        )
                        # Fallback to days if strategy invalid
                        rd = int(dest_config.get("retention_days", 30))
                        destination.apply_retention_policy(retention_days=rd)
            except Exception as retention_exc:
                _logger.warning(
                    "Retention policy enforcement failed",
                    error=str(retention_exc),
                )
            finally:
                if ctx_token:
                    clear_context(ctx_token)

    def restore_backup(
        self,
        source_path: str,
        destination_id: str | None = None,
        components: list[str] | None = None,
        *,
        post_restart: bool = True,
    ) -> tuple[bool, str]:
        """
        Restore from backup.
        components: List of what to restore ["config", "devices", "users", "accounting"]
        Returns: (success, message)
        """
        t0 = datetime.now(UTC)
        allowed = {"config", "devices", "users", "accounting", "metrics", "audit"}
        if components is not None and not all(c in allowed for c in components):
            return False, f"Invalid component. Must be one of: {', '.join(allowed)}"

        local_archive = None
        archive_for_extract = None
        restore_root = None
        emergency_exec_id = None
        ctx_token = bind_context(
            restore_source=source_path,
            destination_id=destination_id,
        )

        maintenance_module = importlib.import_module("tacacs_server.utils.maintenance")
        get_db_manager = maintenance_module.get_db_manager
        restart_services = maintenance_module.restart_services

        maintenance_entered = False
        try:
            _logger.info(
                "Restore started",
                event="restore_started",
                source_path=source_path,
                destination_id=destination_id,
                components=components or list(allowed),
            )
            # Step 1: Download backup if remote
            if destination_id:
                dest_config = self.execution_store.get_destination(destination_id)
                if not dest_config:
                    return False, f"Destination {destination_id} not found"
                destination = create_destination(
                    dest_config["type"], json.loads(dest_config["config_json"])
                )
                _logger.info(
                    "Restore downloading backup",
                    event="restore_downloading",
                    source=source_path,
                    destination_id=destination_id,
                )
                # Download from destination to validated temp path
                try:
                    from tacacs_server.backup.destinations.base import (
                        BackupDestination as _BD_valid,
                    )
                    from tacacs_server.backup.path_policy import (
                        safe_temp_path as _safe_temp,
                    )

                    base_name = os.path.basename(source_path)
                    safe_name = _BD_valid.validate_path_segment(
                        base_name, allow_dot=True, max_len=255
                    )
                    local_archive = str(_safe_temp(safe_name))
                except Exception:
                    return False, "Invalid local archive path"
                destination.download_backup(source_path, local_archive)
                _logger.info(
                    "Restore download completed",
                    event="restore_downloaded",
                    source=source_path,
                    size_bytes=os.path.getsize(local_archive),
                )
            else:
                # If a local source path is provided, stage it under our temp_dir
                # to avoid operating directly on user-controlled locations.
                try:
                    from tacacs_server.backup.destinations.base import (
                        BackupDestination as _BD_valid,
                    )
                    from tacacs_server.backup.path_policy import (
                        safe_temp_path as _safe_temp,
                    )

                    base_name = os.path.basename(source_path)
                    safe_name = _BD_valid.validate_path_segment(
                        base_name, allow_dot=True, max_len=255
                    )
                    staged_path = str(_safe_temp(safe_name))
                    # Validate local source path before copying
                    try:
                        from tacacs_server.backup.path_policy import (
                            safe_input_file as _safe_in,
                        )

                        src_checked = _safe_in(source_path)
                        shutil.copy2(str(src_checked), staged_path)
                    except Exception:
                        return False, "Invalid or unsafe local source path"
                    local_archive = staged_path
                except Exception:
                    return False, "Invalid or inaccessible local source path"

            # Step 2: Decrypt if necessary
            is_encrypted = local_archive.endswith(".enc")
            archive_for_extract = local_archive

            if is_encrypted:
                passphrase = self._get_encryption_passphrase()
                if not passphrase:
                    _logger.warning(
                        "Restore decryption passphrase missing",
                        event="restore_auth_failed",
                        source_path=local_archive,
                    )
                    return False, "Backup is encrypted but no passphrase configured"
                if not BackupEncryption.verify_passphrase(local_archive, passphrase):
                    _logger.warning(
                        "Restore passphrase verification failed",
                        event="restore_auth_failed",
                        source_path=local_archive,
                    )
                    return False, "Incorrect encryption passphrase"

                from tacacs_server.backup.path_policy import (
                    safe_temp_path as _safe_temp,
                )

                dec_name = os.path.basename(local_archive)[:-4]
                try:
                    from tacacs_server.backup.destinations.base import (
                        BackupDestination as _BD_valid,
                    )

                    dec_name = _BD_valid.validate_path_segment(
                        dec_name, allow_dot=True, max_len=255
                    )
                except Exception:
                    return False, "Invalid decrypted path"
                decrypted_path = str(_safe_temp(dec_name))
                _logger.info(
                    "Decrypting restore archive",
                    event="restore_decrypting",
                    source_path=local_archive,
                    target_path=decrypted_path,
                )
                if not decrypt_file(local_archive, decrypted_path, passphrase):
                    _logger.warning(
                        "Restore decryption failed",
                        event="restore_decrypt_failed",
                        source_path=local_archive,
                    )
                    return False, "Decryption failed - file may be corrupted"
                archive_for_extract = decrypted_path

            # Step 3: Extract and verify archive
            from tacacs_server.backup.path_policy import join_safe_temp as _join_temp

            restore_root = str(_join_temp(f"restore_{uuid.uuid4()}"))
            self._extract_tarball(archive_for_extract, restore_root)

            manifest_path = os.path.join(restore_root, "manifest.json")
            if not os.path.exists(manifest_path):
                return False, "Manifest not found in backup"

            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)

            for file_entry in manifest.get("contents", []):
                # Validate manifest file path as a relative path
                try:
                    from tacacs_server.backup.destinations.base import (
                        BackupDestination as _BD,
                    )

                    rel = _BD.validate_relative_path(str(file_entry["file"]))
                except Exception:
                    return False, "Invalid file path in manifest"
                fp = os.path.join(restore_root, rel)
                if os.path.isfile(fp):
                    actual = self._calculate_sha256(fp)
                    if actual != file_entry["checksum_sha256"]:
                        return False, f"Checksum mismatch for {file_entry['file']}"

            # Step 4: Pre-restore safety backup
            try:
                emergency_dest_id = (
                    destination_id or self._pick_fallback_destination_id()
                )
                if emergency_dest_id:
                    emergency_exec_id = self.execute_backup(
                        destination_id=emergency_dest_id,
                        triggered_by="system:pre-restore",
                        backup_type="emergency",
                    )
            except Exception as e:
                _logger.warning(
                    "Emergency pre-restore backup failed",
                    event="restore_emergency_backup_failed",
                    error=str(e),
                    destination_id=destination_id,
                )

            _logger.info(
                "A server restart is required to apply all restored settings.",
                event="restore_restart_required",
            )

            # Step 5: Enter maintenance and restore components
            try:
                get_db_manager().enter_maintenance()
                maintenance_entered = True
            except Exception as maintenance_exc:
                _logger.warning(
                    "Failed to enter maintenance mode before restore",
                    error=str(maintenance_exc),
                )
            components_to_restore = components or list(allowed)
            databases_restored = self._perform_component_restore(
                components_to_restore, restore_root
            )

            # Step 6: Verify restored data
            for db_path in databases_restored:
                db_verify(db_path)

            # Step 7: Log completion
            dur = (datetime.now(UTC) - t0).total_seconds()
            _logger.info(
                "Restore completed",
                event="restore_completed",
                source_path=source_path,
                duration_seconds=dur,
                components=components_to_restore,
                emergency_backup_id=emergency_exec_id,
            )
            return True, "Restore completed successfully. A restart is required."

        except Exception as exc:
            _logger.exception(
                "Restore failed",
                event="restore_failed",
                source_path=source_path,
                error=str(exc),
            )
            return False, f"Restore failed: {exc}"
        finally:
            # Step 8: Cleanup temporary files (only within temp_dir)
            def _safe_cleanup(path: str, is_dir: bool = False):
                safe_path: str | None = None
                try:
                    # Convert any absolute path to a relative under temp_dir
                    rel = os.path.relpath(path, str(self.temp_dir))
                    safe_path = self._safe_local_path(rel)
                except Exception as safe_exc:
                    _logger.warning(
                        "Cleanup path validation failed",
                        path=path,
                        error=str(safe_exc),
                    )
                if safe_path is not None:
                    try:
                        if is_dir:
                            if os.path.isdir(safe_path):
                                shutil.rmtree(safe_path, ignore_errors=True)
                        else:
                            if os.path.exists(safe_path):
                                os.remove(safe_path)
                    except Exception as cleanup_exc:
                        _logger.warning(
                            "Failed to clean path",
                            path=safe_path,
                            error=str(cleanup_exc),
                        )

            if restore_root:
                _safe_cleanup(restore_root, is_dir=True)
            if archive_for_extract and archive_for_extract != local_archive:
                _safe_cleanup(archive_for_extract, is_dir=False)
            if destination_id and local_archive:
                _safe_cleanup(local_archive, is_dir=False)
            # Exit maintenance and optionally restart services
            if maintenance_entered:
                try:
                    get_db_manager().exit_maintenance()
                except Exception as maintenance_exit_exc:
                    _logger.warning(
                        "Failed to exit maintenance mode",
                        error=str(maintenance_exit_exc),
                    )
            if post_restart:
                try:
                    restart_services()
                except Exception as restart_exc:
                    _logger.warning(
                        "Failed to restart services", error=str(restart_exc)
                    )
            if ctx_token:
                clear_context(ctx_token)

    def _perform_component_restore(
        self, components: list[str], restore_root: str
    ) -> list[str]:
        """Helper to restore specific components from the extracted backup."""
        databases_restored: list[str] = []
        db_map = {
            "devices": (
                "devices.db",
                self.config.get_device_store_config()["database"],
            ),
            "users": ("local_auth.db", self.config.get_local_auth_db()),
            "accounting": (
                "tacacs_accounting.db",
                self.config.get_database_config()["accounting_db"],
            ),
            "metrics": (
                "metrics_history.db",
                self.config.get_database_config()["metrics_history_db"],
            ),
            "audit": (
                "audit_trail.db",
                self.config.get_database_config()["audit_trail_db"],
            ),
            "overrides": ("config_overrides.db", "data/config_overrides.db"),
        }

        if "config" in components:
            src_cfg = os.path.join(restore_root, "tacacs.conf")
            if os.path.exists(src_cfg) and getattr(self.config, "config_file", None):
                os.makedirs(os.path.dirname(self.config.config_file), exist_ok=True)
                shutil.copy2(src_cfg, self.config.config_file)
                _logger.info(
                    "Restored main configuration file.",
                    event="restore_config_restored",
                )

        for comp, (src_name, dest_path) in db_map.items():
            if comp in components:
                src_db = os.path.join(restore_root, src_name)
                if os.path.exists(src_db):
                    self._restore_database(src_db, dest_path)
                    databases_restored.append(dest_path)
                    _logger.info(
                        "Restored database",
                        event="restore_database_restored",
                        component=comp,
                        destination_path=dest_path,
                    )
        return databases_restored

    def create_manual_backup(self, destination_id: str, created_by: str) -> str:
        """Trigger manual backup and return execution_id."""
        if not destination_id:
            raise ValueError("destination_id required")
        if not created_by:
            raise ValueError("created_by required")
        return self.execute_backup(
            destination_id, triggered_by=created_by, backup_type="manual"
        )

    def get_backup_status(self, execution_id: str) -> dict:
        """Get status of an ongoing or completed backup by execution_id."""
        if not execution_id:
            raise ValueError("execution_id required")
        return self.execution_store.get_execution(execution_id) or {}

    @staticmethod
    def _parse_json(v: Any) -> dict:
        if isinstance(v, dict):
            return v
        try:
            return json.loads(v) if isinstance(v, str) else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    # --- restore helpers ---
    @staticmethod
    def _extract_tarball(archive_path: str, dest_dir: str) -> str:
        """Securely extract tarball to the destination directory."""
        os.makedirs(dest_dir, exist_ok=True)
        with tarfile.open(archive_path, "r:gz") as tar:
            abs_dest = os.path.abspath(dest_dir)
            members = tar.getmembers()
            safe_members = []
            for member in members:
                member_path = os.path.abspath(os.path.join(dest_dir, member.name))
                if os.path.commonpath([abs_dest, member_path]) != abs_dest:
                    raise RuntimeError(f"Unsafe path inside tarball: {member.name}")
                safe_members.append(member)
            for member in safe_members:
                tar.extract(member, path=dest_dir)
        return dest_dir

    @staticmethod
    def _restore_database(src_db_path: str, dest_db_path: str) -> None:
        """Restore a database file with verification."""
        if not os.path.exists(src_db_path):
            _logger.warning("Source DB for restore not found", source_path=src_db_path)
            return
        try:
            # Verify the backup database before importing
            db_verify(src_db_path)

            # Ensure destination directory exists
            dest_dir = os.path.dirname(dest_db_path)
            os.makedirs(dest_dir, exist_ok=True)

            # Import the database
            db_import(src_db_path, dest_db_path)
            _logger.info(
                "Successfully restored database",
                event="restore_database_imported",
                destination_path=dest_db_path,
            )
        except Exception as e:
            _logger.error(
                "Failed to restore database",
                event="restore_database_failed",
                destination_path=dest_db_path,
                error=str(e),
            )
            raise RuntimeError(f"Database restore failed for {dest_db_path}") from e

    def _pick_fallback_destination_id(self) -> str | None:
        try:
            rows = self.execution_store.list_destinations(enabled_only=True)
            if not rows:
                return None
            # Prefer local type if available
            for r in rows:
                if str(r.get("type", "")).lower() == "local":
                    return str(r.get("id"))
            return str(rows[0].get("id"))
        except Exception:
            return None

    def _get_encryption_passphrase(self) -> str | None:
        # Prefer environment variable to avoid storing secrets in DB
        env_passphrase = os.getenv("BACKUP_ENCRYPTION_PASSPHRASE")
        if env_passphrase:
            return env_passphrase

        # Fallback to config
        try:
            bcfg = getattr(self.config, "get_backup_config", None)
            if callable(bcfg):
                b = bcfg() or {}
                passphrase_cfg = b.get("encryption_passphrase")
                if passphrase_cfg:
                    return str(passphrase_cfg)

            # If not found, try direct config access
            if hasattr(self.config, "config"):
                if hasattr(self.config.config, "get"):
                    backup_section = self.config.config.get("backup", {})
                    passphrase_cfg = backup_section.get("encryption_passphrase")
                    if passphrase_cfg:
                        return str(passphrase_cfg)
        except Exception as e:
            _logger.warning(
                "Error getting encryption passphrase from config", error=str(e)
            )

        return None


# --- Service singleton (explicit init) ---
_backup_service_instance: BackupService | None = None


def initialize_backup_service(config: Any) -> BackupService:
    """Initialize global backup service instance"""
    global _backup_service_instance
    exec_module = importlib.import_module("tacacs_server.backup.execution_store")

    execution_store = exec_module.BackupExecutionStore("data/backup_executions.db")
    _backup_service_instance = BackupService(config, execution_store)
    # Verify fixed roots are available and writable
    try:
        from tacacs_server.backup.path_policy import get_backup_root, get_temp_root

        br = get_backup_root()
        tr = get_temp_root()
        # Simple writability checks
        test_f = tr / ".writetest"
        test_f.write_text("ok", encoding="utf-8")
        test_f.unlink(missing_ok=True)
        if not br.exists() or not br.is_dir():
            raise RuntimeError(f"Backup root unavailable: {br}")
    except Exception as e:
        _logger.warning(
            "Backup path roots check failed",
            error=str(e),
        )
    try:
        from tacacs_server.backup.scheduler import BackupScheduler as _BackupScheduler

        _backup_service_instance.scheduler = _BackupScheduler(_backup_service_instance)
        _backup_service_instance.scheduler.start()
    except Exception as exc:
        _logger.warning(
            "Failed to start scheduler during init",
            error=str(exc),
        )
    # Ensure a default local destination exists when none are configured.
    try:
        rows = _backup_service_instance.execution_store.list_destinations()
        if not rows:
            # Create a sensible default local destination
            try:
                from tacacs_server.backup.path_policy import get_backup_root

                base_path = str(get_backup_root())
            except Exception:
                base_path = str((Path("/data/backups")).resolve())
            os.makedirs(base_path, exist_ok=True)
            dest_id = _backup_service_instance.execution_store.create_destination(
                name="local-default",
                dest_type="local",
                config={"base_path": base_path},
                retention_days=30,
                created_by="system",
            )
            # Schedule a daily backup at 04:00 using the scheduler, if available
            try:
                sched = _backup_service_instance.scheduler
                if sched is not None:
                    sched.add_job(
                        job_id="backup_daily_default",
                        schedule_type="cron",
                        schedule_value="0 4 * * *",
                        destination_id=dest_id,
                        created_by="system",
                    )
            except Exception as exc:
                _logger.warning(
                    "Failed to schedule default backup job",
                    error=str(exc),
                )
    except Exception:
        # Do not block initialization if defaults cannot be created
        _logger.warning("Default backup destination setup failed")
    return _backup_service_instance


def get_backup_service() -> BackupService:
    """Get global backup service instance."""
    global _backup_service_instance

    if _backup_service_instance is None:
        # Lazy initialization fallback for testing/standalone web app
        try:
            config_utils = importlib.import_module("tacacs_server.utils.config_utils")
            config = config_utils.get_config()
            if config:
                _backup_service_instance = initialize_backup_service(config)
                _logger.info("Backup service lazy-initialized")
        except Exception as e:
            _logger.error(
                "Backup service lazy-init failed",
                error=str(e),
            )
            raise RuntimeError("Backup service not initialized") from e

    assert _backup_service_instance is not None
    return _backup_service_instance
