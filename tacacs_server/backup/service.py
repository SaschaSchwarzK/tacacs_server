import hashlib
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

from tacacs_server.config.config import TacacsConfig
from tacacs_server.utils.logger import get_logger

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
from .execution_store import BackupExecutionStore
from .scheduler import BackupScheduler

_logger = get_logger("tacacs_server.backup.service", component="backup")

# Try to import humanize, but provide fallback
try:
    import humanize

    HAS_HUMANIZE = True
except ImportError:
    HAS_HUMANIZE = False
    _logger.warning("humanize library not available, size formatting will be basic")


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

        temp_dir = "data/backup_temp"
        try:
            if hasattr(self.config, "get_backup_config"):
                bcfg = self.config.get_backup_config()
                if bcfg and "temp_directory" in bcfg:
                    temp_dir = bcfg["temp_directory"]
        except Exception as e:
            _logger.debug(f"Using default temp_dir: {e}")

        self.temp_dir = Path(str(temp_dir))
        self._ensure_temp_dir()
        self.instance_name = (
            self.config.config_store.get_instance_name()
            if self.config.config_store is not None
            else "tacacs-server"
        )
        # Initialize scheduler (not started by default)
        self.scheduler: BackupScheduler | None = None
        try:
            self.scheduler = BackupScheduler(self)
        except Exception as e:
            _logger.warning(f"Scheduler initialization failed: {e}")
            self.scheduler = None
        self.instance_id = (
            self.config.config_store.get_metadata("instance_id")
            if self.config.config_store is not None
            else None
        )

    def _ensure_temp_dir(self) -> None:
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    # --- helpers ---
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
                    f"Source database {src_path} failed integrity check, attempting export anyway"
                )

            db_export(src_path, dst_path)

            if not os.path.exists(dst_path):
                raise RuntimeError(f"Export failed: {dst_path} was not created")

            # Verify exported database
            ok, msg = db_verify(dst_path)
            if not ok:
                _logger.warning(f"Exported database integrity issue: {msg}")
                # Don't fail - continue with backup

        except Exception as e:
            _logger.error(f"Database export failed: {e}")

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
            from typing import Any

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
        """Upload with periodic progress logs (best-effort callback).

        Args:
            local_path: Path to the local file to upload
            destination: Destination object with upload method
            remote_filename: Filename to use at the destination
            execution_id: ID of the backup execution

        Returns:
            str: Remote path where the file was uploaded
        """
        file_size = os.path.getsize(local_path)
        last_log_time = 0.0
        bytes_uploaded = 0

        def progress_callback(chunk):
            nonlocal bytes_uploaded, last_log_time
            bytes_uploaded += len(chunk)

            # Log progress at most once per second
            current_time = time.time()
            if current_time - last_log_time >= 1.0:
                last_log_time = current_time
                percent = (bytes_uploaded / file_size) * 100 if file_size > 0 else 0
                try:
                    if HAS_HUMANIZE:
                        size_str = f"{humanize.naturalsize(bytes_uploaded, binary=True)}/{humanize.naturalsize(file_size, binary=True)}"
                    else:
                        size_str = f"{bytes_uploaded}/{file_size} bytes"
                    _logger.info(
                        f"Backup upload progress: {percent:.1f}% ({size_str})",
                        extra={
                            "event": "backup_upload_progress",
                            "execution_id": execution_id,
                            "bytes_uploaded": bytes_uploaded,
                            "total_bytes": file_size,
                            "percent_complete": round(percent, 2),
                        },
                    )
                except Exception as e:
                    _logger.warning("Failed to log upload progress: %s", e)

        # Try to pass progress_callback if destination supports it
        try:
            if hasattr(destination, "upload"):
                return str(
                    destination.upload(
                        local_path,
                        remote_filename=remote_filename,
                    )
                )
            elif hasattr(destination, "upload_backup"):
                return str(
                    destination.upload_backup(
                        local_path, remote_filename=remote_filename
                    )
                )
            else:
                # Fallback to simple upload if neither method is available
                _logger.warning(
                    "Destination doesn't support progress callbacks, using simple upload"
                )
                if hasattr(destination, "upload"):
                    return str(destination.upload(local_path, remote_filename))
                else:
                    return str(destination.upload_backup(local_path, remote_filename))

        except Exception as e:
            _logger.error("Upload failed: %s", str(e))
            raise

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
        backup_dir = os.path.join(str(self.temp_dir), execution_id)
        archive_path = None
        t0 = datetime.now(UTC)

        try:
            # Step 1: Initialize execution tracking
            self.execution_store.create_execution(
                execution_id=execution_id,
                destination_id=destination_id,
                triggered_by=triggered_by,
            )
            try:
                _logger.info(
                    json.dumps(
                        {
                            "event": "backup_started",
                            "execution_id": execution_id,
                            "destination_id": destination_id,
                            "triggered_by": triggered_by,
                            "backup_type": backup_type,
                        }
                    )
                )
            except Exception:
                pass

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
                        f"Failed to export {backup_name}: {exc}",
                        extra={"db": backup_name, "error": str(exc)},
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
                _logger.warning("backup_config_copy_failed", error=str(exc))

            config_dict = self.config._export_full_config()
            with open(
                os.path.join(backup_dir, "config_export.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(config_dict, f, indent=2)

            # Step 5: Create manifest
            manifest = self._create_manifest(backup_dir, backup_type, triggered_by)
            with open(
                os.path.join(backup_dir, "manifest.json"), "w", encoding="utf-8"
            ) as f:
                json.dump(manifest, f, indent=2)

            # Step 6: Create compressed archive
            timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
            filename = f"backup-{self.instance_name}-{timestamp}-{backup_type}.tar.gz"
            archive_path = os.path.join(str(self.temp_dir), filename)
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
                _logger.debug(f"Encryption config not available: {e}")

            if encryption_enabled:
                if not passphrase_cfg:
                    raise ValueError("Encryption enabled but no passphrase configured")
                try:
                    _logger.info(
                        json.dumps(
                            {
                                "event": "backup_encrypting",
                                "execution_id": execution_id,
                                "file": filename,
                            }
                        )
                    )
                except Exception:
                    pass

                encrypted_path = archive_path + ".enc"
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
                except Exception:
                    pass

                # Replace archive with encrypted version
                try:
                    os.remove(archive_path)
                except Exception:
                    pass
                archive_path = encrypted_path
                # Ensure filename has .enc extension
                if not filename.endswith(".enc"):
                    filename = f"{filename}.enc"

                try:
                    _logger.info(
                        json.dumps(
                            {
                                "event": "backup_encrypted",
                                "execution_id": execution_id,
                                "original_size": enc_info.get("original_size"),
                                "encrypted_size": enc_info.get("encrypted_size"),
                                "size_increase_percent": round(
                                    (
                                        enc_info.get("encrypted_size", 0)
                                        / max(1, enc_info.get("original_size", 1))
                                        - 1
                                    )
                                    * 100,
                                    2,
                                ),
                            }
                        )
                    )
                except Exception:
                    pass

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

            remote_path = f"{self.instance_name}/{backup_type}/{filename}"
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
            try:
                dur = (datetime.now(UTC) - t0).total_seconds()
                size = int(
                    manifest.get("total_size_bytes", archive_size) or archive_size
                )
                comp = int(archive_size)
                ratio = (comp / size) if size else None
                _logger.info(
                    json.dumps(
                        {
                            "event": "backup_completed",
                            "execution_id": execution_id,
                            "duration_seconds": dur,
                            "size_bytes": size,
                            "compressed_size_bytes": comp,
                            "compression_ratio": ratio,
                            "files_count": int(len(manifest.get("contents", []))),
                        }
                    )
                )
            except Exception:
                pass
            return execution_id
        except Exception as exc:
            try:
                _logger.exception(
                    json.dumps(
                        {
                            "event": "backup_failed",
                            "execution_id": execution_id,
                            "error": str(exc),
                            "error_type": type(exc).__name__,
                        }
                    )
                )
            except Exception:
                pass
            try:
                self.execution_store.update_execution(
                    execution_id, status="failed", error_message=str(exc)
                )
                self.execution_store.set_last_backup(destination_id, status="failed")
            except Exception:
                pass
            return execution_id
        finally:
            # Step 9: Cleanup
            try:
                if backup_dir and os.path.isdir(backup_dir):
                    shutil.rmtree(backup_dir, ignore_errors=True)
            except Exception:
                pass
            try:
                if archive_path and os.path.exists(archive_path):
                    os.remove(archive_path)
            except Exception:
                pass
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
                    except Exception:
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
                    except Exception:
                        # Fallback to days if strategy invalid
                        rd = int(dest_config.get("retention_days", 30))
                        destination.apply_retention_policy(retention_days=rd)
            except Exception:
                pass

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

        from tacacs_server.utils.maintenance import get_db_manager, restart_services

        maintenance_entered = False
        try:
            # Step 1: Download backup if remote
            if destination_id:
                dest_config = self.execution_store.get_destination(destination_id)
                if not dest_config:
                    return False, f"Destination {destination_id} not found"
                destination = create_destination(
                    dest_config["type"], json.loads(dest_config["config_json"])
                )
                _logger.info(
                    json.dumps(
                        {
                            "event": "restore_downloading",
                            "source": source_path,
                            "destination_id": destination_id,
                        }
                    )
                )
                local_archive = os.path.join(
                    str(self.temp_dir), os.path.basename(source_path)
                )
                destination.download_backup(source_path, local_archive)
                _logger.info(
                    json.dumps(
                        {
                            "event": "restore_downloaded",
                            "source": source_path,
                            "size_bytes": os.path.getsize(local_archive),
                        }
                    )
                )
            else:
                local_archive = source_path

            # Step 2: Decrypt if necessary
            is_encrypted = local_archive.endswith(".enc")
            archive_for_extract = local_archive

            if is_encrypted:
                passphrase = self._get_encryption_passphrase()
                if not passphrase:
                    return False, "Backup is encrypted but no passphrase configured"
                if not BackupEncryption.verify_passphrase(local_archive, passphrase):
                    return False, "Incorrect encryption passphrase"

                decrypted_path = local_archive[:-4]
                _logger.info(f"Decrypting {local_archive} to {decrypted_path}")
                if not decrypt_file(local_archive, decrypted_path, passphrase):
                    return False, "Decryption failed - file may be corrupted"
                archive_for_extract = decrypted_path

            # Step 3: Extract and verify archive
            restore_root = os.path.join(str(self.temp_dir), f"restore_{uuid.uuid4()}")
            self._extract_tarball(archive_for_extract, restore_root)

            manifest_path = os.path.join(restore_root, "manifest.json")
            if not os.path.exists(manifest_path):
                return False, "Manifest not found in backup"

            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)

            for file_entry in manifest.get("contents", []):
                fp = os.path.join(restore_root, file_entry["file"])
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
                _logger.warning(f"Emergency pre-restore backup failed: {e}")

            _logger.warning(
                "A server restart is required to apply all restored settings."
            )

            # Step 5: Enter maintenance and restore components
            try:
                get_db_manager().enter_maintenance()
                maintenance_entered = True
            except Exception:
                pass
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
                json.dumps(
                    {
                        "event": "restore_completed",
                        "source_path": source_path,
                        "duration_seconds": dur,
                        "components": components_to_restore,
                        "emergency_backup_id": emergency_exec_id,
                    }
                )
            )
            return True, "Restore completed successfully. A restart is required."

        except Exception as exc:
            _logger.exception(
                json.dumps(
                    {
                        "event": "restore_failed",
                        "source_path": source_path,
                        "error": str(exc),
                    }
                )
            )
            return False, f"Restore failed: {exc}"
        finally:
            # Step 8: Cleanup temporary files
            if restore_root and os.path.isdir(restore_root):
                shutil.rmtree(restore_root, ignore_errors=True)
            if archive_for_extract and archive_for_extract != local_archive:
                if os.path.exists(archive_for_extract):
                    os.remove(archive_for_extract)
            if destination_id and local_archive and os.path.exists(local_archive):
                os.remove(local_archive)
            # Exit maintenance and optionally restart services
            if maintenance_entered:
                try:
                    get_db_manager().exit_maintenance()
                except Exception:
                    pass
            if post_restart:
                try:
                    restart_services()
                except Exception:
                    pass

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
                _logger.info("Restored main configuration file.")

        for comp, (src_name, dest_path) in db_map.items():
            if comp in components:
                src_db = os.path.join(restore_root, src_name)
                if os.path.exists(src_db):
                    self._restore_database(src_db, dest_path)
                    databases_restored.append(dest_path)
                    _logger.info(f"Restored {comp} database.")
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
            tar.extractall(path=dest_dir)
        return dest_dir

    @staticmethod
    def _restore_database(src_db_path: str, dest_db_path: str) -> None:
        """Restore a database file with verification."""
        if not os.path.exists(src_db_path):
            _logger.warning(f"Source DB for restore not found: {src_db_path}")
            return
        try:
            # Verify the backup database before importing
            db_verify(src_db_path)

            # Ensure destination directory exists
            dest_dir = os.path.dirname(dest_db_path)
            os.makedirs(dest_dir, exist_ok=True)

            # Import the database
            db_import(src_db_path, dest_db_path)
            _logger.info(f"Successfully restored database to {dest_db_path}")
        except Exception as e:
            _logger.error(f"Failed to restore database to {dest_db_path}: {e}")
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
            _logger.warning(f"Error getting encryption passphrase from config: {e}")

        return None


# --- Service singleton (explicit init) ---
_backup_service_instance: BackupService | None = None


def initialize_backup_service(config: TacacsConfig) -> BackupService:
    """Initialize global backup service instance"""
    global _backup_service_instance
    execution_store = BackupExecutionStore("data/backup_executions.db")
    _backup_service_instance = BackupService(config, execution_store)
    try:
        _backup_service_instance.scheduler = BackupScheduler(_backup_service_instance)
        _backup_service_instance.scheduler.start()
    except Exception:
        pass
    return _backup_service_instance


def get_backup_service() -> "BackupService":
    """Get global backup service instance."""
    global _backup_service_instance

    if _backup_service_instance is None:
        # Lazy initialization fallback for testing/standalone web app
        try:
            from tacacs_server.utils.config_utils import get_config

            config = get_config()
            if config:
                _backup_service_instance = initialize_backup_service(config)
                _logger.info("Backup service lazy-initialized")
        except Exception as e:
            _logger.error(f"Backup service lazy-init failed: {e}")
            raise RuntimeError("Backup service not initialized") from e

    assert _backup_service_instance is not None
    return _backup_service_instance
