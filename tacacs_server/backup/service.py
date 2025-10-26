from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from tacacs_server.config.config import TacacsConfig
from tacacs_server.utils.logger import get_logger

from .archive_utils import create_tarball as create_tar
from .archive_utils import extract_tarball as extract_tar
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
from .encryption import decrypt_file, encrypt_file
from .execution_store import BackupExecutionStore
from .scheduler import BackupScheduler

_logger = get_logger("tacacs_server.backup.service", component="backup")


class BackupService:
    def __init__(self, config: TacacsConfig, execution_store: BackupExecutionStore):
        self.config = config
        self.execution_store = execution_store
        # Use temp directory from backup config if available
        try:
            bcfg = getattr(self.config, "get_backup_config", None)
            if callable(bcfg):
                temp_dir = bcfg().get("temp_directory") or "data/backup_temp"
            else:
                temp_dir = "data/backup_temp"
        except Exception:
            temp_dir = "data/backup_temp"
        self.temp_dir = Path(str(temp_dir))
        self._ensure_temp_dir()
        self.instance_name = (
            self.config.config_store.get_instance_name()
            if self.config.config_store
            else "tacacs-server"
        )
        # Initialize scheduler (not started by default)
        try:
            self.scheduler = BackupScheduler(self)
        except Exception:
            self.scheduler = None  # type: ignore[assignment]
        self.instance_id = (
            self.config.config_store.get_metadata("instance_id")
            if self.config.config_store
            else None
        )

    def _ensure_temp_dir(self) -> None:
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    # --- helpers ---
    def _export_database(self, src_path: str, dst_path: str) -> None:
        db_export(src_path, dst_path)

    def _create_manifest(
        self, backup_dir: str, backup_type: str, triggered_by: str
    ) -> dict:
        """Create manifest.json with metadata, checksums, and DB record counts."""
        manifest: dict[str, Any] = {
            "backup_metadata": {
                "instance_id": self.instance_id,
                "instance_name": self.instance_name,
                "hostname": socket.gethostname(),
                "backup_type": backup_type,
                "timestamp_utc": datetime.utcnow().isoformat() + "Z",
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
            "contents": [],
            "total_size_bytes": 0,
        }

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
            manifest["contents"].append(entry)
            manifest["total_size_bytes"] += file_size

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

    def _create_tarball(self, src_dir: str, archive_path: str) -> None:
        # Backwards-compatible wrapper; uses archive_utils
        create_tar(src_dir, archive_path, compression="gz")

    def execute_backup(
        self,
        destination_id: str,
        triggered_by: str,
        backup_type: str = "manual",
        execution_id: str | None = None,
    ) -> str:
        """Execute complete backup workflow and return execution_id."""
        execution_id = execution_id or str(uuid.uuid4())
        backup_dir = os.path.join(str(self.temp_dir), execution_id)
        archive_path = None
        t0 = datetime.utcnow()

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
            for backup_name, source_path in databases_to_backup:
                try:
                    if source_path and os.path.exists(source_path):
                        self._export_database(
                            source_path, os.path.join(backup_dir, backup_name)
                        )
                except Exception as exc:
                    _logger.warning(
                        "backup_db_export_failed", db=backup_name, error=str(exc)
                    )

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
            timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            filename = f"backup-{self.instance_name}-{timestamp}-{backup_type}.tar.gz"
            archive_path = os.path.join(str(self.temp_dir), filename)
            self._create_tarball(backup_dir, archive_path)

            # Optional encryption
            passphrase = self._get_encryption_passphrase()
            if passphrase:
                enc_path = archive_path + ".enc"
                encrypt_file(archive_path, enc_path, passphrase)
                try:
                    os.remove(archive_path)
                except Exception:
                    pass
                archive_path = enc_path
                filename = filename + ".enc"

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

            remote_path = f"{self.instance_name}/{backup_type}/{filename}"
            uploaded_path = destination.upload_backup(archive_path, remote_path)

            # Step 8: Update execution record
            archive_size = (
                os.path.getsize(archive_path) if os.path.exists(archive_path) else 0
            )
            self.execution_store.update_execution(
                execution_id,
                backup_filename=filename,
                backup_path=uploaded_path,
                status="completed",
                size_bytes=manifest["total_size_bytes"],
                compressed_size_bytes=archive_size,
                files_included=len(manifest["contents"]),
                completed_at=datetime.utcnow().isoformat() + "Z",
                manifest_json=json.dumps(manifest),
            )
            self.execution_store.set_last_backup(destination_id, status="success")
            try:
                dur = (datetime.utcnow() - t0).total_seconds()
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
                    destination.apply_retention_policy(
                        int(dest_config.get("retention_days", 30))
                    )
            except Exception:
                pass

    def restore_backup(
        self,
        source_path: str,
        destination_id: str | None = None,
        components: list[str] | None = None,
    ) -> tuple[bool, str]:
        """
        Restore from backup archive or remote path.
        components: ["config", "devices", "users", "accounting", "metrics", "audit"]
        Returns: (success, message)
        """
        local_archive = source_path
        restore_root = None
        emergency_exec_id: str | None = None
        t0 = datetime.utcnow()
        try:
            try:
                _logger.info(
                    json.dumps(
                        {
                            "event": "restore_started",
                            "source_path": source_path,
                            "destination_id": destination_id,
                            "components": components or [],
                        }
                    )
                )
            except Exception:
                pass
            # Step 1: Validation / optional download
            if destination_id:
                dest_cfg = self.execution_store.get_destination(destination_id)
                if not dest_cfg:
                    return False, "Destination not found"
                destination = create_destination(
                    dest_cfg["type"], json.loads(dest_cfg["config_json"])
                )
                tmp_name = f"restore_{uuid.uuid4()}.tar.gz"
                local_archive = os.path.join(str(self.temp_dir), tmp_name)
                ok = destination.download_backup(source_path, local_archive)
                if not ok:
                    return False, "Failed to download backup from destination"

            if not os.path.exists(local_archive):
                return False, "Local archive not found"

            # Step 2: Decrypt if needed, then extract and verify
            # Handle optional encryption by extension .enc
            archive_for_extract = local_archive
            if str(local_archive).endswith(".enc"):
                passphrase = self._get_encryption_passphrase()
                if not passphrase:
                    return (
                        False,
                        "Encrypted backup requires BACKUP_ENCRYPTION_PASSPHRASE",
                    )
                dec_path = local_archive[:-4]
                decrypt_file(local_archive, dec_path, passphrase)
                archive_for_extract = dec_path

            restore_dir = os.path.join(str(self.temp_dir), f"restore_{uuid.uuid4()}")
            os.makedirs(restore_dir, exist_ok=True)
            restore_root = self._extract_tarball(archive_for_extract, restore_dir)

            manifest_path = os.path.join(restore_root, "manifest.json")
            if not os.path.exists(manifest_path):
                return False, "Manifest not found in backup"
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)

            for file_entry in manifest.get("contents", []):
                rel = file_entry.get("file") or file_entry.get("path")
                if not rel:
                    continue
                fp = os.path.join(restore_root, rel)
                if os.path.isfile(fp):
                    actual = self._calculate_sha256(fp)
                    if (
                        actual
                        and file_entry.get("checksum_sha256")
                        and actual != file_entry.get("checksum_sha256")
                    ):
                        raise ValueError(f"Checksum mismatch for {rel}")

            # Step 3: Safety backup of current state (best-effort)
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
                else:
                    _logger.warning("no_destination_for_emergency_backup")
            except Exception:
                _logger.warning("emergency_backup_failed")

            # Step 4: Stop server components - handled by caller; log warning
            _logger.warning("server_restart_required_after_restore")

            # Step 5: Restore selected components
            if components is None:
                components = [
                    "config",
                    "devices",
                    "users",
                    "accounting",
                    "metrics",
                    "audit",
                ]

            db_map = {
                "devices": (
                    os.path.join(restore_root, "devices.db"),
                    self.config.get_device_store_config()["database"],
                ),
                "users": (
                    os.path.join(restore_root, "local_auth.db"),
                    self.config.get_local_auth_db(),
                ),
                "accounting": (
                    os.path.join(restore_root, "tacacs_accounting.db"),
                    self.config.get_database_config()["accounting_db"],
                ),
                "metrics": (
                    os.path.join(restore_root, "metrics_history.db"),
                    self.config.get_database_config()["metrics_history_db"],
                ),
                "audit": (
                    os.path.join(restore_root, "audit_trail.db"),
                    self.config.get_database_config()["audit_trail_db"],
                ),
                "overrides": (
                    os.path.join(restore_root, "config_overrides.db"),
                    "data/config_overrides.db",
                ),
            }

            databases_restored: list[str] = []

            if "config" in components:
                src_cfg = os.path.join(restore_root, "tacacs.conf")
                try:
                    if os.path.exists(src_cfg) and getattr(
                        self.config, "config_file", None
                    ):
                        os.makedirs(
                            os.path.dirname(self.config.config_file), exist_ok=True
                        )
                        shutil.copy2(src_cfg, self.config.config_file)
                except Exception as exc:
                    _logger.warning("config_restore_failed", error=str(exc))
                # Restore overrides DB if present
                src_db, dst_db = db_map["overrides"]
                if os.path.exists(src_db):
                    self._restore_database(src_db, dst_db)
                    databases_restored.append(dst_db)

            for comp in ("devices", "users", "accounting", "metrics", "audit"):
                if comp in components:
                    src_db, dst_db = db_map[comp]
                    if os.path.exists(src_db):
                        self._restore_database(src_db, dst_db)
                        databases_restored.append(dst_db)

            # Step 6: Verify restored data
            for db_file in databases_restored:
                try:
                    self._verify_database_integrity(db_file)
                except Exception as exc:
                    _logger.error("db_integrity_failed", db=db_file, error=str(exc))
                    raise

            try:
                issues = self.config.validate_config()
                if issues:
                    raise ValueError("; ".join(issues))
            except Exception as e:
                _logger.error("restored_config_invalid", error=str(e))
                # A full rollback from emergency backup could be triggered here
                raise

            # Step 7: Cleanup (handled in finally)

            # Step 8: Log restore event
            try:
                if getattr(self.config, "config_store", None):
                    self.config.config_store.record_change(
                        section="system",
                        key="restore",
                        old_value=None,
                        new_value=source_path,
                        value_type="string",
                        changed_by="admin",
                        reason=f"Restored from backup: {manifest.get('backup_metadata', {}).get('timestamp_utc', '')}",
                    )
            except Exception:
                pass

            try:
                dur = (datetime.utcnow() - t0).total_seconds()
                _logger.info(
                    json.dumps(
                        {
                            "event": "restore_completed",
                            "source_path": source_path,
                            "destination_id": destination_id,
                            "components": components or [],
                            "duration_seconds": dur,
                            "emergency_execution_id": emergency_exec_id,
                        }
                    )
                )
            except Exception:
                pass
            return True, "Restore completed"
        except Exception as exc:
            try:
                _logger.exception(
                    json.dumps(
                        {
                            "event": "restore_failed",
                            "source_path": source_path,
                            "destination_id": destination_id,
                            "error": str(exc),
                            "error_type": type(exc).__name__,
                        }
                    )
                )
            except Exception:
                pass
            return False, f"Restore failed: {exc}"
        finally:
            try:
                if restore_root and os.path.isdir(restore_root):
                    shutil.rmtree(restore_root)
            except Exception:
                pass
            try:
                if destination_id and local_archive and os.path.exists(local_archive):
                    os.remove(local_archive)
                # Remove decrypted temp if created
                dec_tmp = None
                if isinstance(local_archive, str) and local_archive.endswith(".enc"):
                    dec_tmp = local_archive[:-4]
                if dec_tmp and os.path.exists(dec_tmp):
                    os.remove(dec_tmp)
            except Exception:
                pass

    def create_manual_backup(self, destination_id: str, created_by: str) -> str:
        """Trigger manual backup, returns execution_id"""
        return self.execute_backup(
            destination_id, triggered_by=created_by, backup_type="manual"
        )

    def get_backup_status(self, execution_id: str) -> dict:
        """Get status of ongoing or completed backup"""
        return self.execution_store.get_execution(execution_id) or {}

    @staticmethod
    def _parse_json(v: Any) -> dict:
        import json

        if isinstance(v, dict):
            return v
        try:
            return json.loads(v) if isinstance(v, str) else {}
        except Exception:
            return {}

    # --- restore helpers ---
    @staticmethod
    def _extract_tarball(archive_path: str, dest_dir: str) -> str:
        # Delegate to secure extractor
        extract_tar(archive_path, dest_dir)
        # If there is a single top-level directory, return it; else dest_dir
        entries = [os.path.join(dest_dir, e) for e in os.listdir(dest_dir)]
        tops = [e for e in entries if os.path.isdir(e)]
        if len(tops) == 1 and os.path.exists(os.path.join(tops[0], "manifest.json")):
            return tops[0]
        return dest_dir

    @staticmethod
    def _restore_database(src_db_path: str, dest_db_path: str) -> None:
        db_import(src_db_path, dest_db_path, verify=True)

    @staticmethod
    def _verify_database_integrity(db_path: str) -> None:
        ok, msg = db_verify(db_path)
        if not ok:
            raise ValueError(f"Integrity check failed for {db_path}: {msg}")

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

    @staticmethod
    def _get_encryption_passphrase() -> str | None:
        # Prefer environment variable to avoid storing secrets in DB
        return os.getenv("BACKUP_ENCRYPTION_PASSPHRASE") or None


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


def get_backup_service() -> BackupService:
    """Get global backup service instance"""
    if _backup_service_instance is None:
        raise RuntimeError("Backup service not initialized")
    return _backup_service_instance
