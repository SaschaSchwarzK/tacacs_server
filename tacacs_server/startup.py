"""Container startup orchestration with Azure storage recovery"""

import os
import sys
import time
from pathlib import Path
from typing import Any

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class StartupOrchestrator:
    """Handles container startup logic with backup/config restoration"""

    def __init__(self):
        self.azure_enabled = False
        self.backup_restored = False
        self.config_downloaded = False

    def check_azure_env_vars(self) -> bool:
        """Check if Azure storage env variables are present (connection string or account-based)."""
        container = os.getenv("AZURE_STORAGE_CONTAINER")
        if not container:
            logger.info("Missing Azure env vars: AZURE_STORAGE_CONTAINER")
            return False

        conn_str = os.getenv("AZURE_CONNECTION_STRING") or os.getenv(
            "AZURE_STORAGE_CONNECTION_STRING"
        )

        # Connection string path
        if conn_str:
            logger.info("Azure storage env detected (connection string)")
            return True

        # Account-based auth
        has_key = bool(os.getenv("AZURE_ACCOUNT_KEY"))
        has_sas = bool(os.getenv("AZURE_SAS_TOKEN"))
        has_mi = bool(os.getenv("AZURE_USE_MANAGED_IDENTITY"))
        methods = sum([has_key, has_sas, has_mi])


        if not container:
            logger.info("Missing Azure env vars: AZURE_STORAGE_CONTAINER")
            return False

        if methods == 0:
            logger.info("No Azure authentication method configured")
            return False

        if not os.getenv("AZURE_STORAGE_ACCOUNT"):
            logger.info(
                "Missing Azure env vars: AZURE_STORAGE_ACCOUNT (required for key/SAS/managed identity auth)"
            )
            return False

        if methods > 1:
            logger.warning(
                "Multiple Azure auth methods configured, using first available"
            )

        logger.info("Azure storage environment variables detected")
        return True

    def restore_from_azure_backup(self) -> bool:
        """Download and restore latest backup from Azure storage"""
        try:
            # Check if Azure libraries are available
            try:
                import azure.storage.blob  # noqa: F401
            except ImportError:
                logger.warning(
                    "azure-storage-blob not installed, skipping Azure backup restore"
                )
                return False

            from tacacs_server.backup.destinations.azure import (
                AzureBlobBackupDestination,
            )

            # Build Azure config from env vars
            config: dict[str, Any] = {
                "container_name": os.getenv("AZURE_STORAGE_CONTAINER"),
                "base_path": os.getenv("AZURE_BACKUP_PATH", "backups"),
            }

            # Add auth config
            conn_str = os.getenv("AZURE_CONNECTION_STRING") or os.getenv(
                "AZURE_STORAGE_CONNECTION_STRING"
            )
            if conn_str:
                config["connection_string"] = conn_str
            else:
                config["account_name"] = os.getenv("AZURE_STORAGE_ACCOUNT")
                if os.getenv("AZURE_ACCOUNT_KEY"):
                    config["account_key"] = os.getenv("AZURE_ACCOUNT_KEY")
                elif os.getenv("AZURE_SAS_TOKEN"):
                    config["sas_token"] = os.getenv("AZURE_SAS_TOKEN")
                elif os.getenv("AZURE_USE_MANAGED_IDENTITY"):
                    config["use_managed_identity"] = True

            logger.info("Connecting to Azure storage to check for backups...")
            destination = AzureBlobBackupDestination(config)

            # List available backups
            backups = destination.list_backups()
            if not backups:
                logger.info("No backups found in Azure storage")
                return False

            # Get latest backup
            latest = max(backups, key=lambda b: b.timestamp)
            logger.info(
                f"Found latest backup: {getattr(latest, 'filename', '')} from {latest.timestamp}"
            )

            # Download to a safe, configurable temp location
            try:
                from tacacs_server.backup.path_policy import (
                    join_safe_temp as _join_safe_temp,
                )

                temp_path = _join_safe_temp("restore_backup.tar.gz")
            except Exception:
                # Fallback conservatively to working directory if policy unavailable
                temp_path = Path("restore_backup.tar.gz").resolve()
            logger.info("Downloading backup from Azure...")
            # Use full remote path when available (includes base_path)
            remote_path = getattr(latest, "path", None) or latest.name
            ok = destination.download_backup(remote_path, str(temp_path))
            if not ok:
                logger.warning("Azure backup download failed")
                return False
            # If the destination fell back to its temp root, adjust the path
            src_path = temp_path
            if not src_path.exists():
                try:
                    from tacacs_server.backup.path_policy import get_temp_root

                    fallback = Path(get_temp_root()) / temp_path.name
                    if fallback.exists():
                        src_path = fallback
                except Exception as exc:
                    logger.warning("Failed to initialize radius server: %s", exc)

            # Restore backup
            logger.info("Restoring backup...")
            from tacacs_server.backup.archive_utils import extract_tarball

            # Extract to data directory
            data_dir = Path("/app/data")
            data_dir.mkdir(parents=True, exist_ok=True)
            extract_tarball(str(src_path), str(data_dir))

            # Cleanup
            try:
                temp_path.unlink(missing_ok=True)
            except Exception as exc:
                logger.warning("Failed to cleanup temp file: %s", exc)

            logger.info("✓ Backup restored successfully from Azure storage")
            self.backup_restored = True
            return True

        except Exception as e:
            logger.warning(f"Failed to restore from Azure backup: {e}", exc_info=True)
            return False

    def download_config_from_azure(self) -> str | None:
        """Download config file from Azure storage"""
        try:
            # Check if Azure libraries are available
            try:
                import azure.storage.blob  # noqa: F401
            except ImportError:
                logger.info(
                    "azure-storage-blob not installed, skipping Azure config download"
                )
                return None

            from tacacs_server.backup.destinations.azure import (
                AzureBlobBackupDestination,
            )

            config_filename = os.getenv("AZURE_CONFIG_FILE", "tacacs.conf")

            # Build Azure config from env vars
            config: dict[str, Any] = {
                "container_name": os.getenv("AZURE_STORAGE_CONTAINER"),
                "base_path": os.getenv("AZURE_CONFIG_PATH", "config"),
            }

            # Add auth config (same as backup)
            conn_str = os.getenv("AZURE_CONNECTION_STRING") or os.getenv(
                "AZURE_STORAGE_CONNECTION_STRING"
            )
            if conn_str:
                config["connection_string"] = conn_str
            else:
                config["account_name"] = os.getenv("AZURE_STORAGE_ACCOUNT")
                if os.getenv("AZURE_ACCOUNT_KEY"):
                    config["account_key"] = os.getenv("AZURE_ACCOUNT_KEY")
                elif os.getenv("AZURE_SAS_TOKEN"):
                    config["sas_token"] = os.getenv("AZURE_SAS_TOKEN")
                elif os.getenv("AZURE_USE_MANAGED_IDENTITY"):
                    config["use_managed_identity"] = True

            logger.info(
                f"Checking for config file '{config_filename}' in Azure storage..."
            )
            # Resolve target path
            config_path = Path("/app/config/tacacs.azure.ini")
            config_path.parent.mkdir(parents=True, exist_ok=True)

            base_prefix = str(config.get("base_path", "")).strip("/")
            remote_path = (
                f"{base_prefix}/{config_filename}" if base_prefix else config_filename
            )

            # Prefer direct SDK download when a connection string is available to
            # avoid path-policy side effects in destinations and improve reliability
            downloaded = False
            last_err: Exception | None = None
            if config.get("connection_string"):
                try:
                    from azure.storage.blob import BlobServiceClient

                    attempts = 30
                    delay = 1.0
                    for _ in range(attempts):
                        try:
                            bsc = BlobServiceClient.from_connection_string(
                                str(config["connection_string"]),
                                connection_timeout=int(config.get("timeout", 300)),
                            )
                            cc = bsc.get_container_client(str(config["container_name"]))
                            bc = cc.get_blob_client(remote_path)
                            data = bc.download_blob().readall()
                            # Write atomically to target path
                            tmp = config_path.with_suffix(".part")
                            with open(tmp, "wb") as fh:
                                fh.write(data)
                            tmp.replace(config_path)
                            downloaded = True
                            last_err = None
                            break
                        except Exception as e:  # noqa: BLE001
                            last_err = e
                            # Break early on clearly invalid connection strings
                            if isinstance(e, Exception) and "Connection string" in str(e):
                                break
                            time.sleep(delay)
                except Exception as e:  # noqa: BLE001
                    last_err = e

            # Fallback to destination helper if direct method not used or failed
            if not downloaded:
                destination = AzureBlobBackupDestination(config)
                attempts = 30
                delay = 1.0
                for _ in range(attempts):
                    try:
                        ok = destination.download_backup(remote_path, str(config_path))
                        if ok:
                            downloaded = True
                            last_err = None
                            break
                    except Exception as e:  # noqa: BLE001
                        last_err = e
                    time.sleep(delay)

                # If the destination fell back to its temp root, relocate file into /app/config
                if not downloaded or not config_path.exists():
                    try:
                        from tacacs_server.backup.path_policy import get_temp_root

                        fallback = Path(get_temp_root()) / config_path.name
                        if fallback.exists():
                            config_path.parent.mkdir(parents=True, exist_ok=True)
                            fallback.replace(config_path)
                            downloaded = True
                    except Exception as exc:
                        logger.warning("Failed to initialize radius server: %s", exc)

            if not downloaded or not config_path.exists():
                raise RuntimeError(
                    f"Azure config download failed: {last_err or 'unknown error'}"
                )

            logger.info(f"✓ Config file downloaded from Azure storage to {config_path}")
            self.config_downloaded = True
            return str(config_path)

        except Exception as e:
            logger.info(f"No config file in Azure storage or download failed: {e}")
            return None

    def validate_minimum_config(self) -> bool:
        """Validate that minimum required configuration is present"""
        # Check critical env vars
        required_env: list[str] = []

        # Add your minimum required env vars here
        # For example:
        # required_env = ['ADMIN_PASSWORD', 'SERVER_PORT']

        missing = [var for var in required_env if not os.getenv(var)]
        if missing:
            logger.error(
                f"Missing required environment variables: {', '.join(missing)}"
            )
            return False

        logger.info("Minimum configuration requirements met")
        return True

    def determine_config_path(self) -> str:
        """Determine which config file to use based on startup flow"""
        # Priority order:
        # 1. Downloaded from Azure (if available)
        # 2. Environment variable override
        # 3. Container default config
        # 4. Standard config location

        if self.config_downloaded:
            config_path = "/app/config/tacacs.azure.ini"
            if Path(config_path).exists():
                logger.info(f"Using Azure-downloaded config: {config_path}")
                return config_path

        env_config = os.getenv("TACACS_CONFIG")
        if env_config and Path(env_config).exists():
            logger.info(f"Using environment-specified config: {env_config}")
            return env_config

        container_config = "/app/config/tacacs.container.ini"
        if Path(container_config).exists():
            logger.info(f"Using container default config: {container_config}")
            return container_config

        default_config = "config/tacacs.conf"
        logger.info(f"Using default config location: {default_config}")
        return default_config

    def run(self) -> str:
        """Execute startup orchestration and return config path to use"""
        logger.info("=" * 60)
        logger.info("TACACS+ Server Container Startup")
        logger.info("=" * 60)

        # Step 1: Check for Azure storage configuration
        self.azure_enabled = self.check_azure_env_vars()

        if self.azure_enabled:
            # Step 2: Try to restore from backup
            logger.info("\nAttempting backup restoration from Azure...")
            backup_success = self.restore_from_azure_backup()

            if not backup_success:
                # Step 3: If no backup, try to download config
                logger.info("\nAttempting config download from Azure...")
                self.download_config_from_azure()
        else:
            logger.info("\nAzure storage not configured, skipping cloud recovery")

        # Step 4: Validate minimum requirements
        logger.info("\nValidating minimum configuration...")
        if not self.validate_minimum_config():
            logger.error("Minimum configuration validation failed!")
            sys.exit(1)

        # Step 5: Determine config path to use
        config_path = self.determine_config_path()

        logger.info("\n" + "=" * 60)
        logger.info("Startup orchestration complete")
        logger.info(f"Backup restored: {self.backup_restored}")
        logger.info(f"Config downloaded: {self.config_downloaded}")
        logger.info(f"Using config: {config_path}")
        logger.info("=" * 60 + "\n")

        return config_path


def run_startup_orchestration() -> str:
    """Run startup orchestration and return config path"""
    orchestrator = StartupOrchestrator()
    return orchestrator.run()
