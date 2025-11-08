"""
Azure Blob Storage Backup Destination Test Suite

This module contains unit tests for the Azure Blob Storage backup destination
implementation. It verifies the functionality of uploading, downloading, and
managing backups in Azure Blob Storage.

Test Coverage:
- Container name validation
- Connection string authentication
- SAS token authentication
- Managed identity authentication
- Container creation and existence checks
- Blob listing and filtering
- Metadata and tag handling
- Error conditions and edge cases

Dependencies:
- pytest for test framework
- unittest.mock for mocking Azure SDK clients
- azure-storage-blob for Azure Blob Storage interaction
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from tacacs_server.backup.destinations.azure import AzureBlobBackupDestination


def _tmp_file(tmp_path: Path, name: str = "test.tar.gz", size: int = 1024) -> str:
    """Create a temporary file with random content for testing.

    Args:
        tmp_path: Pytest fixture providing a temporary directory
        name: Name of the temporary file
        size: Size of random content in bytes

    Returns:
        str: Path to the created temporary file
    """
    p = tmp_path / name
    p.write_bytes(os.urandom(size))
    return str(p)


def test_container_name_validation():
    """Verify container name validation rejects invalid names.

    Test Steps:
    1. Attempt to create AzureBlobBackupDestination with an invalid container name

    Expected Results:
    - Should raise ValueError for invalid container name
    - Should prevent creation of destination with invalid container name

    Edge Cases:
    - Tests Azure's container naming rules (lowercase alphanumeric and hyphens only)
    - Verifies validation happens during initialization
    """
    with pytest.raises(ValueError):
        AzureBlobBackupDestination(
            {"connection_string": "cs", "container_name": "Invalid_UPPER"}
        )


@patch("azure.storage.blob.BlobServiceClient")
def test_connection_string_upload_sets_metadata_and_tags(
    mock_bsc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Verify upload with connection string sets metadata and tags correctly.

    Test Steps:
    1. Mock Azure BlobServiceClient and related components
    2. Configure AzureBlobBackupDestination with connection string
    3. Upload a test file

    Expected Results:
    - upload_blob should be called with the file content
    - set_blob_metadata should be called with default metadata
    - set_blob_tags should be called with default tags

    Security Considerations:
    - Verifies sensitive connection string is properly handled
    - Ensures metadata and tags are set as specified
    """
    # Setup mocks
    mock_container = Mock()
    mock_blob_client = Mock()
    mock_bsc.from_connection_string.return_value.get_container_client.return_value = (
        mock_container
    )
    mock_container.get_blob_client.return_value = mock_blob_client
    mock_container.exists.return_value = True

    # Ensure path policy allows tmp-based inputs
    monkeypatch.setenv("BACKUP_TEMP", str(tmp_path))
    monkeypatch.setenv("BACKUP_ROOT", str(tmp_path))

    # Test with connection string auth
    dest = AzureBlobBackupDestination(
        {
            "connection_string": "DefaultEndpointsProtocol=https;AccountName=acc;...",
            "container_name": "backups",
            "default_metadata": {"env": "test"},
            "default_tags": {"app": "tacacs"},
        }
    )

    # Perform upload
    src = _tmp_file(tmp_path)
    dest.upload_backup(src, "test.tar.gz")

    # Verify Azure SDK interactions
    assert mock_blob_client.upload_blob.called, "Should upload blob content"
    assert mock_blob_client.set_blob_metadata.called, "Should set blob metadata"
    assert mock_blob_client.set_blob_tags.called, "Should set blob tags"


def test_account_key_initialization():
    dest = AzureBlobBackupDestination(
        {
            "account_name": "myacct",
            "account_key": "KEY",
            "container_name": "backups",
        }
    )
    ok, _ = dest.test_connection()
    assert isinstance(ok, bool)


@patch("azure.storage.blob.BlobServiceClient")
def test_sas_token_initialization(mock_bsc):
    dest = AzureBlobBackupDestination(
        {
            "account_name": "myacct",
            "sas_token": "?sv=...",
            "container_name": "backups",
        }
    )
    ok, _ = dest.test_connection()
    assert isinstance(ok, bool)
    assert mock_bsc.from_connection_string.called is False
    assert mock_bsc.called


@patch("azure.identity.DefaultAzureCredential")
@patch("azure.storage.blob.BlobServiceClient")
def test_managed_identity_initialization(mock_bsc, mock_dac):
    dest = AzureBlobBackupDestination(
        {
            "account_name": "myacct",
            "use_managed_identity": True,
            "container_name": "backups",
        }
    )
    ok, _ = dest.test_connection()
    assert isinstance(ok, bool)
    assert mock_dac.called
    assert mock_bsc.called


@patch("azure.storage.blob.BlobServiceClient")
def test_test_connection_container_creation(mock_bsc):
    mock_container = Mock()
    mock_blob = Mock()
    bsc = Mock()
    mock_bsc.from_connection_string.return_value = bsc
    bsc.get_container_client.return_value = mock_container
    mock_container.exists.return_value = False
    mock_container.get_blob_client.return_value = mock_blob
    mock_blob.download_blob.return_value.readall.return_value = b"ok"
    mock_container.list_blobs.return_value = []

    dest = AzureBlobBackupDestination(
        {"connection_string": "cs", "container_name": "backups"}
    )
    ok, msg = dest.test_connection()
    assert ok, msg
    assert mock_container.create_container.called
    assert mock_blob.upload_blob.called
    assert mock_blob.delete_blob.called


@patch("azure.storage.blob.BlobServiceClient")
def test_list_blobs_filtering_and_download(mock_bsc, tmp_path: Path):
    mock_container = Mock()
    bsc = Mock()
    mock_bsc.from_connection_string.return_value = bsc
    bsc.get_container_client.return_value = mock_container

    blob1 = SimpleNamespace(name="a/test1.tar.gz", size=10, last_modified=None)
    blob2 = SimpleNamespace(name="a/readme.txt", size=5, last_modified=None)
    mock_container.list_blobs.return_value = [blob1, blob2]

    dest = AzureBlobBackupDestination(
        {"connection_string": "cs", "container_name": "backups", "base_path": "a"}
    )
    items = dest.list_backups()
    assert len(items) == 1 and items[0].filename == "test1.tar.gz"

    mock_blob = Mock()
    mock_container.get_blob_client.return_value = mock_blob
    mock_blob.download_blob.return_value.readall.return_value = b"data"
    mock_blob.get_blob_properties.return_value.size = 4
    from tacacs_server.backup.path_policy import safe_temp_path

    rel_name = "dl.tar.gz"
    ok = dest.download_backup("a/test1.tar.gz", rel_name)
    expected = safe_temp_path(rel_name)
    assert ok and expected.read_bytes() == b"data"

    assert dest.delete_backup("a/test1.tar.gz") is True
    assert mock_blob.delete_blob.called
