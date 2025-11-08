"""
Security test suite for path_policy.py fixes.

This test suite demonstrates that the fixed version properly rejects
malicious path inputs that could lead to path traversal attacks.
"""

import tempfile
from pathlib import Path

import pytest


# Mock the BackupDestination import for testing
class MockBackupDestination:
    @staticmethod
    def validate_path_segment(
        name: str, *, allow_dot: bool = True, max_len: int = 128
    ) -> str:
        import re

        s = str(name)
        if not s or len(s) > max_len:
            raise ValueError("Invalid name length")
        if "/" in s or "\\" in s or "\x00" in s:
            raise ValueError("Invalid characters in name")
        if s in (".", ".."):
            raise ValueError("Dot-only segments are not allowed")
        pattern = r"^[A-Za-z0-9._-]+$" if allow_dot else r"^[A-Za-z0-9_-]+$"
        if not re.fullmatch(pattern, s):
            raise ValueError("Name contains disallowed characters")
        return s

    @staticmethod
    def validate_relative_path(path: str, *, max_segments: int = 10) -> str:
        s = str(path or "").strip()
        if not s:
            raise ValueError("Empty path")
        if s.startswith("/"):
            raise ValueError("Absolute paths are not allowed")
        if "\\" in s or "\x00" in s:
            raise ValueError("Invalid characters in path")
        parts = [p for p in s.split("/")]
        if not parts or len(parts) > max_segments:
            raise ValueError("Invalid number of path segments")
        cleaned = []
        for i, seg in enumerate(parts):
            if not seg:
                raise ValueError("Empty path segment")
            if seg in (".", ".."):
                raise ValueError("Dot segments are not allowed")
            allow_dot = i == (len(parts) - 1)
            cleaned.append(
                MockBackupDestination.validate_path_segment(seg, allow_dot=allow_dot)
            )
        return "/".join(cleaned)


class TestPathInjectionPrevention:
    """Tests that demonstrate the fixed code properly prevents path injection attacks."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        """Setup test environment and mock imports."""
        # Set test mode
        monkeypatch.setenv("PYTEST_CURRENT_TEST", "test")

        short_root = Path(tempfile.mkdtemp(prefix="tacacs-test-root-"))
        monkeypatch.setenv("BACKUP_ROOT", str(short_root))
        import tacacs_server.backup.path_policy as _pp

        if short_root.resolve() not in _pp.ALLOWED_ROOTS:
            _pp.ALLOWED_ROOTS.append(short_root.resolve())

        # Mock the BackupDestination import
        import sys
        from unittest.mock import MagicMock

        mock_module = MagicMock()
        mock_module.BackupDestination = MockBackupDestination
        sys.modules["tacacs_server.backup.destinations.base"] = mock_module

    def test_environment_variable_injection_prevented(self, monkeypatch, tmp_path):
        """Test that malicious environment variables are rejected."""
        from tacacs_server.backup.path_policy import get_backup_root

        # Try to inject a path traversal via environment variable
        malicious_paths = [
            "../../../etc/passwd",
            "/tmp/../etc",
            "~/.ssh",
            "$(whoami)",
            "`ls`",
            "/tmp;rm -rf /",
        ]

        for malicious in malicious_paths:
            monkeypatch.setenv("BACKUP_ROOT", malicious)
            with pytest.raises(ValueError):
                get_backup_root()

    def test_null_byte_injection_prevented(self):
        """Test that null bytes in paths are rejected."""
        from tacacs_server.backup.path_policy import (
            safe_input_file,
            validate_allowed_root,
            validate_base_directory,
        )

        null_byte_paths = [
            "/tmp/test\x00/etc/passwd",
            "/data\x00",
            "backup\x00.tar.gz",
        ]

        for path in null_byte_paths:
            with pytest.raises(ValueError):
                validate_allowed_root(path)

            with pytest.raises(ValueError):
                validate_base_directory(path)

            with pytest.raises(ValueError):
                safe_input_file(path)

    def test_parent_directory_traversal_prevented(self, tmp_path):
        """Test that parent directory traversal attempts are rejected."""
        from tacacs_server.backup.path_policy import validate_relpath

        traversal_attempts = [
            "../etc/passwd",
            "foo/../../etc",
            "backup/../../../root",
            ".",
            "..",
            "./.",
            "./../",
        ]

        for attempt in traversal_attempts:
            with pytest.raises(
                ValueError,
                match="contains potentially dangerous pattern|Dot segments are not allowed|Empty path",
            ):
                validate_relpath(attempt)

    def test_absolute_path_in_relative_context_prevented(self):
        """Test that absolute paths are rejected when relative paths are expected."""
        from tacacs_server.backup.path_policy import validate_relpath

        absolute_paths = [
            "/etc/passwd",
            "/tmp/test",
            "/var/run/test",
        ]

        for path in absolute_paths:
            with pytest.raises(ValueError, match="Absolute paths are not allowed"):
                validate_relpath(path)

    def test_relative_path_in_absolute_context_prevented(self, tmp_path):
        """Test that relative paths are rejected when absolute paths are expected."""
        from tacacs_server.backup.path_policy import (
            validate_allowed_root,
            validate_base_directory,
        )

        relative_paths = [
            "tmp/test",
            "data/backups",
            "etc/passwd",
        ]

        for path in relative_paths:
            with pytest.raises(ValueError, match="must be an absolute path"):
                validate_allowed_root(path)

            with pytest.raises(ValueError, match="must be an absolute path"):
                validate_base_directory(path)

    def test_command_injection_patterns_prevented(self):
        """Test that command injection patterns are rejected."""
        from tacacs_server.backup.path_policy import _sanitize_path_input

        injection_attempts = [
            "test`whoami`.txt",
            "backup$(id).tar",
            "$PATH/data",
        ]

        for attempt in injection_attempts:
            with pytest.raises(ValueError):
                _sanitize_path_input(attempt)

    def test_home_directory_expansion_prevented(self):
        """Test that home directory expansion attempts are rejected."""
        from tacacs_server.backup.path_policy import _sanitize_path_input

        home_attempts = [
            "~/passwd",
            "~root/.ssh",
            "backup~user",
        ]

        for attempt in home_attempts:
            with pytest.raises(ValueError):
                _sanitize_path_input(attempt)

    def test_variable_expansion_prevented(self):
        """Test that variable expansion attempts are rejected."""
        from tacacs_server.backup.path_policy import _sanitize_path_input

        var_attempts = [
            "$HOME/test",
            "${USER}/data",
            "$PATH",
        ]

        for attempt in var_attempts:
            with pytest.raises(ValueError):
                _sanitize_path_input(attempt)

    def test_path_length_limits_enforced(self):
        """Test that path length limits are enforced."""
        from tacacs_server.backup.path_policy import validate_path_segment

        # Create a segment longer than the maximum
        long_seg = "a" * 260
        with pytest.raises(ValueError):
            validate_path_segment(long_seg, max_len=128)

    def test_symlink_rejection(self, tmp_path):
        """Test that symlinks in paths are rejected."""
        from tacacs_server.backup.path_policy import safe_input_file

        # Create a symlink
        real_dir = tmp_path / "real"
        real_dir.mkdir()

        symlink = tmp_path / "link"
        symlink.symlink_to(real_dir)

        # Try to resolve a path through the symlink
        target = symlink / "test"
        # Depending on policy, symlink inputs may be rejected
        with pytest.raises(ValueError):
            safe_input_file(str(target))

    def test_root_directory_prevented(self):
        """Test that the root directory is rejected as a base."""
        from tacacs_server.backup.path_policy import (
            validate_allowed_root,
        )

        with pytest.raises(ValueError):
            validate_allowed_root("/")

    def test_containment_enforcement(self, tmp_path, monkeypatch):
        """Test that paths are enforced to stay within their allowed boundaries."""
        from tacacs_server.backup.path_policy import (
            safe_local_output,
        )

        # Set up a specific backup root
        backup_root = tmp_path / "backups"
        backup_root.mkdir()
        monkeypatch.setenv("BACKUP_ROOT", str(backup_root))

        # Try to create a path outside the backup root
        outside_root = tmp_path / "outside"
        outside_root.mkdir()

        # In test mode, containment is relaxed, but we can still test the validation logic
        # by trying to validate a base directory outside the configured root

        # Use safeLocalOutput to construct a path under backup root
        valid_rel = "valid/file.txt"
        result = safe_local_output(valid_rel)
        assert str(result).startswith(str(backup_root))

    def test_safe_path_construction(self, tmp_path, monkeypatch):
        """Test that safe path construction functions work correctly with valid inputs."""
        from tacacs_server.backup.path_policy import (
            join_safe_backup,
            join_safe_temp,
            safe_local_output,
            safe_temp_path,
        )

        # Set up test roots
        backup_root = tmp_path / "backups"
        temp_root = tmp_path / "temp"
        backup_root.mkdir()
        temp_root.mkdir()

        monkeypatch.setenv("BACKUP_ROOT", str(backup_root))
        monkeypatch.setenv("BACKUP_TEMP", str(temp_root))

        # Test safe construction with valid inputs
        valid_relative = "2024/11/backup.tar.gz"

        backup_path = safe_local_output(valid_relative)
        assert backup_path.is_relative_to(backup_root)

        temp_path = safe_temp_path(valid_relative)
        assert temp_path.is_relative_to(temp_root)

        joined_backup = join_safe_backup("2024", "11", "backup.tar.gz")
        assert joined_backup.is_relative_to(backup_root)

        joined_temp = join_safe_temp("tmp", "processing", "data.tmp")
        assert joined_temp.is_relative_to(temp_root)

    def test_validation_order_enforced(self, tmp_path):
        """Test that validation happens before Path operations."""
        from tacacs_server.backup.path_policy import _sanitize_path_input as _spi

        # This tests that we validate strings before converting to Path
        # The old code would do Path(input) then validate
        # The new code validates the string first

        malicious = "../../../etc/passwd"

        # Should fail during string validation, not during Path operations
        with pytest.raises(ValueError):
            _spi(malicious)


class TestSecurityImprovedBehavior:
    """Tests that demonstrate improved security behavior."""

    @pytest.fixture(autouse=True)
    def setup(self, monkeypatch):
        """Setup test environment."""
        monkeypatch.setenv("PYTEST_CURRENT_TEST", "test")

        short_root = Path(tempfile.mkdtemp(prefix="tacacs-sec-root-"))
        short_root.mkdir(parents=True, exist_ok=True)
        self._test_root = short_root.resolve()
        monkeypatch.setenv("BACKUP_ROOT", str(self._test_root))

        # Mock the BackupDestination import
        import sys
        from unittest.mock import MagicMock

        mock_module = MagicMock()
        mock_module.BackupDestination = MockBackupDestination
        sys.modules["tacacs_server.backup.destinations.base"] = mock_module

    def test_empty_except_clauses_improved(self, tmp_path, monkeypatch):
        """Test that directory creation failures are handled properly."""
        # Create a read-only parent directory
        readonly_parent = tmp_path / "readonly"
        readonly_parent.mkdir()
        readonly_parent.chmod(0o444)

        target = readonly_parent / "subdir"

        # Should handle the error gracefully
        try:
            from tacacs_server.backup.path_policy import validate_base_directory

            with pytest.raises(ValueError):
                validate_base_directory(str(target))
        finally:
            # Cleanup
            readonly_parent.chmod(0o755)

    def test_type_safety(self):
        """Test that type validation is enforced."""
        from tacacs_server.backup.path_policy import _sanitize_path_input as _spi

        # Test that non-strings are rejected
        invalid_inputs = [
            123,
            None,
            ["path"],
            {"path": "value"},
        ]

        for invalid in invalid_inputs:
            with pytest.raises(Exception):
                _spi(invalid)  # type: ignore[arg-type]

    def test_defensive_programming(self, tmp_path, monkeypatch):
        """Test that the code uses defensive programming principles."""
        from tacacs_server.backup.path_policy import get_backup_root

        # Even with valid environment variables, the code should validate them
        valid_but_checked = str(tmp_path / "backup")
        monkeypatch.setenv("BACKUP_ROOT", valid_but_checked)

        # Should succeed and return a validated Path
        root = get_backup_root()
        assert isinstance(root, Path)
        assert root.is_absolute()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
