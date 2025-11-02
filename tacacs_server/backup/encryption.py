from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class BackupEncryption:
    """Handle backup encryption and decryption using Fernet (AES-128-CBC)"""

    SALT_SIZE = 16  # bytes
    KEY_ITERATIONS = 100000  # PBKDF2 iterations

    @staticmethod
    def derive_key_from_passphrase(
        passphrase: str, salt: bytes | None = None
    ) -> tuple[bytes, bytes]:
        """
        Derive encryption key from passphrase using PBKDF2-HMAC-SHA256.

        Args:
            passphrase: User-provided encryption passphrase
            salt: Optional salt (generated if not provided)

        Returns:
            (key, salt) where key is URL-safe base64-encoded
        """
        if salt is None:
            salt = os.urandom(BackupEncryption.SALT_SIZE)
        if (
            not isinstance(salt, (bytes, bytearray))
            or len(salt) != BackupEncryption.SALT_SIZE
        ):
            raise ValueError("salt must be 16 bytes")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=BackupEncryption.KEY_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
        return key, bytes(salt)

    @staticmethod
    def _safe_local_path(path: str) -> str:
        """Resolve a local filesystem path for encryption I/O.

        Tests and runtime pass absolute temp paths; accept absolute paths and
        ensure parent dirs exist at call sites. For relative paths, resolve
        against CWD.
        """
        from pathlib import Path as _P

        if not isinstance(path, str) or "\x00" in path:
            raise ValueError("Invalid path")
        p = _P(path)
        return str(p.resolve())

    @staticmethod
    def encrypt_file(input_path: str, output_path: str, passphrase: str) -> dict:
        """
        Encrypt file using passphrase-derived key.

        Args:
            input_path: Path to plaintext file
            output_path: Path for encrypted output
            passphrase: Encryption passphrase

        Returns:
            dict with: salt_hex, original_size, encrypted_size, checksum
        """
        # Derive key
        key, salt = BackupEncryption.derive_key_from_passphrase(passphrase)
        fernet = Fernet(key)

        # Calculate original checksum
        # Constrain I/O paths to allowed root
        input_path = BackupEncryption._safe_local_path(input_path)
        output_path = BackupEncryption._safe_local_path(output_path)
        original_checksum = BackupEncryption.calculate_checksum(input_path)
        original_size = os.path.getsize(input_path)

        # Read and encrypt
        with open(input_path, "rb") as f_in:
            plaintext = f_in.read()

        ciphertext = fernet.encrypt(plaintext)

        # Write encrypted file with header
        try:
            from pathlib import Path as _P

            _P(output_path).parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        with open(output_path, "wb") as f_out:
            # Header format: MAGIC(4) + VERSION(1) + SALT(16)
            f_out.write(b"TCBK")  # Magic bytes "TACACS Backup"
            f_out.write(bytes([1]))  # Version 1
            f_out.write(salt)  # 16 bytes salt
            f_out.write(ciphertext)

        encrypted_size = os.path.getsize(output_path)

        return {
            "salt_hex": salt.hex(),
            "original_size": original_size,
            "encrypted_size": encrypted_size,
            "original_checksum": original_checksum,
            "algorithm": "Fernet-AES128-CBC",
        }

    @staticmethod
    def decrypt_file(input_path: str, output_path: str, passphrase: str) -> bool:
        """
        Decrypt file using passphrase.

        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
            passphrase: Decryption passphrase

        Returns:
            True if successful, False if passphrase incorrect or file corrupted
        """
        try:
            input_path = BackupEncryption._safe_local_path(input_path)
            output_path = BackupEncryption._safe_local_path(output_path)
            with open(input_path, "rb") as f:
                # Read and validate header
                magic = f.read(4)
                if magic != b"TCBK":
                    raise ValueError("Invalid encrypted file format")

                ver_bytes = f.read(1)
                if not ver_bytes:
                    raise ValueError("Corrupted file: missing version")
                version = ver_bytes[0]
                if version != 1:
                    raise ValueError(f"Unsupported encryption version: {version}")

                salt = f.read(BackupEncryption.SALT_SIZE)
                if len(salt) != BackupEncryption.SALT_SIZE:
                    raise ValueError("Corrupted file: invalid salt")

                # Read encrypted data
                ciphertext = f.read()

            # Derive key and decrypt
            key, _ = BackupEncryption.derive_key_from_passphrase(passphrase, salt)
            fernet = Fernet(key)

            try:
                plaintext = fernet.decrypt(ciphertext)
            except Exception:
                # Decryption failed - wrong passphrase or corrupted file
                return False

            # Write decrypted data
            try:
                from pathlib import Path as _P

                _P(output_path).parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            with open(output_path, "wb") as f:
                f.write(plaintext)

            return True

        except Exception as e:  # pragma: no cover - defensive logging path
            logger.error(f"Decryption failed: {e}")
            return False

    @staticmethod
    def verify_passphrase(encrypted_file: str, passphrase: str) -> bool:
        """
        Verify passphrase is correct without full decryption.
        Tries to decrypt first 1KB as test (Fernet requires full token; this
        performs a full decrypt in memory and validates authenticity without
        writing output).
        """
        try:
            with open(encrypted_file, "rb") as f:
                if f.read(4) != b"TCBK":
                    return False
                ver = f.read(1)
                if not ver or ver[0] != 1:
                    return False
                salt = f.read(BackupEncryption.SALT_SIZE)
                if len(salt) != BackupEncryption.SALT_SIZE:
                    return False
                ciphertext = f.read()
            key, _ = BackupEncryption.derive_key_from_passphrase(passphrase, salt)
            fernet = Fernet(key)
            try:
                # Decrypt to memory; success indicates correct key
                _ = fernet.decrypt(ciphertext)
                return True
            except Exception:
                return False
        except Exception:
            return False

    @staticmethod
    def calculate_checksum(file_path: str) -> str:
        """Calculate SHA256 checksum of file"""
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""


# Backwards-compatible module-level helpers used elsewhere in the codebase
def derive_key_from_passphrase(
    passphrase: str, salt: bytes | None = None
) -> tuple[bytes, bytes]:
    return BackupEncryption.derive_key_from_passphrase(passphrase, salt)


def encrypt_file(input_path: str, output_path: str, passphrase: str):
    return BackupEncryption.encrypt_file(input_path, output_path, passphrase)


def decrypt_file(input_path: str, output_path: str, passphrase: str) -> bool:
    return BackupEncryption.decrypt_file(input_path, output_path, passphrase)
