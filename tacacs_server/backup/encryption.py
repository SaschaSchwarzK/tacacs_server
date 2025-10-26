from __future__ import annotations

import base64
import os
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key_from_passphrase(passphrase: str, salt: bytes | None = None) -> Tuple[bytes, bytes]:
    """
    Derive encryption key from passphrase using PBKDF2 (SHA256).
    Returns (key, salt). Generates 16-byte salt when not provided.
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
    return key, salt


def encrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """Encrypt file using Fernet (symmetric AES-128 in CBC with HMAC)."""
    key, salt = derive_key_from_passphrase(passphrase)
    fernet = Fernet(key)
    with open(input_path, "rb") as f:
        plaintext = f.read()
    ciphertext = fernet.encrypt(plaintext)
    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(ciphertext)


def decrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """Decrypt file previously encrypted with encrypt_file."""
    with open(input_path, "rb") as f:
        salt = f.read(16)
        ciphertext = f.read()
    key, _ = derive_key_from_passphrase(passphrase, salt)
    fernet = Fernet(key)
    plaintext = fernet.decrypt(ciphertext)
    with open(output_path, "wb") as f:
        f.write(plaintext)

