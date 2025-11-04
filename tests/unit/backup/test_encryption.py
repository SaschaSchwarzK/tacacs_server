from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from tacacs_server.backup.encryption import BackupEncryption


def test_key_derivation_same_passphrase_same_salt():
    salt = os.urandom(16)
    k1, s1 = BackupEncryption.derive_key_from_passphrase("secret-pass", salt)
    k2, s2 = BackupEncryption.derive_key_from_passphrase("secret-pass", salt)
    assert k1 == k2
    assert s1 == s2 == salt
    # Fernet keys are base64 urlsafe encoding of 32 bytes
    raw = base64.urlsafe_b64decode(k1)
    assert len(raw) == 32


def test_key_derivation_different_salt_different_key():
    k1, _ = BackupEncryption.derive_key_from_passphrase("secret-pass", os.urandom(16))
    k2, _ = BackupEncryption.derive_key_from_passphrase("secret-pass", os.urandom(16))
    assert k1 != k2


def test_encrypt_creates_file_and_header(tmp_path: Path):
    src = tmp_path / "data.bin"
    data = b"hello encryption" * 5
    src.write_bytes(data)
    dst = tmp_path / "data.bin.enc"
    info = BackupEncryption.encrypt_file(str(src), str(dst), "StrongPassphrase!123")
    assert dst.exists()
    # Header: TCBK + version(1) + 16-byte salt
    blob = dst.read_bytes()
    assert blob[:4] == b"TCBK"
    assert blob[4] == 1
    assert len(blob) > 4 + 1 + 16
    assert isinstance(info["salt_hex"], str) and len(info["salt_hex"]) == 32
    assert info["original_size"] == src.stat().st_size
    assert info["encrypted_size"] == dst.stat().st_size
    assert info["algorithm"]


def test_decrypt_success_and_wrong_passphrase(tmp_path: Path):
    src = tmp_path / "plain.txt"
    src.write_text("top secret!", encoding="utf-8")
    enc = tmp_path / "plain.txt.enc"
    dec = tmp_path / "out.txt"
    BackupEncryption.encrypt_file(str(src), str(enc), "Pass-12345-!@#")
    ok = BackupEncryption.decrypt_file(str(enc), str(dec), "Pass-12345-!@#")
    assert ok and dec.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")
    # Wrong passphrase fails gracefully
    dec2 = tmp_path / "out2.txt"
    ok2 = BackupEncryption.decrypt_file(str(enc), str(dec2), "bad-pass")
    assert ok2 is False


def test_corrupted_encrypted_file_detection(tmp_path: Path):
    enc = tmp_path / "bad.enc"
    # Write bad header
    enc.write_bytes(b"TCBK" + bytes([1]) + b"\x00" * 15 + b"corrupted")
    dec = tmp_path / "dec"
    ok = BackupEncryption.decrypt_file(str(enc), str(dec), "any")
    assert ok is False


@pytest.mark.parametrize("size", [0, 1, 1024, 1024 * 64])
def test_round_trip_various_sizes(tmp_path: Path, size: int):
    src = tmp_path / f"data_{size}.bin"
    src.write_bytes(os.urandom(size))
    enc = tmp_path / f"data_{size}.bin.enc"
    dec = tmp_path / f"data_{size}.bin.out"
    info = BackupEncryption.encrypt_file(str(src), str(enc), "SuperSecret!123456")
    assert enc.exists()
    assert info["encrypted_size"] > 0
    ok = BackupEncryption.decrypt_file(str(enc), str(dec), "SuperSecret!123456")
    assert ok and dec.read_bytes() == src.read_bytes()


def test_verify_passphrase(tmp_path: Path):
    src = tmp_path / "x.bin"
    src.write_bytes(b"abc" * 100)
    enc = tmp_path / "x.bin.enc"
    BackupEncryption.encrypt_file(str(src), str(enc), "P@ssphrase-XYZ")
    assert BackupEncryption.verify_passphrase(str(enc), "P@ssphrase-XYZ") is True
    assert BackupEncryption.verify_passphrase(str(enc), "wrong") is False
