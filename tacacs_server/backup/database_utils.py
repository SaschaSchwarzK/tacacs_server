from __future__ import annotations

import os
import shutil
import sqlite3
import time
from datetime import UTC, datetime
from typing import Dict, Tuple


def export_database(source_path: str, dest_path: str) -> None:
    """
    Safely export SQLite database using the backup API with retries.
    Falls back to file copy if backup fails, then verifies integrity.
    """
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)

    # Attempt backup API with simple retry loop to tolerate transient locks
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            with sqlite3.connect(source_path, check_same_thread=False, timeout=30.0) as src,
                sqlite3.connect(dest_path, check_same_thread=False, timeout=30.0) as dst:
                # Configure busy timeout to wait on locks
                try:
                    src.execute("PRAGMA busy_timeout = 30000")
                    dst.execute("PRAGMA busy_timeout = 30000")
                except Exception:
                    pass
                src.backup(dst)
            last_err = None
            break
        except Exception as exc:  # pragma: no cover - exercised in integration
            last_err = exc
            time.sleep(0.2 * (attempt + 1))

    if last_err is not None:
        # Fallback to file-level copy as a best-effort
        shutil.copy2(source_path, dest_path)

    ok, msg = verify_database_integrity(dest_path)
    if not ok:
        raise RuntimeError(f"Exported DB failed integrity check: {msg}")


def export_database_with_retry(source_path: str, dest_path: str, max_retries: int = 3) -> None:
    """Export with retry on lock contention (OperationalError: locked)."""
    attempt = 0
    while True:
        try:
            export_database(source_path, dest_path)
            return
        except sqlite3.OperationalError as e:
            locked = "locked" in str(e).lower()
            if locked and attempt < max_retries - 1:
                time.sleep(1 * (attempt + 1))
                attempt += 1
                continue
            raise


def import_database(source_path: str, dest_path: str, verify: bool = True) -> None:
    """
    Import database with verification and atomic replace.
    Creates timestamped backup of existing destination before overwriting.
    """
    if verify:
        ok, msg = verify_database_integrity(source_path)
        if not ok:
            raise ValueError(f"Source DB integrity failed: {msg}")

    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)

    # Backup existing destination if present
    if os.path.exists(dest_path):
        ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        backup_path = f"{dest_path}.bak.{ts}"
        try:
            shutil.copy2(dest_path, backup_path)
        except Exception:
            # Non-fatal; continue with import
            pass

    # Atomic replace
    tmp = dest_path + ".import.tmp"
    shutil.copy2(source_path, tmp)
    os.replace(tmp, dest_path)

    if verify:
        ok, msg = verify_database_integrity(dest_path)
        if not ok:
            raise RuntimeError(f"Imported DB failed integrity: {msg}")


def verify_database_integrity(db_path: str) -> Tuple[bool, str]:
    """Comprehensive database verification: existence, integrity, FKs, readability."""
    if not os.path.exists(db_path):
        return False, "Database file does not exist"

    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.cursor()

            # Basic integrity
            cur.execute("PRAGMA integrity_check")
            row = cur.fetchone()
            if not row:
                return False, "No result from integrity_check"
            result = str(row[0])
            if result.lower() != "ok":
                return False, f"Integrity check failed: {result}"

            # Foreign key check
            try:
                cur.execute("PRAGMA foreign_key_check")
                fk_errors = cur.fetchall()
                if fk_errors:
                    return False, f"Foreign key violations: {len(fk_errors)}"
            except Exception:
                # Ignore if pragma not supported
                pass

            # Read all tables (ensure basic readability)
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            for tbl in tables:
                try:
                    cur.execute(f"SELECT COUNT(*) FROM '{tbl}'")
                    _ = cur.fetchone()
                except Exception as exc:
                    return False, f"Failed to read table {tbl}: {exc}"

        return True, "Database verified successfully"
    except Exception as e:  # pragma: no cover - error path
        return False, f"Verification failed: {str(e)}"


def count_database_records(db_path: str) -> Dict[str, int]:
    """
    Count rows for all tables in the SQLite database.
    Returns mapping of table_name -> row_count.
    """
    counts: Dict[str, int] = {}
    try:
        with sqlite3.connect(db_path) as conn:
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            for (table_name,) in cur.fetchall():
                try:
                    cur2 = conn.execute(f"SELECT COUNT(*) FROM '{table_name}'")
                    counts[table_name] = int(cur2.fetchone()[0] or 0)
                except Exception:
                    counts[table_name] = 0
    except Exception:
        # Return what we have (possibly empty) on failure
        pass
    return counts
