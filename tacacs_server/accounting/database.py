"""
Simple SQLite accounting database logger for TACACS+ server.
"""

import queue
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from typing import Any

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


class DatabasePool:
    """Connection pool for SQLite database"""

    def __init__(self, db_path: str, pool_size: int = 5):
        self.db_path = db_path
        self.pool = queue.Queue(pool_size)
        self._lock = threading.Lock()

        # Ensure directory exists
        db_file = Path(db_path)
        if not db_file.parent.exists():
            db_file.parent.mkdir(parents=True, exist_ok=True)

        # Initialize pool with connections
        for _ in range(pool_size):
            conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA temp_store = MEMORY;")
            conn.execute("PRAGMA cache_size = -2000;")
            self.pool.put(conn)

    @contextmanager
    def get_connection(self):
        """Get database connection from pool"""
        conn = self.pool.get()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.put(conn)

    def close_all(self):
        """Close all connections in pool"""
        with self._lock:
            while not self.pool.empty():
                try:
                    conn = self.pool.get_nowait()
                    conn.close()
                except queue.Empty:
                    break


class DatabaseLogger:
    RECENT_WINDOW_DAYS = 30
    STATS_CACHE_TTL_SECONDS = 60

    def __init__(
        self, db_path: str = "data/tacacs_accounting.db", maintain_mv: bool = True
    ):
        self.db_path = db_path
        self.conn: sqlite3.Connection | None = None
        self.pool: DatabasePool | None = None
        self._stats_cache: dict[int, tuple[float, dict[str, Any]]] = {}
        self.maintain_mv = maintain_mv

        try:
            # Resolve and validate path to prevent path traversal
            db_file = Path(self.db_path).resolve()
            # Ensure path is within expected directory structure
            if not str(db_file).startswith(str(Path.cwd().resolve())):
                raise ValueError(f"Database path outside allowed directory: {db_file}")
            if not db_file.parent.exists():
                db_file.parent.mkdir(parents=True, exist_ok=True)

            self.conn = sqlite3.connect(
                str(db_file), timeout=10, check_same_thread=False
            )
            # Enable foreign keys
            self.conn.execute("PRAGMA foreign_keys = ON;")
            self.conn.execute("PRAGMA journal_mode = WAL;")
            self.conn.execute("PRAGMA synchronous = NORMAL;")
            self.conn.execute("PRAGMA temp_store = MEMORY;")
            self.conn.execute("PRAGMA cache_size = -2000;")
            self._initialize_schema()

            # ADD THIS LINE AFTER SUCCESSFUL INITIALIZATION:
            self.pool = DatabasePool(str(db_file))

        except Exception as e:
            logger.exception("Failed to initialize database: %s", e)
            if self.conn:
                try:
                    self.conn.close()
                except Exception:
                    pass
            self.conn = None
            self.pool = None  # type: ignore[assignment]
            self._stats_cache = {}

    def _now_utc_iso(self) -> str:
        """Return current UTC timestamp as ISO string."""
        return datetime.now(UTC).isoformat()

    def _compute_is_recent(self, timestamp_str: str | None) -> int:
        """Determine if timestamp falls within the recent statistics window."""
        if not timestamp_str:
            return 1
        try:
            ts = datetime.fromisoformat(timestamp_str)
        except ValueError:
            return 0
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        cutoff = datetime.now(UTC) - timedelta(days=self.RECENT_WINDOW_DAYS)
        return 1 if ts >= cutoff else 0

    def _invalidate_stats_cache(self):
        """Flush cached statistics."""
        self._stats_cache.clear()

    def _invalidate_stats_cache_for_timestamp(self, timestamp_str: str | None):
        if not self._stats_cache:
            return
        if not timestamp_str:
            logger.debug("Statistics cache cleared (no timestamp provided)")
            self._invalidate_stats_cache()
            return
        try:
            ts = datetime.fromisoformat(timestamp_str)
        except ValueError:
            logger.debug(
                "Statistics cache cleared due to unparsable timestamp: %s",
                timestamp_str,
            )
            self._invalidate_stats_cache()
            return
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        now_utc = datetime.now(UTC)
        trimmed_any = False
        for days in list(self._stats_cache.keys()):
            cutoff = now_utc - timedelta(days=days)
            if ts >= cutoff:
                self._stats_cache.pop(days, None)
                trimmed_any = True
        if trimmed_any:
            logger.debug("Statistics cache pruned for timestamp %s", timestamp_str)

    def _get_cached_stats(self, days: int) -> dict[str, Any] | None:
        entry = self._stats_cache.get(days)
        if not entry:
            return None
        expires_at, payload = entry
        if monotonic() >= expires_at:
            self._stats_cache.pop(days, None)
            return None
        return dict(payload)

    def _set_cached_stats(self, days: int, payload: dict[str, Any]):
        self._stats_cache[days] = (
            monotonic() + self.STATS_CACHE_TTL_SECONDS,
            dict(payload),
        )

    def _initialize_schema(self):
        """Create tables and indexes in a SQLite-compatible way."""
        try:
            cur = self.conn.cursor()
            # Create accounting table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS accounting (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    username TEXT,
                    acct_type TEXT,
                    start_time INTEGER,
                    stop_time INTEGER,
                    bytes_in INTEGER,
                    bytes_out INTEGER,
                    attributes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_accounting_session_id "
                "ON accounting(session_id);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_accounting_username "
                "ON accounting(username);"
            )

            # Active session tracking table used by pooled logger helpers
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS active_sessions (
                    session_id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    client_ip TEXT,
                    start_time TEXT NOT NULL,
                    last_update TEXT NOT NULL,
                    service TEXT,
                    port TEXT,
                    privilege_level INTEGER DEFAULT 1,
                    bytes_in INTEGER DEFAULT 0,
                    bytes_out INTEGER DEFAULT 0
                );
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_active_sessions_username "
                "ON active_sessions(username);"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_active_sessions_last_update "
                "ON active_sessions(last_update);"
            )

            # Primary logging table for aggregated statistics
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS accounting_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    username TEXT NOT NULL,
                    session_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    service TEXT,
                    command TEXT,
                    client_ip TEXT,
                    port TEXT,
                    start_time TEXT,
                    stop_time TEXT,
                    bytes_in INTEGER DEFAULT 0,
                    bytes_out INTEGER DEFAULT 0,
                    elapsed_time INTEGER DEFAULT 0,
                    privilege_level INTEGER DEFAULT 1,
                    authentication_method TEXT,
                    nas_port TEXT,
                    nas_port_type TEXT,
                    task_id TEXT,
                    timezone TEXT,
                    attributes TEXT,
                    is_recent INTEGER DEFAULT 0
                );
                """
            )
            for index_name in (
                "idx_accounting_logs_username",
                "idx_accounting_logs_timestamp",
                "idx_accounting_logs_session_id",
                "idx_username",
                "idx_timestamp",
                "idx_user_timestamp",
                "idx_user_stats",
                "idx_recent_logs",
                "idx_session_id",
            ):
                cur.execute(f"DROP INDEX IF EXISTS {index_name};")

            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_user_timestamp "
                "ON accounting_logs(username, timestamp DESC);"
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_recent_logs 
                ON accounting_logs(timestamp DESC, username, status)
                WHERE is_recent = 1;
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_session_id "
                "ON accounting_logs(session_id);"
            )

            if self.maintain_mv:
                # Aggregation tables and view used for fast statistics reads
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mv_daily_totals (
                        stat_date DATE PRIMARY KEY,
                        total_records INTEGER NOT NULL DEFAULT 0
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mv_daily_unique_users (
                        stat_date DATE NOT NULL,
                        username TEXT NOT NULL,
                        first_seen_ts DATETIME NOT NULL,
                        PRIMARY KEY (stat_date, username)
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE VIEW IF NOT EXISTS mv_daily_stats AS
                    SELECT 
                        t.stat_date,
                        t.total_records,
                        COALESCE(u.unique_users, 0) AS unique_users
                    FROM mv_daily_totals t
                    LEFT JOIN (
                        SELECT stat_date, COUNT(*) AS unique_users
                        FROM mv_daily_unique_users
                        GROUP BY stat_date
                    ) u USING (stat_date);
                    """
                )

                # Ensure triggers keep materialized statistics in sync
                for trigger_name in (
                    "trg_accounting_logs_insert_totals",
                    "trg_accounting_logs_delete_totals",
                    "trg_accounting_logs_update_date",
                    "trg_accounting_logs_update_username",
                ):
                    cur.execute(f"DROP TRIGGER IF EXISTS {trigger_name};")

                cur.execute(
                    """
                    CREATE TRIGGER trg_accounting_logs_insert_totals
                    AFTER INSERT ON accounting_logs
                    BEGIN
                        INSERT INTO mv_daily_totals(stat_date, total_records)
                        VALUES (date(NEW.timestamp), 1)
                        ON CONFLICT(stat_date)
                        DO UPDATE SET total_records = total_records + 1;

                        INSERT OR IGNORE INTO 
                        mv_daily_unique_users(stat_date, username, first_seen_ts)
                        VALUES (date(NEW.timestamp), NEW.username, NEW.timestamp);
                    END;
                    """
                )
                cur.execute(
                    """
                    CREATE TRIGGER trg_accounting_logs_delete_totals
                    AFTER DELETE ON accounting_logs
                    BEGIN
                        UPDATE mv_daily_totals
                        SET total_records = total_records - 1
                        WHERE stat_date = date(OLD.timestamp);

                        DELETE FROM mv_daily_totals
                        WHERE stat_date = date(OLD.timestamp)
                          AND total_records <= 0;

                        DELETE FROM mv_daily_unique_users
                        WHERE stat_date = date(OLD.timestamp)
                          AND username = OLD.username
                          AND NOT EXISTS (
                              SELECT 1 FROM accounting_logs
                              WHERE username = OLD.username
                                AND date(timestamp) = date(OLD.timestamp)
                          );
                    END;
                    """
                )
                cur.execute(
                    """
                    CREATE TRIGGER trg_accounting_logs_update_date
                    AFTER UPDATE ON accounting_logs
                    WHEN date(NEW.timestamp) <> date(OLD.timestamp)
                    BEGIN
                        UPDATE mv_daily_totals
                        SET total_records = total_records - 1
                        WHERE stat_date = date(OLD.timestamp);

                        DELETE FROM mv_daily_totals
                        WHERE stat_date = date(OLD.timestamp)
                          AND total_records <= 0;

                        DELETE FROM mv_daily_unique_users
                        WHERE stat_date = date(OLD.timestamp)
                          AND username = OLD.username
                          AND NOT EXISTS (
                              SELECT 1 FROM accounting_logs
                              WHERE username = OLD.username
                                AND date(timestamp) = date(OLD.timestamp)
                          );

                        INSERT INTO mv_daily_totals(stat_date, total_records)
                        VALUES (date(NEW.timestamp), 1)
                        ON CONFLICT(stat_date)
                        DO UPDATE SET total_records = total_records + 1;

                        INSERT OR IGNORE INTO 
                        mv_daily_unique_users(stat_date, username, first_seen_ts)
                        VALUES (date(NEW.timestamp), NEW.username, NEW.timestamp);
                    END;
                    """
                )
                cur.execute(
                    """
                    CREATE TRIGGER trg_accounting_logs_update_username
                    AFTER UPDATE OF username ON accounting_logs
                    WHEN date(NEW.timestamp) = date(OLD.timestamp) 
                    AND NEW.username <> OLD.username
                    BEGIN
                        DELETE FROM mv_daily_unique_users
                        WHERE stat_date = date(OLD.timestamp)
                          AND username = OLD.username
                          AND NOT EXISTS (
                              SELECT 1 FROM accounting_logs
                              WHERE username = OLD.username
                                AND date(timestamp) = date(OLD.timestamp)
                          );

                        INSERT OR IGNORE INTO 
                        mv_daily_unique_users(stat_date, username, first_seen_ts)
                        VALUES (date(NEW.timestamp), NEW.username, NEW.timestamp);
                    END;
                    """
                )

            self.conn.commit()
            logger.info("Database initialized: %s", self.db_path)
        except sqlite3.OperationalError as e:
            logger.error("SQLite operational error during schema init: %s", e)
            raise
        except Exception as e:
            logger.exception("Unexpected error initializing DB schema: %s", e)
            raise

    def log_accounting(self, record) -> bool:
        """Log accounting record (uses pool if available)"""
        return self.log_accounting_with_pool(record)

    def log_accounting_with_pool(self, record) -> bool:
        """Log accounting record using connection pool"""
        if not self.pool:
            # Fallback to original single connection method
            return self.log_accounting_original(record)

        try:
            status = getattr(record, "status", None)
            with self.pool.get_connection() as conn:
                # Prepare data for insertion
                data = record.to_dict()
                timestamp_value = data.get("timestamp") or self._now_utc_iso()
                data["timestamp"] = timestamp_value
                data["is_recent"] = self._compute_is_recent(timestamp_value)

                # Build safe query with validated columns
                valid_columns = {
                    "timestamp",
                    "username",
                    "session_id",
                    "status",
                    "service",
                    "command",
                    "client_ip",
                    "port",
                    "start_time",
                    "stop_time",
                    "bytes_in",
                    "bytes_out",
                    "elapsed_time",
                    "privilege_level",
                    "authentication_method",
                    "nas_port",
                    "nas_port_type",
                    "task_id",
                    "timezone",
                    "is_recent",
                }

                # Filter to only valid columns
                safe_data = {k: v for k, v in data.items() if k in valid_columns}
                columns = list(safe_data.keys())
                placeholders = ["?" for _ in columns]
                values = list(safe_data.values())

                query = (
                    f"INSERT INTO accounting_logs ({','.join(columns)}) "
                    f"VALUES ({','.join(placeholders)})"
                )

                conn.execute(query, values)
                # Connection is automatically committed by the context manager

                logger.info(
                    f"Accounting logged: {record.username}@{record.session_id} - "
                    f"{record.command} [{record.status}]"
                )

            # Update active sessions once the write transaction has closed
            if status == "START":
                self._start_session_with_pool(record)
            elif status == "STOP":
                self._stop_session_with_pool(record)
            elif status == "UPDATE":
                self._update_session_with_pool(record)

            self._invalidate_stats_cache_for_timestamp(timestamp_value)
            return True

        except Exception as e:
            logger.error(f"Failed to log accounting record with pool: {e}")
            return False

    # Helper methods for session management with pool
    def _start_session_with_pool(self, record):
        """Start tracking an active session using pool"""
        try:
            with self.pool.get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO active_sessions 
                    (session_id, username, client_ip, start_time, last_update, 
                     service, port, privilege_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        record.session_id,
                        record.username,
                        record.client_ip,
                        record.start_time or self._now_utc_iso(),
                        self._now_utc_iso(),
                        record.service,
                        record.port,
                        record.privilege_level,
                    ),
                )
        except Exception as e:
            logger.error(f"Failed to start session tracking with pool: {e}")

    def _update_session_with_pool(self, record):
        """Update active session using pool"""
        try:
            with self.pool.get_connection() as conn:
                conn.execute(
                    """
                    UPDATE active_sessions 
                    SET last_update = ?, bytes_in = ?, bytes_out = ?
                    WHERE session_id = ?
                """,
                    (
                        self._now_utc_iso(),
                        record.bytes_in,
                        record.bytes_out,
                        record.session_id,
                    ),
                )
        except Exception as e:
            logger.error(f"Failed to update session with pool: {e}")

    def _stop_session_with_pool(self, record):
        """Stop tracking an active session using pool"""
        try:
            with self.pool.get_connection() as conn:
                conn.execute(
                    "DELETE FROM active_sessions WHERE session_id = ?",
                    (record.session_id,),
                )
        except Exception as e:
            logger.error(f"Failed to stop session tracking with pool: {e}")

    # Add cleanup method to close pool when logger is destroyed
    def close(self):
        """Close database connections and pool"""
        if self.pool:
            self.pool.close_all()

        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def __del__(self):
        """Ensure cleanup on object destruction"""
        self.close()

    def log_accounting_original(self, record: dict[str, Any]) -> bool:
        """Original log_accounting method as fallback"""
        if not self.conn:
            logger.error("Database connection not available")
            return False

        try:
            data = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        except Exception:
            logger.exception("Invalid accounting record payload")
            return False

        try:
            cur = self.conn.cursor()
            timestamp_value = data.get("timestamp") or self._now_utc_iso()
            data["timestamp"] = timestamp_value
            is_recent = self._compute_is_recent(timestamp_value)
            cur.execute(
                """
                INSERT INTO accounting (
                    session_id, username, acct_type, start_time, stop_time, 
                    bytes_in, bytes_out, attributes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data.get("session_id"),
                    data.get("username"),
                    data.get("acct_type"),
                    data.get("start_time"),
                    data.get("stop_time"),
                    data.get("bytes_in"),
                    data.get("bytes_out"),
                    data.get("attributes"),
                ),
            )

            cur.execute(
                """
                INSERT INTO accounting_logs (
                    timestamp, username, session_id, status, service, command,
                    client_ip, port, start_time, stop_time, bytes_in, bytes_out,
                    elapsed_time, privilege_level, authentication_method,
                    nas_port, nas_port_type, task_id, timezone, attributes, is_recent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp_value,
                    data.get("username", "unknown"),
                    data.get("session_id", 0),
                    data.get("status", data.get("acct_type", "UNKNOWN")),
                    data.get("service"),
                    data.get("command"),
                    data.get("client_ip"),
                    data.get("port"),
                    data.get("start_time"),
                    data.get("stop_time"),
                    data.get("bytes_in", 0),
                    data.get("bytes_out", 0),
                    data.get("elapsed_time", 0),
                    data.get("privilege_level", 1),
                    data.get("authentication_method"),
                    data.get("nas_port"),
                    data.get("nas_port_type"),
                    data.get("task_id"),
                    data.get("timezone"),
                    data.get("attributes"),
                    is_recent,
                ),
            )

            self.conn.commit()
            self._invalidate_stats_cache_for_timestamp(timestamp_value)
            return True
        except Exception:
            self.conn.rollback()
            logger.exception("Failed to write accounting record")
            return False

    def get_statistics(self, days: int = 30) -> dict[str, Any]:
        """Return aggregate accounting stats for the requested window."""
        days = max(int(days), 0)
        date_offset = f"-{days} days"

        cached = self._get_cached_stats(days)
        if cached is not None:
            return cached

        def _row_value(row: Any, key: str, index: int) -> int:
            if row is None:
                return 0
            if hasattr(row, "keys") and key in row.keys():
                return row[key] or 0
            try:
                return row[index] or 0
            except (IndexError, TypeError):
                return 0

        def _fetch_stats(conn: sqlite3.Connection) -> dict[str, Any]:
            """Fetch statistics with optimized query path."""
            conn.row_factory = sqlite3.Row

            # Try materialized view first for better performance
            if self.maintain_mv:
                try:
                    cursor = conn.execute(
                        "SELECT COALESCE(SUM(total_records), 0) AS total_records, "
                        "COALESCE(SUM(unique_users), 0) AS unique_users "
                        "FROM mv_daily_stats WHERE stat_date > date('now', ?)",
                        (date_offset,),
                    )
                    row = cursor.fetchone()
                    if row is not None:
                        return {
                            "period_days": days,
                            "total_records": _row_value(row, "total_records", 0),
                            "unique_users": _row_value(row, "unique_users", 1),
                        }
                except sqlite3.Error as exc:
                    logger.warning(
                        "Materialized view unavailable (%s), using live query", exc
                    )

            # Fallback to live query with optimized index usage
            cursor = conn.execute(
                "SELECT COUNT(*) AS total_records, "
                "COUNT(DISTINCT username) AS unique_users "
                "FROM accounting_logs WHERE timestamp > datetime('now', ?) "
                "AND is_recent = 1",
                (date_offset,),
            )
            row = cursor.fetchone()
            return {
                "period_days": days,
                "total_records": _row_value(row, "total_records", 0),
                "unique_users": _row_value(row, "unique_users", 1),
            }

        try:
            if self.pool:
                with self.pool.get_connection() as conn:
                    result = _fetch_stats(conn)
            elif self.conn:
                result = _fetch_stats(self.conn)
            else:
                with sqlite3.connect(self.db_path, timeout=10) as conn:
                    conn.row_factory = sqlite3.Row
                    result = _fetch_stats(conn)

            self._set_cached_stats(days, result)
            return dict(result)
        except Exception as exc:
            logger.error(f"Failed to gather statistics: {exc}")
            return {"period_days": days, "total_records": 0, "unique_users": 0}

    def get_recent_records(
        self, since: datetime, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Get recent accounting records for monitoring with optimized query.

        Args:
            since: Start datetime for record retrieval
            limit: Maximum number of records to return

        Returns:
            List of accounting record dictionaries
        """
        # Validate limit to prevent resource exhaustion
        limit = min(max(1, int(limit)), 10000)

        try:
            # Use optimized query with index hint
            query = (
                "SELECT username, session_id, status, service, command, client_ip, "
                "timestamp, bytes_in, bytes_out FROM accounting_logs "
                "WHERE timestamp >= ? AND is_recent = 1 "
                "ORDER BY timestamp DESC LIMIT ?"
            )

            if self.pool:
                with self.pool.get_connection() as conn:
                    cursor = conn.execute(query, (since.isoformat(), limit))
                    return [dict(row) for row in cursor.fetchall()]
            else:
                # Fallback with proper resource management
                with sqlite3.connect(self.db_path, timeout=5) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(query, (since.isoformat(), limit))
                    return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error("Failed to get recent records: %s", e)
            return []

    def get_hourly_stats(self, hours: int = 24) -> list[dict[str, Any]]:
        """Get hourly statistics for charts with performance optimization.

        Args:
            hours: Number of hours to look back (max 168 for 1 week)

        Returns:
            List of hourly statistics dictionaries
        """
        # Validate and limit hours to prevent excessive queries
        hours = min(max(1, int(hours)), 168)  # Max 1 week

        try:
            # Optimized query using is_recent index
            query = (
                "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour, "
                "COUNT(*) as total, "
                "SUM(CASE WHEN status = 'START' THEN 1 ELSE 0 END) as starts, "
                "SUM(CASE WHEN status = 'STOP' THEN 1 ELSE 0 END) as stops "
                "FROM accounting_logs "
                "WHERE timestamp >= datetime('now', ?) AND is_recent = 1 "
                "GROUP BY strftime('%Y-%m-%d %H:00:00', timestamp) "
                "ORDER BY hour"
            )

            if self.pool:
                with self.pool.get_connection() as conn:
                    cursor = conn.execute(query, (f"-{hours} hours",))
                    return [dict(row) for row in cursor.fetchall()]
            else:
                with sqlite3.connect(self.db_path, timeout=5) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(query, (f"-{hours} hours",))
                    return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error("Failed to get hourly stats: %s", e)
            return []
