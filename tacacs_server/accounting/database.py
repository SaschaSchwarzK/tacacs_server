"""
Simple SQLite accounting database logger for TACACS+ server.
"""

import sqlite3
import logging
import queue
from contextlib import contextmanager
import datetime
import threading
from pathlib import Path
from typing import Optional, Any, Dict, List

logger = logging.getLogger(__name__)

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
    def __init__(self, db_path: str = "data/tacacs_accounting.db"):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        
        try:
            db_file = Path(self.db_path)
            if not db_file.parent.exists():
                db_file.parent.mkdir(parents=True, exist_ok=True)
            
            self.conn = sqlite3.connect(str(db_file), timeout=10, check_same_thread=False)
            # Enable foreign keys
            self.conn.execute("PRAGMA foreign_keys = ON;")
            self._initialize_schema()
            
            # ADD THIS LINE AFTER SUCCESSFUL INITIALIZATION:
            self.pool = DatabasePool(str(db_file))
            
        except Exception as e:
            logger.exception("Failed to initialize database: %s", e)
            if self.conn:
                try:
                    self.conn.close()
                except:
                    pass
            self.conn = None
            self.pool = None

    def _initialize_schema(self):
        """Create tables and indexes in a SQLite-compatible way."""
        try:
            cur = self.conn.cursor()
            # Create accounting table
            cur.execute("""
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
            """)
            # Additional table(s) can be created similarly
            # Create indexes separately (SQLite does not allow INDEX inside CREATE TABLE)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_accounting_session_id ON accounting(session_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_accounting_username ON accounting(username);")
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
            with self.pool.get_connection() as conn:
                # Prepare data for insertion
                data = record.to_dict()
                data['timestamp'] = datetime.utcnow().isoformat()
                
                # Build dynamic query based on available data
                columns = list(data.keys())
                placeholders = ['?' for _ in columns]
                values = list(data.values())
                
                query = f"""
                    INSERT INTO accounting_logs ({','.join(columns)}) 
                    VALUES ({','.join(placeholders)})
                """
                
                conn.execute(query, values)
                # Connection is automatically committed by the context manager
                
                logger.info(f"Accounting logged: {record.username}@{record.session_id} - {record.command} [{record.status}]")
                
                # Update active sessions if applicable
                if record.status == 'START':
                    self._start_session_with_pool(record)
                elif record.status == 'STOP':
                    self._stop_session_with_pool(record)
                elif record.status == 'UPDATE':
                    self._update_session_with_pool(record)
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to log accounting record with pool: {e}")
            return False

    # Helper methods for session management with pool
    def _start_session_with_pool(self, record):
        """Start tracking an active session using pool"""
        try:
            with self.pool.get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO active_sessions 
                    (session_id, username, client_ip, start_time, last_update, service, port, privilege_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record.session_id,
                    record.username,
                    record.client_ip,
                    record.start_time or datetime.utcnow().isoformat(),
                    datetime.utcnow().isoformat(),
                    record.service,
                    record.port,
                    record.privilege_level
                ))
        except Exception as e:
            logger.error(f"Failed to start session tracking with pool: {e}")

    def _update_session_with_pool(self, record):
        """Update active session using pool"""
        try:
            with self.pool.get_connection() as conn:
                conn.execute('''
                    UPDATE active_sessions 
                    SET last_update = ?, bytes_in = ?, bytes_out = ?
                    WHERE session_id = ?
                ''', (
                    datetime.utcnow().isoformat(),
                    record.bytes_in,
                    record.bytes_out,
                    record.session_id
                ))
        except Exception as e:
            logger.error(f"Failed to update session with pool: {e}")

    def _stop_session_with_pool(self, record):
        """Stop tracking an active session using pool"""
        try:
            with self.pool.get_connection() as conn:
                conn.execute('DELETE FROM active_sessions WHERE session_id = ?', (record.session_id,))
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


    def log_accounting_original(self, record: Dict[str, Any]) -> bool:
        """Original log_accounting method as fallback"""
        if not self.conn:
            logger.error("Database connection not available")
            return False
        try:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO accounting (session_id, username, acct_type, start_time, stop_time, bytes_in, bytes_out, attributes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.get("session_id"),
                record.get("username"),
                record.get("acct_type"),
                record.get("start_time"),
                record.get("stop_time"),
                record.get("bytes_in"),
                record.get("bytes_out"),
                record.get("attributes"),
            ))
            self.conn.commit()
            return True
        except Exception:
            logger.exception("Failed to write accounting record")
            return False
        
    def get_recent_records(self, since: datetime, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent accounting records for monitoring"""
        try:
            if self.pool:
                with self.pool.get_connection() as conn:
                    cursor = conn.execute('''
                        SELECT * FROM accounting_logs 
                        WHERE timestamp >= ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    ''', (since.isoformat(), limit))
                    return [dict(row) for row in cursor.fetchall()]
            else:
                # Fallback to single connection
                conn = sqlite3.connect(self.db_file)
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM accounting_logs 
                    WHERE timestamp >= ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (since.isoformat(), limit))
                results = [dict(row) for row in cursor.fetchall()]
                conn.close()
                return results
        except Exception as e:
            logger.error(f"Failed to get recent records: {e}")
            return []
    
    def get_hourly_stats(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get hourly statistics for charts"""
        try:
            if self.pool:
                with self.pool.get_connection() as conn:
                    cursor = conn.execute('''
                        SELECT 
                            strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                            COUNT(*) as total,
                            SUM(CASE WHEN status = 'START' THEN 1 ELSE 0 END) as starts,
                            SUM(CASE WHEN status = 'STOP' THEN 1 ELSE 0 END) as stops
                        FROM accounting_logs 
                        WHERE timestamp >= datetime('now', '-{} hours')
                        GROUP BY strftime('%Y-%m-%d %H:00:00', timestamp)
                        ORDER BY hour
                    '''.format(hours))
                    return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get hourly stats: {e}")
            return []