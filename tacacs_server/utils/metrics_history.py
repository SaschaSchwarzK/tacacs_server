"""
Historical Metrics Storage for TACACS+ Server

SQLite-based storage for metrics history and trend analysis.
"""

import sqlite3
import time
from pathlib import Path

from .logger import get_logger

logger = get_logger(__name__)


class MetricsHistory:
    """Historical metrics storage and retrieval"""
    
    def __init__(self, db_path: str = "data/metrics_history.db"):
        self.db_path = db_path
        self._ensure_db_directory()
        self._init_database()
    
    def _ensure_db_directory(self):
        """Ensure database directory exists"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    def _init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics_snapshots (
                    timestamp INTEGER PRIMARY KEY,
                    auth_requests INTEGER DEFAULT 0,
                    auth_success INTEGER DEFAULT 0,
                    auth_failures INTEGER DEFAULT 0,
                    author_requests INTEGER DEFAULT 0,
                    author_success INTEGER DEFAULT 0,
                    author_failures INTEGER DEFAULT 0,
                    acct_requests INTEGER DEFAULT 0,
                    acct_success INTEGER DEFAULT 0,
                    acct_failures INTEGER DEFAULT 0,
                    connections_active INTEGER DEFAULT 0,
                    connections_total INTEGER DEFAULT 0,
                    memory_usage_mb REAL DEFAULT 0,
                    cpu_percent REAL DEFAULT 0
                )
            """)
            
            # Create index for efficient time-based queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON metrics_snapshots(timestamp)
            """)
    
    def record_snapshot(self, metrics: dict) -> bool:
        """Record a metrics snapshot"""
        try:
            timestamp = int(time.time())
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO metrics_snapshots (
                        timestamp, auth_requests, auth_success, auth_failures,
                        author_requests, author_success, author_failures,
                        acct_requests, acct_success, acct_failures,
                        connections_active, connections_total,
                        memory_usage_mb, cpu_percent
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp,
                    metrics.get('auth_requests', 0),
                    metrics.get('auth_success', 0),
                    metrics.get('auth_failures', 0),
                    metrics.get('author_requests', 0),
                    metrics.get('author_success', 0),
                    metrics.get('author_failures', 0),
                    metrics.get('acct_requests', 0),
                    metrics.get('acct_success', 0),
                    metrics.get('acct_failures', 0),
                    metrics.get('connections_active', 0),
                    metrics.get('connections_total', 0),
                    metrics.get('memory_usage_mb', 0),
                    metrics.get('cpu_percent', 0)
                ))
            return True
        except Exception as e:
            logger.error(f"Failed to record metrics snapshot: {e}")
            return False
    
    def get_historical_data(self, hours: int = 24) -> list[dict]:
        """Get historical metrics data"""
        try:
            since_timestamp = int(time.time() - (hours * 3600))
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT * FROM metrics_snapshots 
                    WHERE timestamp >= ? 
                    ORDER BY timestamp ASC
                """, (since_timestamp,))
                
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get historical data: {e}")
            return []
    
    def get_summary_stats(self, hours: int = 24) -> dict:
        """Get summary statistics for time period"""
        try:
            since_timestamp = int(time.time() - (hours * 3600))
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as data_points,
                        AVG(auth_success * 100.0 / NULLIF(auth_requests, 0)) as avg_auth_success_rate,
                        MAX(connections_active) as peak_connections,
                        AVG(memory_usage_mb) as avg_memory_mb,
                        MAX(memory_usage_mb) as peak_memory_mb,
                        AVG(cpu_percent) as avg_cpu_percent,
                        MAX(cpu_percent) as peak_cpu_percent
                    FROM metrics_snapshots 
                    WHERE timestamp >= ?
                """, (since_timestamp,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'data_points': row[0] or 0,
                        'avg_auth_success_rate': round(row[1] or 0, 2),
                        'peak_connections': row[2] or 0,
                        'avg_memory_mb': round(row[3] or 0, 2),
                        'peak_memory_mb': round(row[4] or 0, 2),
                        'avg_cpu_percent': round(row[5] or 0, 2),
                        'peak_cpu_percent': round(row[6] or 0, 2)
                    }
                return {}
        except Exception as e:
            logger.error(f"Failed to get summary stats: {e}")
            return {}
    
    def cleanup_old_data(self, retention_days: int = 30) -> int:
        """Clean up old metrics data"""
        try:
            cutoff_timestamp = int(time.time() - (retention_days * 24 * 3600))
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    DELETE FROM metrics_snapshots 
                    WHERE timestamp < ?
                """, (cutoff_timestamp,))
                
                deleted_count = cursor.rowcount
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old metrics records")
                
                return deleted_count
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
            return 0


# Global metrics history instance
_metrics_history: MetricsHistory | None = None

def get_metrics_history() -> MetricsHistory:
    """Get global metrics history instance"""
    global _metrics_history
    if _metrics_history is None:
        _metrics_history = MetricsHistory()
    return _metrics_history

def set_metrics_history(history: MetricsHistory):
    """Set global metrics history instance"""
    global _metrics_history
    _metrics_history = history