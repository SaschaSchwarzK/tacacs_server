"""
Audit Trail Logger for TACACS+ Server

Structured logging for admin actions and compliance reporting.
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .logger import get_logger

logger = get_logger(__name__)


class AuditLogger:
    """Audit trail logging and retrieval"""
    
    def __init__(self, db_path: str = "data/audit_trail.db"):
        self.db_path = db_path
        self._ensure_db_directory()
        self._init_database()
    
    def _ensure_db_directory(self):
        """Ensure database directory exists"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    def _init_database(self):
        """Initialize audit database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT,
                    details TEXT,
                    client_ip TEXT,
                    success BOOLEAN NOT NULL,
                    error_message TEXT
                )
            """)
            
            # Create indexes for efficient queries
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON audit_log(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_action ON audit_log(action)")
    
    def log_action(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        client_ip: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> bool:
        """Log an admin action"""
        try:
            timestamp = int(time.time())
            details_json = json.dumps(details) if details else None
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO audit_log (
                        timestamp, user_id, action, resource_type, resource_id,
                        details, client_ip, success, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, user_id, action, resource_type, resource_id,
                    details_json, client_ip, success, error_message
                ))
            
            # Also log to structured logger
            logger.info(
                "audit_action",
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                success=success,
                client_ip=client_ip
            )
            
            return True
        except Exception as e:
            logger.error(f"Failed to log audit action: {e}")
            return False
    
    def get_audit_log(
        self,
        hours: int = 24,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get audit log entries"""
        try:
            since_timestamp = int(time.time() - (hours * 3600))
            
            query = """
                SELECT * FROM audit_log 
                WHERE timestamp >= ?
            """
            params = [since_timestamp]
            
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            
            if action:
                query += " AND action = ?"
                params.append(action)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                
                entries = []
                for row in cursor.fetchall():
                    entry = dict(row)
                    if entry['details']:
                        try:
                            entry['details'] = json.loads(entry['details'])
                        except json.JSONDecodeError:
                            pass
                    entries.append(entry)
                
                return entries
        except Exception as e:
            logger.error(f"Failed to get audit log: {e}")
            return []
    
    def get_audit_summary(self, hours: int = 24) -> Dict:
        """Get audit summary statistics"""
        try:
            since_timestamp = int(time.time() - (hours * 3600))
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_actions,
                        COUNT(CASE WHEN success = 1 THEN 1 END) as successful_actions,
                        COUNT(CASE WHEN success = 0 THEN 1 END) as failed_actions,
                        COUNT(DISTINCT user_id) as unique_users,
                        COUNT(DISTINCT action) as unique_actions
                    FROM audit_log 
                    WHERE timestamp >= ?
                """, (since_timestamp,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'total_actions': row[0],
                        'successful_actions': row[1],
                        'failed_actions': row[2],
                        'unique_users': row[3],
                        'unique_actions': row[4],
                        'success_rate': round((row[1] / row[0] * 100) if row[0] > 0 else 0, 2)
                    }
                return {}
        except Exception as e:
            logger.error(f"Failed to get audit summary: {e}")
            return {}
    
    def cleanup_old_entries(self, retention_days: int = 90) -> int:
        """Clean up old audit entries"""
        try:
            cutoff_timestamp = int(time.time() - (retention_days * 24 * 3600))
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    DELETE FROM audit_log 
                    WHERE timestamp < ?
                """, (cutoff_timestamp,))
                
                deleted_count = cursor.rowcount
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old audit entries")
                
                return deleted_count
        except Exception as e:
            logger.error(f"Failed to cleanup old audit entries: {e}")
            return 0


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None

def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger

def set_audit_logger(audit_logger: AuditLogger):
    """Set global audit logger instance"""
    global _audit_logger
    _audit_logger = audit_logger