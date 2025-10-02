"""
Async database operations for better performance
"""
import asyncio
from datetime import datetime
from typing import Any

import aiosqlite

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)

class AsyncDatabaseLogger:
    """Async database logger for high-performance accounting"""
    
    def __init__(self, db_path: str = "data/tacacs_accounting.db"):
        self.db_path = db_path
        self.write_queue = asyncio.Queue(maxsize=10000)
        self.writer_task = None
        self.running = False
    
    async def start(self):
        """Start async writer"""
        self.running = True
        await self._initialize_schema()
        self.writer_task = asyncio.create_task(self._writer_worker())
        logger.info("Async database logger started")
    
    async def stop(self):
        """Stop async writer"""
        self.running = False
        if self.writer_task:
            await self.writer_task
        logger.info("Async database logger stopped")
    
    async def _initialize_schema(self):
        """Initialize database schema"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('''
                CREATE TABLE IF NOT EXISTS accounting_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    username TEXT NOT NULL,
                    session_id INTEGER NOT NULL,
                    client_ip TEXT,
                    service TEXT,
                    command TEXT,
                    status TEXT NOT NULL,
                    bytes_in INTEGER DEFAULT 0,
                    bytes_out INTEGER DEFAULT 0,
                    elapsed_time INTEGER DEFAULT 0
                )
            ''')
            await db.execute(
                'CREATE INDEX IF NOT EXISTS idx_username ON accounting_logs(username)'
            )
            await db.execute(
                'CREATE INDEX IF NOT EXISTS idx_session_id ON '
                'accounting_logs(session_id)'
            )
            await db.execute(
                'CREATE INDEX IF NOT EXISTS idx_timestamp ON accounting_logs(timestamp)'
            )
            await db.commit()
    
    async def log_accounting(self, record: dict[str, Any]) -> bool:
        """Queue accounting record for async write"""
        try:
            await self.write_queue.put(record)
            return True
        except asyncio.QueueFull:
            logger.warning("Accounting queue full, dropping record")
            return False
    
    async def _writer_worker(self):
        """Background worker for async writes"""
        batch = []
        batch_size = 100
        flush_interval = 1.0  # seconds
        last_flush = asyncio.get_event_loop().time()
        
        while self.running or not self.write_queue.empty():
            try:
                # Get record with timeout
                record = await asyncio.wait_for(
                    self.write_queue.get(), 
                    timeout=0.1
                )
                batch.append(record)
                
                # Flush if batch is full or time elapsed
                current_time = asyncio.get_event_loop().time()
                if (
                    len(batch) >= batch_size
                    or (current_time - last_flush) >= flush_interval
                ):
                    await self._flush_batch(batch)
                    batch = []
                    last_flush = current_time
                    
            except TimeoutError:
                # Flush partial batch if time elapsed
                if (
                    batch
                    and (asyncio.get_event_loop().time() - last_flush) >= flush_interval
                ):
                    await self._flush_batch(batch)
                    batch = []
                    last_flush = asyncio.get_event_loop().time()
            except Exception as e:
                logger.error(f"Error in writer worker: {e}")
        
        # Flush remaining records
        if batch:
            await self._flush_batch(batch)
    
    async def _flush_batch(self, batch: list[dict[str, Any]]):
        """Flush batch of records to database"""
        if not batch:
            return
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Prepare batch insert
                placeholders = ','.join(['(?, ?, ?, ?, ?, ?, ?, ?, ?)' for _ in batch])
                query = f"""
                    INSERT INTO accounting_logs 
                    (timestamp, username, session_id, client_ip, service, command, 
                     status, bytes_in, bytes_out)
                    VALUES {placeholders}
                """
                
                # Flatten batch data
                values = []
                for record in batch:
                    values.extend([
                        datetime.utcnow().isoformat(),
                        record.get('username', 'unknown'),
                        record.get('session_id', 0),
                        record.get('client_ip'),
                        record.get('service', 'unknown'),
                        record.get('command', ''),
                        record.get('status', 'UNKNOWN'),
                        record.get('bytes_in', 0),
                        record.get('bytes_out', 0)
                    ])
                
                await db.execute(query, values)
                await db.commit()
                
                logger.debug(f"Flushed {len(batch)} accounting records to database")
                
        except Exception as e:
            logger.error(f"Error flushing batch to database: {e}")
    
    async def get_statistics(self, days: int = 30) -> dict[str, Any]:
        """Get accounting statistics"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            # Total records (prefer pre-computed stats, fall back to raw count)
            try:
                cursor = await db.execute(f'''
                    SELECT COALESCE(SUM(total_records), 0) AS count
                    FROM mv_daily_stats
                    WHERE stat_date > date('now', '-{days} days')
                ''')
                row = await cursor.fetchone()
                total_records = row['count'] if row else 0
            except Exception as exc:
                logger.warning(
                    "Failed to read mv_daily_stats (%s), counting logs directly", exc
                )
                cursor = await db.execute(f'''
                    SELECT COUNT(*) as count FROM accounting_logs 
                    WHERE timestamp > datetime('now', '-{days} days')
                ''')
                row = await cursor.fetchone()
                total_records = row['count'] if row else 0
            
            # Unique users
            cursor = await db.execute(f'''
                SELECT COUNT(DISTINCT username) as count FROM accounting_logs 
                WHERE timestamp > datetime('now', '-{days} days')
            ''')
            row = await cursor.fetchone()
            unique_users = row['count'] if row else 0
            
            return {
                'period_days': days,
                'total_records': total_records,
                'unique_users': unique_users
            }
