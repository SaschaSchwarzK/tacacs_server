"""
Background Tasks for TACACS+ Server

Periodic tasks for metrics collection, cleanup, and maintenance.
"""

import threading
import time

from .audit_logger import get_audit_logger
from .logger import get_logger
from .metrics_history import get_metrics_history
from .rate_limiter import get_rate_limiter

logger = get_logger(__name__)


class BackgroundTaskManager:
    """Manages background tasks for the TACACS+ server"""

    def __init__(self, tacacs_server=None):
        self.tacacs_server = tacacs_server
        self.running = False
        self.task_thread: threading.Thread | None = None
        self.metrics_interval = 60  # Record metrics every minute
        self.cleanup_interval = 3600  # Cleanup every hour
        self.last_metrics_time = 0
        self.last_cleanup_time = 0

    def start(self):
        """Start background tasks"""
        if self.running:
            return

        self.running = True
        self.task_thread = threading.Thread(target=self._run_tasks, daemon=True)
        self.task_thread.start()
        logger.info("Background task manager started")

    def stop(self):
        """Stop background tasks"""
        if not self.running:
            return

        self.running = False
        if self.task_thread:
            self.task_thread.join(timeout=5)
        logger.info("Background task manager stopped")

    def _run_tasks(self):
        """Main task loop"""
        while self.running:
            try:
                current_time = time.time()

                # Record metrics periodically
                if current_time - self.last_metrics_time >= self.metrics_interval:
                    self._record_metrics()
                    self.last_metrics_time = current_time

                # Cleanup old data periodically
                if current_time - self.last_cleanup_time >= self.cleanup_interval:
                    self._cleanup_old_data()
                    self.last_cleanup_time = current_time

                # Sleep for a short interval
                time.sleep(10)

            except Exception as e:
                logger.error(f"Background task error: {e}")
                time.sleep(30)  # Wait longer on error

    def _record_metrics(self):
        """Record current metrics to history"""
        try:
            if not self.tacacs_server:
                return

            stats = self.tacacs_server.get_stats()
            if not stats:
                return

            # Add system metrics
            try:
                import psutil

                memory_info = psutil.virtual_memory()
                cpu_percent = psutil.cpu_percent(interval=0.0)

                metrics_data = {
                    **stats,
                    "memory_usage_mb": memory_info.used / 1024 / 1024,
                    "cpu_percent": cpu_percent,
                }
            except ImportError:
                metrics_data = stats

            # Record to history
            history = get_metrics_history()
            history.record_snapshot(metrics_data)

        except Exception as e:
            logger.debug(f"Failed to record metrics: {e}")

    def _cleanup_old_data(self):
        """Clean up old data from various stores"""
        try:
            # Clean up old metrics (30 days)
            history = get_metrics_history()
            deleted_metrics = history.cleanup_old_data(retention_days=30)

            # Clean up old audit entries (90 days)
            audit_logger = get_audit_logger()
            deleted_audit = audit_logger.cleanup_old_entries(retention_days=90)

            # Clean up old rate limiter entries (1 hour)
            rate_limiter = get_rate_limiter()
            rate_limiter.cleanup_old_entries(max_age_seconds=3600)

            if deleted_metrics > 0 or deleted_audit > 0:
                logger.info(
                    f"Cleanup completed: {deleted_metrics} metrics, "
                    f"{deleted_audit} audit entries removed"
                )

        except Exception as e:
            logger.error(f"Cleanup task error: {e}")


# Global task manager instance
_task_manager: BackgroundTaskManager | None = None


def get_task_manager() -> BackgroundTaskManager | None:
    """Get global task manager instance"""
    return _task_manager


def start_background_tasks(tacacs_server=None):
    """Start background tasks"""
    global _task_manager
    if _task_manager is None:
        _task_manager = BackgroundTaskManager(tacacs_server)
    _task_manager.start()


def stop_background_tasks():
    """Stop background tasks"""
    global _task_manager
    if _task_manager:
        _task_manager.stop()
        _task_manager = None
