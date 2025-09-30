"""
Structured logging configuration
"""
import logging
import json
from datetime import datetime
from typing import Dict, Any

class StructuredLogger:
    """Structured JSON logging with context"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.context: Dict[str, Any] = {}
    
    def set_context(self, **kwargs):
        """Set context variables for all log messages"""
        self.context.update(kwargs)
    
    def clear_context(self):
        """Clear context variables"""
        self.context = {}
    
    def _log(self, level: str, message: str, **kwargs):
        """Log structured message"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': level,
            'message': message,
            'context': self.context,
            **kwargs
        }
        
        # Log as JSON
        getattr(self.logger, level.lower())(json.dumps(log_data))
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self._log('INFO', message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self._log('WARNING', message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self._log('ERROR', message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self._log('DEBUG', message, **kwargs)
