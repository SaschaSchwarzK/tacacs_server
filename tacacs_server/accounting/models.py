"""
Data Models for TACACS+ Accounting
"""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass
class AccountingRecord:
    """TACACS+ accounting record data model"""
    
    username: str
    session_id: int
    status: str  # START, STOP, UPDATE
    service: str = 'unknown'
    command: str = 'unknown'
    client_ip: str | None = None
    port: str | None = None
    start_time: str | None = None
    stop_time: str | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    elapsed_time: int = 0
    privilege_level: int = 1
    authentication_method: str | None = None
    nas_port: str | None = None
    nas_port_type: str | None = None
    task_id: str | None = None
    timezone: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values"""
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'AccountingRecord':
        """Create AccountingRecord from dictionary"""
        # Filter out keys that don't exist in the dataclass
        valid_keys = {f.name for f in cls.__dataclasses_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered_data)
    
    def duration_seconds(self) -> int | None:
        """Calculate session duration in seconds"""
        if self.start_time and self.stop_time:
            try:
                start = datetime.fromisoformat(self.start_time)
                stop = datetime.fromisoformat(self.stop_time)
                return int((stop - start).total_seconds())
            except ValueError:
                return None
        return self.elapsed_time if self.elapsed_time > 0 else None
    
    def format_duration(self) -> str:
        """Format duration as human readable string"""
        duration = self.duration_seconds()
        if duration is None:
            return "Unknown"
        
        hours, remainder = divmod(duration, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def format_bytes(self, bytes_count: int) -> str:
        """Format bytes as human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} TB"
    
    def format_bytes_in(self) -> str:
        """Format incoming bytes"""
        return self.format_bytes(self.bytes_in)
    
    def format_bytes_out(self) -> str:
        """Format outgoing bytes"""
        return self.format_bytes(self.bytes_out)
    
    def __str__(self) -> str:
        """String representation"""
        return f"AccountingRecord({self.username}@{self.session_id}: {self.status} - {self.command})"

@dataclass
class SessionInfo:
    """Active session information"""
    
    session_id: int
    username: str
    client_ip: str
    start_time: str
    last_update: str
    service: str
    port: str | None = None
    privilege_level: int = 1
    bytes_in: int = 0
    bytes_out: int = 0
    
    def duration_seconds(self) -> int:
        """Calculate session duration in seconds"""
        try:
            start = datetime.fromisoformat(self.start_time)
            now = datetime.utcnow()
            return int((now - start).total_seconds())
        except ValueError:
            return 0
    
    def is_idle(self, idle_threshold_minutes: int = 30) -> bool:
        """Check if session is idle"""
        try:
            last_update = datetime.fromisoformat(self.last_update)
            now = datetime.utcnow()
            idle_time = (now - last_update).total_seconds() / 60
            return idle_time > idle_threshold_minutes
        except ValueError:
            return False
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'SessionInfo':
        """Create SessionInfo from dictionary"""
        return cls(**data)