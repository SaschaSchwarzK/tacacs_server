"""
Metrics collection for TACACS+ server
"""
import time
from collections import Counter, deque
from typing import Any


class MetricsCollector:
    """Collect and analyze server metrics"""
    
    def __init__(self, max_samples=1000):
        self.max_samples = max_samples
        self.auth_latencies = deque(maxlen=max_samples)
        self.packet_sizes = deque(maxlen=max_samples)
        self.error_counts = Counter()
        self.auth_methods = Counter()
        self.start_time = time.time()
    
    def record_auth_latency(self, latency_ms: float):
        """Record authentication latency"""
        self.auth_latencies.append(latency_ms)
    
    def record_packet_size(self, size: int):
        """Record packet size"""
        self.packet_sizes.append(size)
    
    def record_error(self, error_type: str):
        """Record error occurrence"""
        self.error_counts[error_type] += 1
    
    def record_auth_method(self, method: str):
        """Record authentication method usage"""
        self.auth_methods[method] += 1
    
    def get_auth_stats(self) -> dict[str, float]:
        """Get authentication statistics"""
        if not self.auth_latencies:
            return {}
        
        latencies = list(self.auth_latencies)
        latencies.sort()
        
        return {
            'count': len(latencies),
            'avg_latency_ms': sum(latencies) / len(latencies),
            'min_latency_ms': min(latencies),
            'max_latency_ms': max(latencies),
            'p50_latency_ms': latencies[len(latencies) // 2],
            'p95_latency_ms': (
                latencies[int(len(latencies) * 0.95)] 
                if len(latencies) > 20 else max(latencies)
            )
        }
    
    def get_summary(self) -> dict[str, Any]:
        """Get complete metrics summary"""
        return {
            'uptime_seconds': time.time() - self.start_time,
            'auth_stats': self.get_auth_stats(),
            'error_counts': dict(self.error_counts),
            'auth_methods': dict(self.auth_methods),
            'packet_stats': {
                'count': len(self.packet_sizes),
                'avg_size': (
                    sum(self.packet_sizes) / len(self.packet_sizes) 
                    if self.packet_sizes else 0
                ),
                'max_size': max(self.packet_sizes) if self.packet_sizes else 0
            }
        }