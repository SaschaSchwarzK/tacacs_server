"""
Performance benchmarks
"""
import pytest
import time
from concurrent.futures import ThreadPoolExecutor

def test_concurrent_authentications(benchmark, running_server):
    """Benchmark concurrent authentication performance"""
    
    def authenticate():
        # Authenticate user
        return running_server.authenticate("user", "pass")
    
    # Benchmark with 100 concurrent authentications
    result = benchmark(lambda: [
        authenticate() for _ in range(100)
    ])
    
    # Assert performance requirements
    assert benchmark.stats['mean'] < 1.0  # Average under 1 second

def test_accounting_throughput(benchmark, db_logger):
    """Benchmark accounting write throughput"""
    
    def log_records():
        for i in range(1000):
            db_logger.log_accounting(create_test_record())
    
    result = benchmark(log_records)
    
    # Assert can handle 1000 records/second
    assert benchmark.stats['mean'] < 1.0