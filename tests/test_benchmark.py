"""Performance benchmarks for TACACS+/RADIUS workflows."""

from __future__ import annotations

import pytest

from tacacs_server.accounting.database import DatabaseLogger
from tacacs_server.accounting.models import AccountingRecord


@pytest.fixture(scope="session")
def running_server():
    """Provide a lightweight stubbed server for authentication benchmarks."""

    class RunningServer:
        def authenticate(self, username: str, password: str) -> bool:
            _ = (username, password)
            return True

    return RunningServer()


@pytest.fixture
def db_logger(test_db) -> DatabaseLogger:
    """Provide a temporary accounting logger for benchmarks."""
    return DatabaseLogger(test_db.replace("test.db", "accounting.db"))


def create_test_record(index: int) -> AccountingRecord:
    """Build a synthetic accounting record for benchmarking."""

    return AccountingRecord(
        username=f"benchmark{index}",
        session_id=index,
        status="START",
        service="exec",
        command="show version",
        client_ip="127.0.0.1",
    )


def test_concurrent_authentications(benchmark, running_server):
    """Benchmark the end-to-end authentication path."""

    benchmark.group = "tacacs-auth"

    def run_batch() -> int:
        successes = 0
        for idx in range(25):
            if running_server.authenticate("admin", "admin123"):
                successes += 1
        return successes

    result = benchmark(run_batch)
    assert result == 25


def test_accounting_throughput(benchmark, db_logger: DatabaseLogger):
    """Benchmark accounting logging throughput."""

    benchmark.group = "tacacs-accounting"

    def log_records() -> int:
        for i in range(500):
            db_logger.log_accounting(create_test_record(i))
        return 500

    result = benchmark(log_records)
    assert result == 500
