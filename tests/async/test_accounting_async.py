from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timedelta

import pytest

from tacacs_server.accounting.database import DatabaseLogger
from tacacs_server.accounting.models import AccountingRecord


@pytest.mark.asyncio
async def test_log_accounting_async(tmp_path):
    db_path = tmp_path / "acct.db"
    logger = DatabaseLogger(str(db_path))
    rec = AccountingRecord(
        username="alice",
        session_id=1234,
        status="START",
        service="exec",
        command="login",
        client_ip="127.0.0.1",
        port="tty0",
        bytes_in=10,
        bytes_out=20,
        privilege_level=1,
    )
    ok = await logger.log_accounting_async(rec)
    assert ok is True

    # Verify record exists
    con = sqlite3.connect(str(db_path))
    cur = con.execute("SELECT username, session_id, status FROM accounting_logs")
    row = cur.fetchone()
    assert row is not None
    assert row[0] == "alice"
    assert int(row[1]) == 1234
    con.close()

    # Test get_recent_records path
    since = datetime.utcnow() - timedelta(days=1)
    stats = logger.get_recent_records(since, limit=10)
    assert isinstance(stats, list)
