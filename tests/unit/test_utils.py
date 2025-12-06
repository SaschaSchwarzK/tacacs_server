"""
Unit tests for utility functions and classes.

This module contains tests for various utility components including:
- Caching mechanisms (TTLCache, time_cache, LRUDict)
- Authentication rate limiting
- SQL security and query building
- Input validation and sanitization
- Database operations with security constraints

The tests ensure that utility functions correctly implement security measures
and handle edge cases appropriately.
"""

import asyncio

import pytest
from fastapi import HTTPException

from tacacs_server.utils.exceptions import ValidationError
from tacacs_server.utils.security import (
    AuthRateLimiter,
    sanitize_command,
    validate_username,
)
from tacacs_server.utils.simple_cache import LRUDict, TTLCache, time_cache
from tacacs_server.utils.sql_security import (
    ParameterizedQuery,
    SecureDatabase,
    SQLSecurityError,
    sanitize_sql_input,
    validate_sql_identifier,
)
from tacacs_server.utils.validation import (
    InputValidator,
    validate_api_input,
)


class _FakeTime:
    """Mock time provider for testing time-based functionality.

    Allows manual control of time for testing time-dependent code paths.
    """

    def __init__(self):
        """Initialize with a fixed starting time."""
        self.now = 1_000_000

    def time(self):
        """Return the current mock time."""
        return self.now

    def advance(self, seconds):
        """Advance the mock time by the specified number of seconds.

        Args:
            seconds: Number of seconds to advance the mock clock
        """
        self.now += seconds


def test_ttlcache_expiration_and_eviction(monkeypatch):
    """Test time-to-live cache expiration and eviction behavior.

    Verifies:
    - Items expire after their TTL
    - Cache respects maximum size limit
    - Statistics are tracked correctly
    - Clear operation resets the cache
    """
    fake_time = _FakeTime()
    monkeypatch.setattr("tacacs_server.utils.simple_cache.time.time", fake_time.time)
    cache = TTLCache(ttl_seconds=10, maxsize=1)
    cache.set("a", "first")
    assert cache.get("a") == "first"
    fake_time.advance(20)
    assert cache.get("a") is None
    cache.set("a", "first")
    cache.set("b", "second")
    assert cache.evictions == 1
    cache.clear()
    assert cache.hits == 0 and cache.misses == 0 and cache.evictions == 0


def test_time_cache_decorator(monkeypatch):
    """Test the time-based caching decorator.

    Verifies:
    - Function results are cached
    - Cache respects max_age parameter
    - Cache properly expires after time
    - Edge cases for max_age handling
    """
    fake_time = _FakeTime()
    monkeypatch.setattr("tacacs_server.utils.simple_cache.time.time", fake_time.time)
    counter = {"calls": 0}

    @time_cache(max_age=2)
    def identity(value):
        counter["calls"] += 1
        return value

    assert identity("x") == "x"
    fake_time.advance(1)
    assert identity("x") == "x"
    fake_time.advance(3)
    assert identity("x") == "x"
    assert counter["calls"] == 2

    # max_age <= 0 returns identity decorator
    @time_cache(0)
    def identity_direct(value):
        counter["calls"] += 1
        return value

    identity_direct("y")
    identity_direct("y")
    assert counter["calls"] >= 4


def test_lrudict_behaviour():
    """Test LRU (Least Recently Used) dictionary behavior.

    Verifies:
    - Basic dictionary operations
    - LRU eviction policy
    - Default value handling
    """
    lru = LRUDict(maxsize=2)
    lru["a"] = 1
    lru["b"] = 2
    assert lru.get("a") == 1
    lru["c"] = 3
    assert "b" not in lru
    assert lru.get("missing", "default") == "default"


def test_auth_rate_limiter_behaviour(monkeypatch):
    """Test authentication rate limiting functionality.

    Verifies:
    - Request allowance based on attempt count
    - Window-based rate limiting
    - Cleanup of old entries
    - Input validation
    """
    limiter = AuthRateLimiter(max_attempts=2, window_seconds=1)
    assert limiter.is_allowed("1.1.1.1")
    limiter.record_attempt("1.1.1.1")
    limiter.record_attempt("1.1.1.1")
    assert not limiter.is_allowed("1.1.1.1")
    limiter.attempts["old"] = [0]
    monkeypatch.setattr(
        "tacacs_server.utils.security.time.time",
        lambda: limiter.window * 3,
    )
    limiter.cleanup_old_ips()
    assert "old" not in limiter.attempts
    assert not validate_username("")
    assert not validate_username("x" * 65)
    assert validate_username("ok_user")
    assert sanitize_command("rm; echo") == "rm echo"


def test_sql_parameterized_query_operations():
    """Test SQL query building with parameterized queries.

    Verifies:
    - Safe identifier validation
    - Parameterized query construction
    - Input validation
    - All CRUD operations
    """
    assert ParameterizedQuery.validate_identifier("users") == "users"
    with pytest.raises(ValidationError):
        ParameterizedQuery.validate_identifier("DROP")
    with pytest.raises(ValidationError):
        ParameterizedQuery.validate_identifier("")

    with pytest.raises(ValidationError):
        ParameterizedQuery.validate_value("1 OR 1=1")

    select_stmt, select_params = ParameterizedQuery.build_select(
        "users", ["id", "name"], {"id": 1}, order_by="name", limit=10
    )
    compiled_select = str(select_stmt)
    assert "SELECT" in compiled_select and "users" in compiled_select
    assert select_params == {"w_0": 1}

    insert_stmt, insert_params = ParameterizedQuery.build_insert(
        "users", {"name": "alice", "email": "test"}
    )
    assert "INSERT" in str(insert_stmt)
    assert insert_params == {"name": "alice", "email": "test"}

    update_stmt, update_params = ParameterizedQuery.build_update(
        "users", {"name": "bob"}, {"id": 1}
    )
    assert "UPDATE" in str(update_stmt)
    assert "v_name" in update_params and "w_0" in update_params
    delete_stmt, delete_params = ParameterizedQuery.build_delete("users", {"id": 2})
    assert "DELETE" in str(delete_stmt)
    assert delete_params == {"w_0": 2}

    with pytest.raises(ValidationError):
        ParameterizedQuery.build_insert("users", {})

    with pytest.raises(ValidationError):
        ParameterizedQuery.build_update("users", {}, {"id": 1})

    with pytest.raises(ValidationError):
        ParameterizedQuery.build_delete("users", {})


def test_secure_database_operations(tmp_path):
    """Test secure database operations with input validation.

    Verifies:
    - Database connection and table creation
    - CRUD operations with parameterized queries
    - Error handling for invalid queries
    - Input sanitization
    """
    db_path = tmp_path / "secure.db"
    db = SecureDatabase(str(db_path))
    engine = db.connect()
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT)")
    rowid = db.insert("items", {"value": "x"})
    assert rowid >= 1
    results = db.select("items", ["id", "value"])
    assert results[0]["value"] == "x"
    updated = db.update("items", {"value": "y"}, {"id": rowid})
    assert updated == 1
    deleted = db.delete("items", {"id": rowid})
    assert deleted == 1
    db.close()

    with pytest.raises(SQLSecurityError):
        db.select("missing_table", ["id"])

    assert sanitize_sql_input("clean") == "clean"
    assert validate_sql_identifier("ok") == "ok"


def test_input_validation_and_form_helpers():
    """Test input validation and form helper functions.

    Verifies validation for:
    - Usernames and passwords
    - Network addresses and hostnames
    - Port numbers and privilege levels
    - LDAP filters
    - String length and format
    """
    with pytest.raises(ValidationError):
        InputValidator.validate_username("")
    with pytest.raises(ValidationError):
        InputValidator.validate_password("short1")
    with pytest.raises(ValidationError):
        InputValidator.validate_network("invalid")
    with pytest.raises(ValidationError):
        InputValidator.validate_ip_address("999.999.999.999")
    with pytest.raises(ValidationError):
        InputValidator.validate_hostname("")
    assert InputValidator.validate_string_length("abc", "field", min_len=1) == "abc"
    assert InputValidator.validate_port("80") == 80
    with pytest.raises(ValidationError):
        InputValidator.validate_port("-1")
    with pytest.raises(ValidationError):
        InputValidator.validate_privilege_level("abc")
    with pytest.raises(ValidationError):
        InputValidator.validate_secret("short")
    assert InputValidator.sanitize_log_input("clean\nline") == "cleanline"
    with pytest.raises(ValidationError):
        InputValidator.validate_ldap_filter("(cn=admin)")
    with pytest.raises(ValidationError):
        InputValidator.validate_ldap_filter("cn=admin)")
    assert InputValidator.validate_string_list("a,b", "items") == ["a", "b"]


def test_validate_api_input_decorator():
    """Test the API input validation decorator.

    Verifies:
    - Input validation before function execution
    - Error handling for invalid inputs
    - Proper HTTP error status codes for invalid payloads
    """

    def validator(payload):
        if payload.get("fail"):
            raise ValidationError("failure")
        return payload

    async def handler(*, payload):
        return payload

    decorated = validate_api_input(validator)(handler)

    result = asyncio.run(decorated(payload={"valid": True}))
    assert result == {"valid": True}

    with pytest.raises(HTTPException) as exc:
        asyncio.run(decorated(payload={"fail": True}))
    assert exc.value.status_code == 422
