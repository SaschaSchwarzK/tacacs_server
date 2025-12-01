"""Unit tests for metadata cache behavior."""

import time

from tacacs_server.auth.metadata_cache import MetadataCache


def test_metadata_cache_lru_behavior():
    cache = MetadataCache(max_size=2, ttl_seconds=60)
    cache.set("a", {"v": 1})
    cache.set("b", {"v": 2})
    # Touch "a" so it stays recent
    assert cache.get("a") == {"v": 1}
    # Insert "c" should evict least-recently-used ("b")
    cache.set("c", {"v": 3})
    assert cache.get("b") is None
    assert cache.get("a") == {"v": 1}
    assert cache.get("c") == {"v": 3}


def test_metadata_cache_ttl_expiry():
    cache = MetadataCache(max_size=2, ttl_seconds=0)
    cache.set("a", {"v": 1})
    time.sleep(0.01)
    assert cache.get("a") is None
