"""Cache for user group metadata to reduce DB lookups."""

import threading
import time
from collections import OrderedDict
from typing import Any


class MetadataCache:
    """Thread-safe LRU-ish cache for user group metadata."""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, group_name: str) -> dict[str, Any] | None:
        """Get metadata from cache if not expired."""
        with self._lock:
            if group_name not in self._cache:
                return None

            metadata, timestamp = self._cache.get(group_name, (None, 0))
            if metadata is None:
                return None
            if time.time() - timestamp > self.ttl_seconds:
                del self._cache[group_name]
                return None

            # mark as recently used
            self._cache.move_to_end(group_name)
            return metadata

    def set(self, group_name: str, metadata: dict[str, Any]) -> None:
        """Store metadata in cache with current timestamp."""
        with self._lock:
            if group_name in self._cache:
                self._cache.move_to_end(group_name)
            self._cache[group_name] = (metadata, time.time())

            if len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

    def invalidate(self, group_name: str) -> None:
        """Remove specific group from cache."""
        with self._lock:
            self._cache.pop(group_name, None)

    def clear(self) -> None:
        """Clear entire cache."""
        with self._lock:
            self._cache.clear()

    def stats(self) -> dict[str, int]:
        """Get cache statistics."""
        with self._lock:
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "ttl_seconds": self.ttl_seconds,
            }


_metadata_cache = MetadataCache(max_size=1000, ttl_seconds=300)


def get_metadata_cache() -> MetadataCache:
    """Get global metadata cache instance."""
    return _metadata_cache
