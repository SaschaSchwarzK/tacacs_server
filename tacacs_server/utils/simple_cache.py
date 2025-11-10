from __future__ import annotations

import functools
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, Generic, TypeVar, cast

from tacacs_server.utils.logger import get_logger

K = TypeVar("K")
V = TypeVar("V")

_logger = get_logger(__name__)


class TTLCache(Generic[K, V]):
    """Simple in-memory TTL cache with basic hit/miss counters.

    - Thread-safe via a single RLock
    - No LRU eviction; optional maxsize for coarse limiting
    """

    def __init__(self, ttl_seconds: int, maxsize: int | None = None) -> None:
        self._ttl = int(max(0, ttl_seconds))
        self._maxsize = maxsize if (isinstance(maxsize, int) and maxsize > 0) else None
        self._data: dict[K, tuple[float, V]] = {}
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key: K) -> V | None:
        now = time.time()
        with self._lock:
            item = self._data.get(key)
            if not item:
                self.misses += 1
                return None
            exp, val = item
            if exp and exp < now:
                # expired
                self.misses += 1
                try:
                    del self._data[key]
                except KeyError as exc:
                    _logger.debug("Cache key delete race: %s", exc)
                return None
            self.hits += 1
            return val

    def set(self, key: K, value: V, *, ttl: int | None = None) -> None:
        exp_ttl = int(ttl if ttl is not None else self._ttl)
        exp = time.time() + exp_ttl if exp_ttl > 0 else 0.0
        with self._lock:
            if self._maxsize is not None and len(self._data) >= self._maxsize:
                # naive eviction: remove one arbitrary expired/oldest entry
                # prefer to drop expired entries first
                oldest_key: K | None = None
                oldest_exp = float("inf")
                for k, (e, _v) in list(self._data.items()):
                    if e and e < time.time():
                        try:
                            del self._data[k]
                            self.evictions += 1
                            break
                        except KeyError as exc:
                            _logger.debug(
                                "Cache eviction race on expired entry: %s", exc
                            )
                            continue
                    if e < oldest_exp:
                        oldest_exp = e
                        oldest_key = k
                else:
                    if oldest_key is not None:
                        try:
                            del self._data[oldest_key]
                            self.evictions += 1
                        except KeyError as exc:
                            _logger.debug(
                                "Cache eviction race on oldest entry: %s", exc
                            )
            self._data[key] = (exp, value)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self.hits = 0
            self.misses = 0
            self.evictions = 0


def time_cache(
    max_age: int, maxsize: int = 128, typed: bool = False
) -> Callable[[Callable[..., V]], Callable[..., V]]:
    """LRU cache decorator with time-based invalidation via a changing salt.

    - Wraps functools.lru_cache but injects a time-derived argument to enforce TTL.
    - Best for pure, argument-only functions (no reliance on mutable state).
    - For instance-scoped caches, prefer TTLCache above.
    """

    if max_age <= 0:
        # Degenerate case: no caching
        def _identity_decorator(fn: Callable[..., V]) -> Callable[..., V]:
            return fn

        return _identity_decorator

    def _decorator(fn: Callable[..., V]) -> Callable[..., V]:
        @functools.lru_cache(maxsize=maxsize, typed=typed)
        def _cached(*args: object, __time_salt: int, **kwargs: object) -> V:
            return fn(*args, **kwargs)

        @functools.wraps(fn)
        def _wrapped(*args: object, **kwargs: object) -> V:
            # Integer-divide current time by max_age to change salt per-window
            return _cached(*args, __time_salt=int(time.time() // max_age), **kwargs)

        return _wrapped

    return _decorator


class LRUDict(OrderedDict, Generic[K, V]):
    """A lightweight LRU dict with optional max size.

    - Evicts the least-recently-used item when `maxsize` is exceeded.
    - On set, updates recency and enforces the size bound.
    - On get, moves the key to most-recent if found.
    - Thread safety is the caller's responsibility.
    """

    def __init__(self, maxsize: int | None = 1000) -> None:
        super().__init__()
        self.maxsize = maxsize if (isinstance(maxsize, int) and maxsize > 0) else None

    def __setitem__(self, key: K, value: V) -> None:
        if key in self:
            try:
                super().__delitem__(key)
            except KeyError:
                pass
        super().__setitem__(key, value)
        try:
            self.move_to_end(key, last=True)
        except Exception as exc:
            _logger.warning("LRU move_to_end failed for %s: %s", key, exc)
        if self.maxsize is not None and len(self) > self.maxsize:
            try:
                self.popitem(last=False)
            except Exception:
                pass

    def __getitem__(self, key: K) -> V:
        value = cast(V, super().__getitem__(key))
        try:
            self.move_to_end(key, last=True)
        except Exception as exc:
            _logger.warning("LRU move_to_end during get failed for %s: %s", key, exc)
        return value

    def get(self, key: K, default: Any = None) -> Any:
        try:
            return self.__getitem__(key)
        except KeyError:
            return default

    def touch(self, key: K) -> None:
        try:
            self.move_to_end(key, last=True)
        except Exception as exc:
            _logger.warning("LRU touch failed for %s: %s", key, exc)
