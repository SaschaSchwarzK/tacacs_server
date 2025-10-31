from __future__ import annotations

"""Generic retry decorator with exponential backoff.

Usage:
    from tacacs_server.utils.retry import retry

    @retry(max_retries=3, initial_delay=1.0, backoff=2.0, max_delay=30.0,
           exceptions=(TimeoutError,))
    def flaky_call(...):
        ...
"""

import time
from functools import wraps
from typing import Any, Callable, Type, TypeVar

try:
    from typing_extensions import ParamSpec  # Python <3.10 compatibility
except Exception:  # pragma: no cover
    ParamSpec = lambda name: Any  # type: ignore[misc,assignment]

P = ParamSpec("P")
T = TypeVar("T")


def retry(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff: float = 2.0,
    exceptions: tuple[Type[Exception], ...] = (Exception,),
):
    """Retry decorator with exponential backoff.

    Args:
        max_retries: Number of retry attempts (in addition to the first try)
        initial_delay: Base delay before first retry in seconds
        max_delay: Maximum delay cap between retries
        backoff: Exponential backoff factor (e.g., 2.0 doubles each time)
        exceptions: Tuple of exception types to catch and retry
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:  # type: ignore[misc]
            last_exc: Exception | None = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:  # type: ignore[misc]
                    last_exc = e
                    if attempt >= max_retries:
                        break
                    sleep_time = min(initial_delay * (backoff**attempt), max_delay)
                    time.sleep(sleep_time)
            assert last_exc is not None
            raise last_exc  # re-raise last exception

        return wrapper

    return decorator
