from __future__ import annotations

from collections.abc import Sequence
from typing import Any


# Define a global no-op metric that safely accepts operations
class _NoOp:
    def labels(self, *args, **kwargs):
        return self

    def inc(self, *args, **kwargs):
        return None

    def observe(self, *args, **kwargs):
        return None

    def set(self, *args, **kwargs):
        return None


_PROM_REGISTRY: Any | None
_PROM_Counter: Any | None
_PROM_Histogram: Any | None
_PROM_Gauge: Any | None
try:
    from prometheus_client import (
        REGISTRY as _PROM_REGISTRY,
    )
    from prometheus_client import (
        Counter as _PROM_Counter,
    )
    from prometheus_client import (
        Gauge as _PROM_Gauge,
    )
    from prometheus_client import (
        Histogram as _PROM_Histogram,
    )
except Exception:  # pragma: no cover
    _PROM_REGISTRY = None
    _PROM_Counter = None
    _PROM_Histogram = None
    _PROM_Gauge = None


def _fullname(name: str, namespace: str | None) -> str:
    return f"{namespace}_{name}" if namespace else name


def _get_existing(fullname: str):
    try:
        if _PROM_REGISTRY is None:
            return None
        # Access default registry for existing collectors
        reg = getattr(_PROM_REGISTRY, "_names_to_collectors", {})
        if isinstance(reg, dict):
            return reg.get(fullname)
        return None
    except Exception:
        return None


def safe_counter(
    name: str,
    documentation: str,
    labelnames: list[str] | None = None,
    namespace: str | None = None,
):
    fullname = _fullname(name, namespace)
    existing = _get_existing(fullname)
    if existing is not None:
        return existing
    try:
        if _PROM_Counter is None:
            return _NoOp()
        ns = namespace or ""
        return _PROM_Counter(name, documentation, labelnames or [], namespace=ns)
    except Exception:
        return _NoOp()


def safe_histogram(
    name: str,
    documentation: str,
    buckets: list[float] | None = None,
    namespace: str | None = None,
):
    fullname = _fullname(name, namespace)
    existing = _get_existing(fullname)
    if existing is not None:
        return existing
    try:
        if _PROM_Histogram is None:
            return _NoOp()
        ns = namespace or ""
        bks: Sequence[float | str] = tuple(buckets) if buckets else ()
        return _PROM_Histogram(name, documentation, buckets=bks, namespace=ns)
    except Exception:
        return _NoOp()


def safe_gauge(name: str, documentation: str, namespace: str | None = None):
    fullname = _fullname(name, namespace)
    existing = _get_existing(fullname)
    if existing is not None:
        return existing
    try:
        if _PROM_Gauge is None:
            return _NoOp()
        ns = namespace or ""
        return _PROM_Gauge(name, documentation, namespace=ns)
    except Exception:
        return _NoOp()


# Okta caches
okta_group_cache_hits = safe_counter(
    "okta_group_cache_hits_total", "Okta group cache hits", [], namespace="tacacs"
)
okta_group_cache_misses = safe_counter(
    "okta_group_cache_misses_total", "Okta group cache misses", [], namespace="tacacs"
)

# Okta HTTP metrics
okta_token_requests = safe_counter(
    "okta_token_requests_total", "Okta token endpoint requests", [], namespace="tacacs"
)
okta_group_requests = safe_counter(
    "okta_group_requests_total", "Okta groups API requests", [], namespace="tacacs"
)
okta_token_latency = safe_histogram(
    "okta_token_latency_seconds",
    "Latency for Okta token requests",
    buckets=[0.05, 0.1, 0.2, 0.5, 1, 2, 5],
    namespace="tacacs",
)
okta_group_latency = safe_histogram(
    "okta_group_latency_seconds",
    "Latency for Okta group requests",
    buckets=[0.05, 0.1, 0.2, 0.5, 1, 2, 5],
    namespace="tacacs",
)
okta_retries_total = safe_counter(
    "okta_retries_total",
    "Count of Okta retry-worthy responses (429/5xx)",
    [],
    namespace="tacacs",
)
okta_circuit_open = safe_gauge(
    "okta_circuit_open",
    "Circuit breaker open state for Okta backend (1=open,0=closed)",
    namespace="tacacs",
)

# Circuit transitions
okta_circuit_open_total = safe_counter(
    "okta_circuit_open_total",
    "Total times Okta circuit breaker opened",
    [],
    namespace="tacacs",
)
okta_circuit_reset_total = safe_counter(
    "okta_circuit_reset_total",
    "Total times Okta circuit breaker reset/closed",
    [],
    namespace="tacacs",
)

# LDAP pool metrics
ldap_pool_borrows = safe_counter(
    "ldap_pool_borrows_total", "LDAP pool borrows", [], namespace="tacacs"
)
ldap_pool_reconnects = safe_counter(
    "ldap_pool_reconnects_total", "LDAP pool reconnects", [], namespace="tacacs"
)


class MetricsCollector:
    """Backward-compatible placeholder for legacy metrics integration.

    The server constructs this class but does not currently use instance methods.
    This stub preserves import compatibility and a future hook point.
    """

    def __init__(self) -> None:
        pass
