"""Unit tests for metrics helpers."""

import uuid

import pytest
from prometheus_client import REGISTRY, generate_latest

from tacacs_server.utils import metrics


def _unique_name(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@pytest.mark.parametrize("factory", [metrics.safe_counter, metrics.safe_gauge])
def test_counters_and_gauges_reuse_existing(factory):
    """safe_* should reuse collectors and allow basic operations."""
    name = _unique_name("metric")
    doc = "test metric"
    first = factory(name, doc, namespace="unit")
    second = factory(name, doc, namespace="unit")
    assert first is second
    if hasattr(first, "inc"):
        first.inc()
    if hasattr(first, "set"):
        first.set(1)


def test_histogram_buckets_and_export():
    """Histograms honor provided buckets and export via Prometheus format."""
    name = _unique_name("hist")
    hist = metrics.safe_histogram(
        name, "histogram test", buckets=[0.1, 1.0], namespace="unit"
    )
    hist.observe(0.5)
    output = generate_latest(REGISTRY).decode()
    assert f'unit_{name}_bucket{{le="0.1"}}' in output
    assert f'unit_{name}_bucket{{le="1.0"}}' in output
    assert f'unit_{name}_bucket{{le="+Inf"}}' in output


def test_noop_metrics_do_not_raise(monkeypatch):
    """When prometheus client is unavailable, helpers should not explode."""
    monkeypatch.setattr(metrics, "_PROM_Counter", None)
    monkeypatch.setattr(metrics, "_PROM_Gauge", None)
    monkeypatch.setattr(metrics, "_PROM_Histogram", None)
    c = metrics.safe_counter(_unique_name("noop"), "doc")
    g = metrics.safe_gauge(_unique_name("noop"), "doc")
    h = metrics.safe_histogram(_unique_name("noop"), "doc")
    # These should be no-op objects that accept calls
    c.inc()
    g.set(1)
    h.observe(0.1)
