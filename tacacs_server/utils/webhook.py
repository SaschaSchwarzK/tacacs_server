from __future__ import annotations

import json
import os
import threading
import urllib.request
from collections.abc import Callable
from typing import Any, cast

from .logger import get_logger

logger = get_logger(__name__)


class WebhookConfig:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.headers: dict[str, str] = {"Content-Type": "application/json"}
        self.template: dict[str, Any] | None = None
        self.timeout: float = float(os.getenv("WEBHOOK_TIMEOUT", "3"))
        self.threshold_count: int = int(
            os.getenv("THRESHOLD_AUTH_FAIL_COUNT", "0") or 0
        )
        self.threshold_window: int = int(os.getenv("THRESHOLD_WINDOW_SEC", "60") or 60)
        self._load_from_env()

    def _load_from_env(self) -> None:
        single = os.getenv("WEBHOOK_URL")
        if single:
            self.urls.append(single)
        multi = os.getenv("WEBHOOK_URLS")
        if multi:
            self.urls.extend([u.strip() for u in multi.split(",") if u.strip()])
        hdrs = os.getenv("WEBHOOK_HEADERS")
        if hdrs:
            try:
                self.headers.update(json.loads(hdrs))
            except Exception as exc:
                logger.warning("Failed to render webhook template: %s", exc)
        tmpl = os.getenv("WEBHOOK_TEMPLATE")
        if tmpl:
            try:
                self.template = json.loads(tmpl)
            except Exception:
                self.template = None


_cfg = WebhookConfig()
_sender: Callable[[str, dict[str, Any], float], None] | None = None
_fail_counts: dict[str, list[float]] = {}


def set_webhook_config(
    urls: list[str] | None = None,
    headers: dict[str, str] | None = None,
    template: dict[str, Any] | None = None,
    timeout: float | None = None,
    threshold_count: int | None = None,
    threshold_window: int | None = None,
) -> None:
    if urls is not None:
        _cfg.urls = list(urls)
    if headers is not None:
        _cfg.headers = dict(headers)
    if template is not None:
        _cfg.template = dict(template)
    if timeout is not None:
        _cfg.timeout = float(timeout)
    if threshold_count is not None:
        _cfg.threshold_count = int(threshold_count)
    if threshold_window is not None:
        _cfg.threshold_window = int(threshold_window)


def get_webhook_config_dict() -> dict[str, Any]:
    """Return current webhook configuration as a serializable dict."""
    return {
        "urls": list(_cfg.urls),
        "headers": dict(_cfg.headers),
        "template": _cfg.template or {},
        "timeout": _cfg.timeout,
        "threshold_count": _cfg.threshold_count,
        "threshold_window": _cfg.threshold_window,
    }


def _render_payload(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    if _cfg.template:
        # simple template with placeholder replacement for flat keys
        try:
            tmpl_json = json.dumps(_cfg.template)
            merged = dict(payload)
            merged.setdefault("event", event)
            for k, v in list(merged.items()):
                tmpl_json = tmpl_json.replace(f"{{{{{k}}}}}", str(v))
            result = cast(dict[str, Any], json.loads(tmpl_json))
            # Ensure canonical 'event' key is present for downstream consumers/tests
            result.setdefault("event", event)
            return result
        except Exception as exc:
            logger.warning("Failed to notify threshold webhook: %s", exc)
    out = dict(payload)
    out.setdefault("event", event)
    return out


def _post(url: str, payload: dict[str, Any], timeout: float) -> None:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers=_cfg.headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            resp.read(1)
    except Exception as e:
        logger.warning("Webhook delivery failed to %s: %s", url, e)


def set_webhook_sender(
    sender: Callable[[str, dict[str, Any], float], None] | None,
) -> None:
    """Override the transport used to send webhooks.

    Tests can inject a local in-process sender to avoid network constraints
    and capture payloads reliably. Pass None to restore default HTTP sender.
    """
    global _sender
    _sender = sender


def notify(event: str, payload: dict[str, Any]) -> None:
    if not _cfg.urls:
        return
    body = _render_payload(event, payload)
    send_func = _sender or _post
    for url in _cfg.urls:
        threading.Thread(
            target=send_func, args=(url, body, _cfg.timeout), daemon=True
        ).start()


def record_event(
    event: str, key: str, now_func: Callable[[], float] | None = None
) -> None:
    """Record an event (e.g., auth_failure) keyed by username or IP and trigger threshold webhook.

    Controlled by THRESHOLD_AUTH_FAIL_COUNT and THRESHOLD_WINDOW_SEC.
    """
    if _cfg.threshold_count <= 0:
        return
    import time

    now = (now_func or time.time)()
    window = _cfg.threshold_window
    arr = _fail_counts.setdefault(key, [])
    arr[:] = [t for t in arr if now - t < window]
    arr.append(now)
    if len(arr) >= _cfg.threshold_count:
        try:
            notify(
                "threshold_exceeded",
                {"event": event, "key": key, "count": len(arr), "window_sec": window},
            )
        except Exception:
            pass
