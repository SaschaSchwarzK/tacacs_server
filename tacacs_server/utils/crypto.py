from __future__ import annotations

import re
from typing import Any

from tacacs_server.utils.logger import get_logger

logger = get_logger(__name__)


def validate_pem_format(pem: Any, *, expected_label: str | None = None) -> bool:
    """
    Light-weight PEM format validator.

    Ensures the content is a string, contains BEGIN/END markers, and includes
    at least one newline (so single-line env exports are caught).
    """
    if not isinstance(pem, str):
        return False
    pem_str = pem.strip()
    if not pem_str or "\n" not in pem_str:
        return False

    match = re.match(r"-----BEGIN ([^-]+)-----", pem_str)
    if not match:
        return False

    label = match.group(1)
    if expected_label and label != expected_label:
        return False

    end_marker = f"-----END {label}-----"
    if not pem_str.endswith(end_marker):
        return False

    # Quick sanity: body should be base64-ish
    begin_marker = match.group(0)
    body_content = pem_str[len(begin_marker) : -len(end_marker)]
    body = "".join(line.strip() for line in body_content.splitlines() if line.strip())
    return bool(body) and all(c.isalnum() or c in "+/=" for c in body)


__all__ = ["validate_pem_format"]
