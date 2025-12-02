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
    if not pem_str:
        return False

    if expected_label:
        begin = f"-----BEGIN {expected_label}-----"
        end = f"-----END {expected_label}-----"
        if not (pem_str.startswith(begin) and pem_str.endswith(end)):
            return False
    else:
        # Generic check allowing any PEM label (including hyphens)
        if not (
            re.match(r"-----BEGIN [^-]+?-----", pem_str)
            and re.search(r"-----END [^-]+?-----", pem_str)
        ):
            return False

    # Require at least one real newline to avoid single-line env issues
    if "\n" not in pem_str:
        return False

    # Quick sanity: body should be base64-ish
    body = re.sub(r"-----BEGIN .*?-----", "", pem_str)
    body = re.sub(r"-----END .*?-----", "", body)
    body = "".join(line.strip() for line in body.splitlines() if line.strip())
    return bool(body) and all(c.isalnum() or c in "+/=" for c in body)


__all__ = ["validate_pem_format"]
