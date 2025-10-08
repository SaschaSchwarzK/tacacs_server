"""
Export the OpenAPI schema served by the TACACS+ web app to a local file.

This script builds the FastAPI monitoring app (without starting servers),
generates the OpenAPI schema, and writes it to `docs/openapi.json` so it can
be browsed on GitHub and used by client generators.

Usage:
    poetry run python scripts/export_openapi.py

Optional env:
    OUTPUT_PATH: override output path (default: docs/openapi.json)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from tacacs_server.web.monitoring import TacacsMonitoringAPI


def export_schema(output_path: str = "docs/openapi.json") -> str:
    # Build monitoring web app with no running TACACS/RADIUS servers
    api = TacacsMonitoringAPI(tacacs_server=None, radius_server=None)
    app = api.app

    # Ensure OpenAPI is generated via our custom schema
    schema = app.openapi()  # type: ignore[call-arg]

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        json.dump(schema, fh, indent=2, ensure_ascii=False)
    return str(out.resolve())


if __name__ == "__main__":
    dest = os.environ.get("OUTPUT_PATH", "docs/openapi.json")
    path = export_schema(dest)
    print(f"✔ OpenAPI schema exported to: {path}")

