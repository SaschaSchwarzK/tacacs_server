"""
Generate OpenAPI JSON and write it to docs/openapi.json.

Usage:
  poetry run python scripts/generate_openapi.py
"""

from __future__ import annotations

import json
from pathlib import Path

from tacacs_server.web.app_setup import create_app, setup_routes
from tacacs_server.web.openapi_config import custom_openapi_schema


def main() -> int:
    app = create_app()
    # Install example routes to ensure tags and models are present
    try:
        setup_routes(app)
    except Exception:
        # Routes may be provided elsewhere; ignore if setup fails
        pass
    # Use our custom schema generator
    app.openapi = lambda: custom_openapi_schema(app)  # type: ignore[assignment]

    schema = app.openapi()
    out_dir = Path("docs")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "openapi.json"
    out_file.write_text(json.dumps(schema, indent=2))
    print(f"Wrote OpenAPI schema to {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
