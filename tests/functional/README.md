Functional tests

This suite contains functional, end-to-end tests grouped by subsystem.

Subfolders
- admin: Admin Web UI flows
- api: Admin REST API
- tacacs: TACACS+ protocol behaviors
- radius: RADIUS protocol behaviors

Notes
- Tests reuse shared fixtures in `tests/conftest.py`.
- Original test modules remain in `tests/` for reference; discovery is scoped to this folder.

