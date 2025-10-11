# Contributing

Thank you for your interest in contributing to this project!

## Development setup
- Python 3.13+
- Poetry for dependency management: `poetry install`
- Run checks locally:
  - `poetry run ruff check . && poetry run ruff format --check .`
  - `poetry run mypy .`
  - `poetry run pytest -q`

## Branching & commits
- Create feature branches from `develop`.
- Keep commits focused and include a clear message.

## Tests
- Add tests for new features and bug fixes.
- Prefer property-based tests (Hypothesis) for protocol parsing and validation.
- Keep CI green.

## Security
- Do not include secrets in code or tests.
- Use bcrypt for admin/user passwords; legacy hashes are rejected/rehash on login.

## Reporting issues
- Use GitHub Issues with a minimal reproducer and logs where possible.
