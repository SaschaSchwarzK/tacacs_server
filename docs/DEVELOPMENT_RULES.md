1. 📘 Code Documentation
	•	Docstrings are mandatory for all:
	•	Modules
	•	Classes
	•	Methods
	•	Functions
	•	Use Google-style or PEP 257 docstrings.
	•	Include:
	•	Description of functionality
	•	Arguments and types
	•	Return type
	•	Raised exceptions
	•	Examples when applicable

Example:
```python
def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate a user using configured authentication backends.

    Args:
        username (str): The username to authenticate.
        password (str): The user's password.

    Returns:
        bool: True if authentication succeeded, otherwise False.

    Raises:
        AuthenticationError: If backend communication fails.
    """
```

2. 💬 Comments
	•	Comment why, not what.
	•	Use comments to clarify complex logic, configuration, or edge cases.
	•	Keep comments concise and relevant; outdated comments must be removed.

⸻

3. 🧪 Testing Requirements

Every piece of functionality must be covered by tests.

✅ General Rules
	•	Tests live under tests/ and mirror the module structure.
	•	Use pytest with clear naming conventions:
	•	test_<functionality>.py
	•	Individual test names start with test_
	•	Each test must:
	•	Have a description (docstring or comment) explaining:
	•	What is being tested
	•	How it is tested
	•	Expected outcome

Example:

```python
def test_authenticate_valid_user():
    """
    Test that a valid username and password authenticate successfully.
    Expectation: The function returns True.
    """
    assert authenticate_user("admin", "correct-password") is True
```

⚖️ Positive and Negative Testing
	•	Positive tests confirm correct behavior for valid input.
	•	Negative tests verify that errors or invalid input are handled properly.

🧩 Coverage & Tools
	•	Minimum test coverage: 90%
	•	Run coverage reports locally before PRs:

```bash
poetry run pytest --cov=tacacs_server --cov-report=term-missing
```

4. 🧹 Linting & Formatting

All code must pass automated linting and formatting checks.

🧰 Tools
	•	Ruff — Linting and formatting (ruff check . && ruff format .)
	•	Mypy — Static typing validation (mypy tacacs_server)
	•	Bandit — Security checks (bandit -r tacacs_server)
	•	Pytest — Functional/unit/integration tests

⚙️ Pre-commit Setup

Install the pre-commit hooks to ensure all checks run automatically before commits:

```bash
poetry run pre-commit install
```

Example .pre-commit-config.yaml (simplified):

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.11.1
    hooks:
      - id: mypy
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.8
    hooks:
      - id: bandit
```

. 🔒 Security
	•	Avoid hardcoded credentials, secrets, or tokens.
	•	All secrets must come from environment variables or secure vaults.
	•	Never log passwords, tokens, or sensitive configuration data.
	•	Use parameterized queries for database access.
	•	Bandit must pass with no medium or high severity findings.

⸻

6. 🧠 Typing
	•	All public functions and methods must include type annotations.
	•	The code must pass:

```bash
poetry run mypy tacacs_server --strict
```

7. 🧩 Pull Request Standards
	•	One logical change per PR.
	•	Include:
	•	A clear summary of what changed and why.
	•	Reference to related issue or feature request.
	•	Confirmation that all checks (lint, test, typing, security) pass.

Checklist for PRs:
	•	All code has docstrings and comments
	•	Tests added for new or changed functionality
	•	All tests pass locally
	•	Ruff, Mypy, Bandit checks pass
	•	No performance regressions or hardcoded data

⸻

8. 🧑‍💻 Code Review

All PRs undergo code review (GitHub) before merging.

Reviewers verify that:
	•	The code is readable, maintainable, and secure
	•	It follows architecture and design patterns used in the project
	•	All checks pass in CI
	•	Documentation and tests are complete

⸻

9. 💡 Additional Recommendations
	•	Use async/await where appropriate for I/O.
	•	Keep functions short and cohesive.
	•	Apply SOLID principles where applicable.
	•	Avoid circular imports; use dependency injection patterns.
	•	All CLI commands must have help text (--help).
	•	Prefer pathlib over os.path and logging over print.
