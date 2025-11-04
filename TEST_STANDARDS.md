# Test Documentation Standards

This document outlines the standards for writing and documenting tests in the TACACS+ server project.

## Test File Structure

Each test file should follow this structure:

1. **Module Docstring**:
   - Brief description of what's being tested
   - Test organization within the file
   - Any important setup requirements

2. **Test Functions**:
   - Clear, descriptive names (test_*)
   - Docstrings following the standard format
   - Isolated test cases (one assertion per test when possible)

## Test Documentation Format

### Module-Level Docstring

```python
"""[Component] Test Suite

This module contains [unit/integration/functional] tests for [component].
It verifies [key functionality, edge cases, error conditions].

Test Organization:
- Category 1
- Category 2
- Edge Cases
- Error Conditions

Each test is isolated and creates its own test fixtures to ensure
independence and reliability.
"""
```

### Test Function Docstring

```python
def test_feature_under_condition():
    """[Concise summary of what's being tested]
    
    [Detailed description of the test case, including any relevant context]

    Test Steps:
    1. [Step 1 description]
    2. [Step 2 description]
    3. [Step 3 description]

    Expected Results:
    - [Expected outcome 1]
    - [Expected outcome 2]
    - [Any side effects or state changes]
    
    Edge Cases/Notes:
    - [Any special conditions or edge cases being tested]
    - [Dependencies or assumptions]
    """
```

## Best Practices

1. **Test Naming**:
   - Use `test_` prefix
   - Follow pattern: `test_[what]_[condition]_[expected]`
   - Example: `test_radius_auth_invalid_credentials_fails`

2. **Assertions**:
   - One logical assertion per test
   - Use descriptive assertion messages
   - Prefer specific assertions over generic ones

3. **Test Data**:
   - Use realistic test data
   - Keep tests independent and isolated
   - Clean up after tests

4. **Documentation**:
   - Document why, not just what
   - Include edge cases in docstrings
   - Note any test dependencies

## Example Test File

```python
"""TACACS+ Authentication Test Suite

This module contains functional tests for TACACS+ authentication.
It verifies successful logins, authentication failures, and edge cases.

Test Organization:
- Basic Authentication
- Error Conditions
- Edge Cases
- Performance

Each test creates an isolated server instance with temporary resources.
"""

def test_tacacs_auth_success(server_factory):
    """Test successful TACACS+ authentication with valid credentials.
    
    Verifies that a user can authenticate with correct credentials
    and receives the appropriate privilege level.

    Test Steps:
    1. Start TACACS+ server with test user
    2. Send authentication request with valid credentials
    3. Verify successful authentication

    Expected Results:
    - Authentication succeeds (return code 0)
    - User receives correct privilege level
    - Session is properly established
    
    Edge Cases/Notes:
    - Tests both username and password validation
    - Verifies privilege level assignment
    """
    # Test implementation...
```

## Linting and Style

- Follow PEP 8 style guide
- Use type hints for better IDE support
- Keep line length under 100 characters
- Use descriptive variable names
- Add comments for complex logic

## Test Organization

- Group related tests in the same file
- Use test classes when appropriate
- Keep tests focused and fast
- Avoid test interdependencies
