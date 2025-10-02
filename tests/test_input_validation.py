"""
Tests for input validation security features.
"""

import pytest

from tacacs_server.utils.exceptions import ValidationError
from tacacs_server.utils.sql_security import ParameterizedQuery
from tacacs_server.utils.validation import FormValidator, InputValidator


class TestInputValidator:
    """Test InputValidator class."""
    
    def test_validate_username_valid(self):
        """Test valid username validation."""
        assert InputValidator.validate_username("user123") == "user123"
        assert InputValidator.validate_username("test_user") == "test_user"
        assert InputValidator.validate_username("admin.user") == "admin.user"
        assert InputValidator.validate_username("user-name") == "user-name"
    
    def test_validate_username_invalid(self):
        """Test invalid username validation."""
        with pytest.raises(ValidationError, match="Username is required"):
            InputValidator.validate_username("")
        
        with pytest.raises(ValidationError, match="Username cannot be empty"):
            InputValidator.validate_username("   ")
        
        with pytest.raises(ValidationError, match="64 characters or less"):
            InputValidator.validate_username("a" * 65)
        
        with pytest.raises(ValidationError, match="can only contain"):
            InputValidator.validate_username("user@domain")
        
        with pytest.raises(ValidationError, match="can only contain"):
            InputValidator.validate_username("admin'; DROP TABLE users; --")
    
    def test_validate_password_valid(self):
        """Test valid password validation."""
        password = InputValidator.validate_password("Password123")
        assert password == "Password123"
    
    def test_validate_password_invalid(self):
        """Test invalid password validation."""
        with pytest.raises(ValidationError, match="Password is required"):
            InputValidator.validate_password("")
        
        with pytest.raises(ValidationError, match="at least 8 characters"):
            InputValidator.validate_password("short")
        
        with pytest.raises(ValidationError, match="128 characters or less"):
            InputValidator.validate_password("a" * 129)
        
        with pytest.raises(ValidationError, match="uppercase, lowercase, and numeric"):
            InputValidator.validate_password("password")  # No uppercase or numbers
        
        with pytest.raises(ValidationError, match="uppercase, lowercase, and numeric"):
            InputValidator.validate_password("PASSWORD123")  # No lowercase
    
    def test_validate_network_valid(self):
        """Test valid network validation."""
        network = InputValidator.validate_network("192.168.1.0/24")
        assert str(network) == "192.168.1.0/24"
        
        network = InputValidator.validate_network("10.0.0.1")
        assert str(network) == "10.0.0.1/32"
    
    def test_validate_network_invalid(self):
        """Test invalid network validation."""
        with pytest.raises(ValidationError, match="Network is required"):
            InputValidator.validate_network("")
        
        with pytest.raises(ValidationError, match="Invalid network format"):
            InputValidator.validate_network("invalid")
    
    def test_validate_privilege_level_valid(self):
        """Test valid privilege level validation."""
        assert InputValidator.validate_privilege_level(0) == 0
        assert InputValidator.validate_privilege_level("15") == 15
        assert InputValidator.validate_privilege_level(7) == 7
    
    def test_validate_privilege_level_invalid(self):
        """Test invalid privilege level validation."""
        with pytest.raises(ValidationError, match="must be a number"):
            InputValidator.validate_privilege_level("invalid")
        
        with pytest.raises(ValidationError, match="between 0 and 15"):
            InputValidator.validate_privilege_level(-1)
        
        with pytest.raises(ValidationError, match="between 0 and 15"):
            InputValidator.validate_privilege_level(16)
    
    def test_validate_secret_valid(self):
        """Test valid secret validation."""
        secret = InputValidator.validate_secret("mysecret123")
        assert secret == "mysecret123"
    
    def test_validate_secret_invalid(self):
        """Test invalid secret validation."""
        with pytest.raises(ValidationError, match="secret is required"):
            InputValidator.validate_secret("")
        
        with pytest.raises(ValidationError, match="at least 8 characters"):
            InputValidator.validate_secret("short")
        
        with pytest.raises(ValidationError, match="potentially unsafe"):
            InputValidator.validate_secret("secret'; DROP TABLE devices; --")
    
    def test_validate_string_list_valid(self):
        """Test valid string list validation."""
        result = InputValidator.validate_string_list(["item1", "item2"])
        assert result == ["item1", "item2"]
        
        result = InputValidator.validate_string_list("item1,item2,item3")
        assert result == ["item1", "item2", "item3"]
        
        result = InputValidator.validate_string_list(None)
        assert result == []
    
    def test_validate_string_list_invalid(self):
        """Test invalid string list validation."""
        with pytest.raises(ValidationError, match="must be a list"):
            InputValidator.validate_string_list(123)
        
        with pytest.raises(ValidationError, match="must be strings"):
            InputValidator.validate_string_list([123, "valid"])
        
        with pytest.raises(ValidationError, match="255 characters or less"):
            InputValidator.validate_string_list(["a" * 256])
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection."""
        malicious_inputs = [
            "admin'; DROP TABLE users; --",
            "1 OR 1=1",
            "admin' UNION SELECT * FROM passwords --",
            "'; INSERT INTO users VALUES ('hacker', 'pass'); --"
        ]
        
        for malicious in malicious_inputs:
            with pytest.raises(ValidationError, match="can only contain"):
                InputValidator.validate_username(malicious)
    
    def test_ldap_injection_detection(self):
        """Test LDAP injection character detection."""
        malicious_inputs = [
            "admin*",
            "user(cn=*)",
            "test\\user",
            "admin/user"
        ]
        
        for malicious in malicious_inputs:
            with pytest.raises(ValidationError, match="invalid character"):
                InputValidator.validate_string_list([malicious])
    
    def test_sanitize_log_input(self):
        """Test log input sanitization."""
        # Normal input should pass through
        assert InputValidator.sanitize_log_input("normal text") == "normal text"
        
        # Control characters should be removed
        malicious = "test\x00\x01\x02\ninjection"
        sanitized = InputValidator.sanitize_log_input(malicious)
        assert "\x00" not in sanitized
        assert "\n" not in sanitized
        
        # Long input should be truncated
        long_input = "a" * 2000
        sanitized = InputValidator.sanitize_log_input(long_input)
        assert len(sanitized) <= 1000
        assert sanitized.endswith("...")


class TestFormValidator:
    """Test FormValidator class."""
    
    def test_validate_device_form_valid(self):
        """Test valid device form validation."""
        data = {
            "name": "router1",
            "network": "192.168.1.0/24",
            "group": "routers"
        }
        
        result = FormValidator.validate_device_form(data)
        assert result["name"] == "router1"
        assert result["network"] == "192.168.1.0/24"
        assert result["group"] == "routers"
    
    def test_validate_user_form_valid(self):
        """Test valid user form validation."""
        data = {
            "username": "testuser",
            "password": "Password123",
            "privilege_level": 7,
            "service": "exec",
            "groups": ["users", "operators"],
            "enabled": True
        }
        
        result = FormValidator.validate_user_form(data)
        assert result["username"] == "testuser"
        assert result["password"] == "Password123"
        assert result["privilege_level"] == 7
        assert result["groups"] == ["users", "operators"]
    
    def test_validate_group_form_valid(self):
        """Test valid group form validation."""
        data = {
            "name": "test-group",
            "description": "Test group",
            "tacacs_secret": "tacacs_secret123",
            "radius_secret": "radius_secret123",
            "allowed_user_groups": ["users", "admins"]
        }
        
        result = FormValidator.validate_group_form(data)
        assert result["name"] == "test-group"
        assert result["tacacs_secret"] == "tacacs_secret123"
        assert result["allowed_user_groups"] == ["users", "admins"]


class TestParameterizedQuery:
    """Test ParameterizedQuery class."""
    
    def test_validate_identifier_valid(self):
        """Test valid identifier validation."""
        assert ParameterizedQuery.validate_identifier("users") == "users"
        assert ParameterizedQuery.validate_identifier("user_table") == "user_table"
        assert ParameterizedQuery.validate_identifier("table123") == "table123"
    
    def test_validate_identifier_invalid(self):
        """Test invalid identifier validation."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            ParameterizedQuery.validate_identifier("")
        
        with pytest.raises(ValidationError, match="too long"):
            ParameterizedQuery.validate_identifier("a" * 65)
        
        with pytest.raises(ValidationError, match="invalid characters"):
            ParameterizedQuery.validate_identifier("table-name")
        
        with pytest.raises(ValidationError, match="reserved keyword"):
            ParameterizedQuery.validate_identifier("DROP")
    
    def test_build_select_query(self):
        """Test SELECT query building."""
        query, params = ParameterizedQuery.build_select(
            "users", 
            ["username", "email"],
            {"active": True, "role": "admin"},
            order_by="username",
            limit=10
        )
        
        expected_query = (
            "SELECT username, email FROM users WHERE active = ? AND role = ? "
            "ORDER BY username LIMIT 10"
        )
        assert query == expected_query
        assert params == [True, "admin"]
    
    def test_build_insert_query(self):
        """Test INSERT query building."""
        query, params = ParameterizedQuery.build_insert(
            "users",
            {"username": "testuser", "email": "test@example.com", "active": True}
        )
        
        assert "INSERT INTO users" in query
        assert "VALUES (?, ?, ?)" in query
        assert len(params) == 3
        assert "testuser" in params
    
    def test_build_update_query(self):
        """Test UPDATE query building."""
        query, params = ParameterizedQuery.build_update(
            "users",
            {"email": "new@example.com", "active": False},
            {"username": "testuser"}
        )
        
        expected_query = "UPDATE users SET email = ?, active = ? WHERE username = ?"
        assert query == expected_query
        assert params == ["new@example.com", False, "testuser"]
    
    def test_build_delete_query(self):
        """Test DELETE query building."""
        query, params = ParameterizedQuery.build_delete(
            "users",
            {"username": "testuser", "active": False}
        )
        
        expected_query = "DELETE FROM users WHERE username = ? AND active = ?"
        assert query == expected_query
        assert params == ["testuser", False]
    
    def test_sql_injection_prevention(self):
        """Test SQL injection prevention in queries."""
        malicious_table = "users; DROP TABLE passwords; --"
        
        with pytest.raises(ValidationError):
            ParameterizedQuery.build_select(malicious_table, ["username"])
        
        malicious_column = "username'; DROP TABLE users; --"
        
        with pytest.raises(ValidationError):
            ParameterizedQuery.build_select("users", [malicious_column])


if __name__ == "__main__":
    pytest.main([__file__])