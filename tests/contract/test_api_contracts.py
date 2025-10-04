"""
API Contract Testing Suite for TACACS+ Server

Tests API contracts using Pact for consumer-driven contract testing
and JSON Schema validation.

Installation:
    pip install pact-python jsonschema schemathesis hypothesis

Usage:
    # Run contract tests
    pytest tests/contract/test_api_contracts.py -v

    # Generate Pact files
    pytest tests/contract/test_api_contracts.py --pact-publish

    # Property-based testing
    pytest tests/contract/test_api_contracts.py --hypothesis-show-statistics
"""

import json
from datetime import datetime
from typing import Any

import pytest
import requests
from jsonschema import ValidationError, validate

# ============================================================================
# JSON Schema Definitions
# ============================================================================


class APISchemas:
    """JSON Schema definitions for API responses"""

    # User Schema
    USER_SCHEMA = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 3, "maxLength": 50},
            "enabled": {"type": "boolean"},
            "privilege_level": {"type": "integer", "minimum": 0, "maximum": 15},
            "groups": {"type": "array", "items": {"type": "string"}},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
        "required": ["username", "enabled"],
        "additionalProperties": True,
    }

    # Device Schema
    DEVICE_SCHEMA = {
        "type": "object",
        "properties": {
            "id": {"type": "integer", "minimum": 1},
            "name": {"type": "string", "minLength": 1, "maxLength": 100},
            "ip_address": {
                "type": "string",
                "oneOf": [{"format": "ipv4"}, {"format": "ipv6"}],
            },
            "device_group_id": {"type": "integer", "minimum": 1},
            "device_group_name": {"type": "string"},
            "enabled": {"type": "boolean"},
            "metadata": {"type": "object"},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
        },
        "required": ["id", "name", "ip_address", "device_group_id", "enabled"],
        "additionalProperties": False,
    }

    # Device Group Schema
    DEVICE_GROUP_SCHEMA = {
        "type": "object",
        "properties": {
            "id": {"type": "integer", "minimum": 1},
            "name": {"type": "string", "minLength": 1, "maxLength": 100},
            "description": {"type": ["string", "null"]},
            "tacacs_secret_set": {"type": "boolean"},
            "radius_secret_set": {"type": "boolean"},
            "allowed_user_groups": {"type": "array", "items": {"type": "integer"}},
            "device_count": {"type": "integer", "minimum": 0},
            "created_at": {"type": "string", "format": "date-time"},
        },
        "required": ["id", "name"],
        "additionalProperties": False,
    }

    # Authentication Response Schema
    AUTH_RESPONSE_SCHEMA = {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "username": {"type": "string"},
            "privilege_level": {"type": "integer", "minimum": 0, "maximum": 15},
            "groups": {"type": "array", "items": {"type": "string"}},
            "message": {"type": "string"},
        },
        "required": ["success"],
        "additionalProperties": True,
    }

    # Server Status Schema
    STATUS_SCHEMA = {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["running", "starting", "stopped"]},
            "uptime_seconds": {"type": "number", "minimum": 0},
            "version": {"type": "string"},
            "tacacs": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "active_connections": {"type": "integer", "minimum": 0},
                    "total_requests": {"type": "integer", "minimum": 0},
                    "success_rate": {"type": "number", "minimum": 0, "maximum": 100},
                },
                "required": ["enabled", "port"],
            },
            "radius": {
                "type": "object",
                "properties": {
                    "enabled": {"type": "boolean"},
                    "auth_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                    "acct_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                },
            },
        },
        "required": ["status", "uptime_seconds"],
        "additionalProperties": True,
    }

    # Error Response Schema
    ERROR_SCHEMA = {
        "type": "object",
        "properties": {
            "error": {"type": "string", "minLength": 1},
            "details": {"type": ["string", "object", "null"]},
            "timestamp": {"type": "string", "format": "date-time"},
        },
        "required": ["error"],
        "additionalProperties": True,
    }

    # Paginated Response Schema
    PAGINATED_SCHEMA = {
        "type": "object",
        "properties": {
            "items": {"type": "array"},
            "total": {"type": "integer", "minimum": 0},
            "page": {"type": "integer", "minimum": 1},
            "page_size": {"type": "integer", "minimum": 1},
            "total_pages": {"type": "integer", "minimum": 0},
        },
        "required": ["items", "total"],
        "additionalProperties": False,
    }


# ============================================================================
# Contract Test Base Class
# ============================================================================


class ContractTest:
    """Base class for contract testing"""

    BASE_URL = "http://localhost:8080"
    HEADERS = {"Accept": "application/json"}

    def validate_schema(self, data: Any, schema: dict):
        """Validate data against JSON schema"""
        try:
            validate(instance=data, schema=schema)
            return True
        except ValidationError as e:
            pytest.fail(f"Schema validation failed: {e.message}")
            return False

    def validate_response_structure(
        self,
        response: requests.Response,
        expected_status: int,
        schema: dict | None = None,
    ):
        """Validate response structure"""
        # Status code
        assert response.status_code == expected_status, (
            f"Expected {expected_status}, got {response.status_code}"
        )

        # Content-Type
        content_type = response.headers.get("Content-Type", "")
        assert "application/json" in content_type, (
            f"Expected JSON response, got {content_type}"
        )

        # Valid JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            pytest.fail("Response is not valid JSON")

        # Schema validation
        if schema:
            self.validate_schema(data, schema)

        return data


# ============================================================================
# User API Contract Tests
# ============================================================================


class TestUserAPIContract(ContractTest):
    """Contract tests for User API"""

    @pytest.fixture(autouse=True)
    def setup_server(self, tacacs_server):
        """Use server fixture"""
        self.server_info = tacacs_server

    @pytest.mark.contract
    def test_list_users_contract(self):
        """Verify GET /admin/users contract"""
        response = requests.get(
            f"{self.BASE_URL}/admin/users", headers=self.HEADERS, timeout=10
        )

        data = self.validate_response_structure(
            response,
            expected_status=200,
            schema={
                "type": "object",
                "properties": {
                    "users": {"type": "array", "items": APISchemas.USER_SCHEMA}
                },
                "required": ["users"],
            },
        )

        # Contract assertions
        assert isinstance(data["users"], list), "Response must be an array"

    @pytest.mark.contract
    def test_create_user_contract(self):
        """Verify POST /admin/users contract"""
        new_user = {
            "username": f"contract_test_user_{datetime.now().timestamp()}",
            "password": "SecurePass123!",
            "email": "contract@example.com",
            "enabled": True,
        }

        response = requests.post(
            f"{self.BASE_URL}/admin/users",
            json=new_user,
            headers=self.HEADERS,
            timeout=10,
        )

        data = self.validate_response_structure(
            response,
            expected_status=201,
            schema={
                "type": "object",
                "properties": {"username": {"type": "string"}},
                "required": ["username"],
            },
        )

        # Verify returned data matches input
        assert data["username"] == new_user["username"]

    @pytest.mark.contract
    def test_update_user_contract(self):
        """Verify PUT /admin/users/{id} contract"""
        # Create a user first
        {
            "username": f"update_test_{datetime.now().timestamp()}",
            "password": "SecurePass123!",
            "email": "update@example.com",
            "enabled": True,
        }
