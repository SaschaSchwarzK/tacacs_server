"""
Tests for Admin API endpoints
"""

from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from tacacs_server.auth.local_user_group_service import LocalUserGroupService
from tacacs_server.auth.local_user_service import LocalUserService
from tacacs_server.devices.service import DeviceService
from tacacs_server.web.admin.auth import AdminSessionManager
from tacacs_server.web.admin.routers import admin_router


@pytest.fixture
def mock_services():
    """Mock all required services"""
    with (
        patch(
            "tacacs_server.web.admin.routers.monitoring_get_device_service"
        ) as mock_device,
        patch(
            "tacacs_server.web.admin.routers.monitoring_get_local_user_service"
        ) as mock_user,
        patch(
            "tacacs_server.web.admin.routers.monitoring_get_local_user_group_service"
        ) as mock_user_group,
        patch(
            "tacacs_server.web.admin.routers.monitoring_get_tacacs_server"
        ) as mock_tacacs,
        patch(
            "tacacs_server.web.admin.routers.monitoring_get_radius_server"
        ) as mock_radius,
        patch("tacacs_server.web.admin.routers.monitoring_get_config") as mock_config,
        patch(
            "tacacs_server.web.admin.routers.get_admin_session_manager"
        ) as mock_session,
    ):
        # Mock device service
        device_service = Mock(spec=DeviceService)
        mock_device.return_value = device_service

        # Mock user service
        user_service = Mock(spec=LocalUserService)
        mock_user.return_value = user_service

        # Mock user group service
        user_group_service = Mock(spec=LocalUserGroupService)
        mock_user_group.return_value = user_group_service

        # Mock TACACS server
        tacacs_server = Mock()
        tacacs_server.running = True
        tacacs_server.get_stats.return_value = {
            "connections_active": 5,
            "connections_total": 100,
            "auth_requests": 50,
            "auth_success": 45,
            "auth_failures": 5,
        }
        tacacs_server.get_health_status.return_value = {
            "uptime_seconds": 3600,
            "memory_usage": {"rss_mb": 128},
        }
        tacacs_server.reload_configuration.return_value = True
        tacacs_server.get_active_sessions.return_value = []
        mock_tacacs.return_value = tacacs_server

        # Mock RADIUS server
        radius_server = Mock()
        radius_server.get_stats.return_value = {
            "running": True,
            "auth_requests": 10,
            "auth_accepts": 8,
            "auth_rejects": 2,
        }
        mock_radius.return_value = radius_server

        # Mock config
        config = Mock()
        config.get_config_summary.return_value = {"server": {"host": "0.0.0.0"}}
        config.update_server_config = Mock()
        config.config_source = "test_config.conf"
        config.config_file = "test_config.conf"
        mock_config.return_value = config

        # Mock session manager
        session_manager = Mock(spec=AdminSessionManager)
        session_manager.login.return_value = "test_token"
        session_manager.config = Mock()
        session_manager.config.session_timeout = Mock()
        session_manager.config.session_timeout.total_seconds.return_value = 3600
        mock_session.return_value = session_manager

        yield {
            "device_service": device_service,
            "user_service": user_service,
            "user_group_service": user_group_service,
            "tacacs_server": tacacs_server,
            "radius_server": radius_server,
            "config": config,
            "session_manager": session_manager,
        }


@pytest.fixture
def client():
    """Create test client"""
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(admin_router)
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Mock authentication headers"""
    return {"Cookie": "admin_session=test_token"}


class TestServerControlEndpoints:
    """Test server control API endpoints"""

    def test_reload_config(self, client, mock_services, auth_headers):
        """Test config reload endpoint"""
        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.post("/admin/server/reload-config", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "Configuration reloaded" in data["message"]

    def test_reset_stats(self, client, mock_services, auth_headers):
        """Test stats reset endpoint"""
        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.post("/admin/server/reset-stats", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "Statistics reset" in data["message"]

    def test_get_server_logs(self, client, mock_services, auth_headers):
        """Test server logs endpoint"""
        with (
            patch("tacacs_server.web.admin.routers.admin_guard"),
            patch("builtins.open", create=True) as mock_open,
        ):
            mock_open.return_value.__enter__.return_value.readlines.return_value = [
                "2024-01-01 12:00:00 - INFO - Server started\n",
                "2024-01-01 12:01:00 - INFO - User authenticated\n",
            ]

            response = client.get("/admin/server/logs?lines=10", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert "logs" in data
            assert data["count"] == 2

    def test_get_server_status(self, client, mock_services, auth_headers):
        """Test server status endpoint"""
        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.get("/admin/server/status", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert "tacacs" in data
            assert data["tacacs"]["running"] is True
            assert "radius" in data


class TestDeviceEndpoints:
    """Test device management API endpoints"""

    def test_create_device(self, client, mock_services, auth_headers):
        """Test device creation"""
        mock_device = Mock()
        mock_device.id = 1
        mock_services["device_service"].create_device.return_value = mock_device

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.post(
                "/admin/devices",
                json={"name": "router1", "network": "192.168.1.0/24"},
                headers=auth_headers,
            )
            assert response.status_code == 201
            data = response.json()
            assert data["id"] == 1

    def test_get_device(self, client, mock_services, auth_headers):
        """Test device retrieval"""
        mock_device = Mock()
        mock_device.id = 1
        mock_device.name = "router1"
        mock_device.network = "192.168.1.0/24"
        mock_device.group = None
        mock_services["device_service"].get_device.return_value = mock_device

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.get("/admin/devices/1", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "router1"

    def test_update_device(self, client, mock_services, auth_headers):
        """Test device update"""
        mock_device = Mock()
        mock_device.id = 1
        mock_services["device_service"].update_device.return_value = mock_device

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.put(
                "/admin/devices/1",
                json={"name": "router1-updated"},
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["id"] == 1

    def test_delete_device(self, client, mock_services, auth_headers):
        """Test device deletion"""
        mock_services["device_service"].delete_device.return_value = True

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.delete("/admin/devices/1", headers=auth_headers)
            assert response.status_code == 204

    def test_list_devices(self, client, mock_services, auth_headers):
        """Test device listing"""
        mock_device = Mock()
        mock_device.id = 1
        mock_device.name = "router1"
        mock_device.network = "192.168.1.0/24"
        mock_device.group = None
        mock_services["device_service"].list_devices.return_value = [mock_device]
        mock_services["device_service"].list_groups.return_value = []

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.get("/admin/devices?format=json", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert "devices" in data
            assert len(data["devices"]) == 1
            assert data["devices"][0]["name"] == "router1"


class TestGroupEndpoints:
    """Test device group management API endpoints"""

    def test_create_group(self, client, mock_services, auth_headers):
        """Test group creation"""
        mock_group = Mock()
        mock_group.id = 1
        mock_services["device_service"].create_group.return_value = mock_group

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.post(
                "/admin/groups",
                json={"name": "routers", "description": "Router group"},
                headers=auth_headers,
            )
            assert response.status_code == 201
            data = response.json()
            assert data["id"] == 1

    def test_get_group(self, client, mock_services, auth_headers):
        """Test group retrieval"""
        mock_group = Mock()
        mock_group.id = 1
        mock_group.name = "routers"
        mock_group.description = "Router group"
        mock_group.metadata = {}
        mock_group.radius_secret = None
        mock_group.tacacs_secret = None
        mock_group.device_config = None
        mock_group.allowed_user_groups = []
        mock_services["device_service"].get_group.return_value = mock_group

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.get("/admin/groups/1", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "routers"

    def test_update_group(self, client, mock_services, auth_headers):
        """Test group update"""
        mock_group = Mock()
        mock_group.id = 1
        mock_services["device_service"].update_group.return_value = mock_group

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.put(
                "/admin/groups/1",
                json={"description": "Updated description"},
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["id"] == 1

    def test_delete_group(self, client, mock_services, auth_headers):
        """Test group deletion"""
        mock_services["device_service"].delete_group.return_value = True

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.delete("/admin/groups/1", headers=auth_headers)
            assert response.status_code == 204


class TestUserEndpoints:
    """Test user management API endpoints"""

    def test_create_user(self, client, mock_services, auth_headers):
        """Test user creation"""
        mock_user = Mock()
        mock_user.username = "testuser"
        mock_services["user_service"].create_user.return_value = mock_user

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.post(
                "/admin/users",
                json={
                    "username": "testuser",
                    "password": "Password123",
                    "privilege_level": 1,
                },
                headers=auth_headers,
            )
            assert response.status_code == 201
            data = response.json()
            assert data["username"] == "testuser"

    def test_get_user(self, client, mock_services, auth_headers):
        """Test user retrieval"""
        mock_user = Mock()
        mock_user.username = "testuser"
        mock_user.privilege_level = 1
        mock_user.service = "exec"
        mock_user.shell_command = ["show"]
        mock_user.groups = ["users"]
        mock_user.enabled = True
        mock_user.description = None
        mock_services["user_service"].get_user.return_value = mock_user

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.get("/admin/users/testuser", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert data["username"] == "testuser"

    def test_update_user(self, client, mock_services, auth_headers):
        """Test user update"""
        mock_user = Mock()
        mock_user.username = "testuser"
        mock_services["user_service"].update_user.return_value = mock_user

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.put(
                "/admin/users/testuser",
                json={"privilege_level": 15},
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["username"] == "testuser"

    def test_set_user_password(self, client, mock_services, auth_headers):
        """Test user password update"""
        mock_user = Mock()
        mock_user.username = "testuser"
        mock_services["user_service"].set_password.return_value = mock_user

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.post(
                "/admin/users/testuser/password",
                json={"password": "NewPassword123"},
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["username"] == "testuser"

    def test_delete_user(self, client, mock_services, auth_headers):
        """Test user deletion"""
        mock_services["user_service"].delete_user.return_value = True

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.delete("/admin/users/testuser", headers=auth_headers)
            assert response.status_code == 204


class TestUserGroupEndpoints:
    """Test user group management API endpoints"""

    def test_create_user_group(self, client, mock_services, auth_headers):
        """Test user group creation"""
        mock_group = Mock()
        mock_group.name = "admins"
        mock_services["user_group_service"].create_group.return_value = mock_group

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.post(
                "/admin/user-groups",
                json={
                    "name": "admins",
                    "description": "Administrator group",
                    "privilege_level": 15,
                },
                headers=auth_headers,
            )
            assert response.status_code == 201
            data = response.json()
            assert data["name"] == "admins"

    def test_get_user_group(self, client, mock_services, auth_headers):
        """Test user group retrieval"""
        mock_group = Mock()
        mock_group.name = "admins"
        mock_group.description = "Administrator group"
        mock_group.metadata = {}
        mock_group.ldap_group = None
        mock_group.okta_group = None
        mock_group.privilege_level = 15
        mock_services["user_group_service"].get_group.return_value = mock_group

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.get("/admin/user-groups/admins", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "admins"

    def test_update_user_group(self, client, mock_services, auth_headers):
        """Test user group update"""
        mock_group = Mock()
        mock_group.name = "admins"
        mock_services["user_group_service"].update_group.return_value = mock_group

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.put(
                "/admin/user-groups/admins",
                json={"description": "Updated description"},
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "admins"

    def test_delete_user_group(self, client, mock_services, auth_headers):
        """Test user group deletion"""
        mock_services["user_group_service"].delete_group.return_value = True

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.delete("/admin/user-groups/admins", headers=auth_headers)
            assert response.status_code == 204


class TestConfigurationEndpoints:
    """Test configuration management API endpoints"""

    def test_view_config(self, client, mock_services, auth_headers):
        """Test configuration viewing"""
        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.get("/admin/config?format=json", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert "configuration" in data or "source" in data

    def test_update_config(self, client, mock_services, auth_headers):
        """Test configuration update"""
        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.put(
                "/admin/config",
                json={
                    "server": {"host": "0.0.0.0", "port": "49"},
                    "auth": {"backends": "local"},
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True


class TestAuthenticationEndpoints:
    """Test authentication API endpoints"""

    def test_login_success(self, client, mock_services):
        """Test successful login"""
        response = client.post(
            "/admin/login",
            json={"username": "admin", "password": "password"},
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_logout(self, client, mock_services, auth_headers):
        """Test logout"""
        response = client.post(
            "/admin/logout", headers={**auth_headers, "Accept": "application/json"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True


class TestValidationErrors:
    """Test API validation and error handling"""

    def test_invalid_device_data(self, client, mock_services, auth_headers):
        """Test device creation with invalid data"""
        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.post(
                "/admin/devices",
                json={"name": "", "network": "invalid"},
                headers=auth_headers,
            )
            assert response.status_code == 422

    def test_invalid_user_data(self, client, mock_services, auth_headers):
        """Test user creation with invalid data"""
        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.post(
                "/admin/users",
                json={"username": "", "password": "Weak123"},
                headers=auth_headers,
            )
            assert response.status_code == 422

    def test_nonexistent_resource(self, client, mock_services, auth_headers):
        """Test accessing nonexistent resources"""
        from tacacs_server.devices.service import DeviceNotFound

        mock_services["device_service"].get_device.side_effect = DeviceNotFound(
            "Device not found"
        )

        with patch("tacacs_server.web.admin.routers.admin_guard"):
            response = client.get("/admin/devices/999", headers=auth_headers)
            assert response.status_code == 404


if __name__ == "__main__":
    pytest.main([__file__])
