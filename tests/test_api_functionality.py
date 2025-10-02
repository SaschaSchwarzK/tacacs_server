"""
Tests for API functionality without requiring FastAPI TestClient
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from tacacs_server.web.admin.routers import (
    create_device,
    create_group,
    create_user,
    create_user_group,
    delete_device,
    get_device,
    get_group_details,
    get_server_logs,
    get_server_status,
    get_user_details,
    get_user_group_details,
    reload_server_config,
    reset_server_stats,
    set_user_password,
    update_config,
    update_device,
)


class TestServerControlAPI:
    """Test server control API functions"""
    
    @pytest.mark.asyncio
    async def test_reload_server_config(self):
        """Test config reload functionality"""
        with patch(
            'tacacs_server.web.admin.routers.monitoring_get_tacacs_server'
        ) as mock_get_server:
            mock_server = Mock()
            mock_server.reload_configuration.return_value = True
            mock_get_server.return_value = mock_server
            
            result = await reload_server_config()
            assert result["success"] is True
            assert "Configuration reloaded" in result["message"]
    
    @pytest.mark.asyncio
    async def test_reset_server_stats(self):
        """Test stats reset functionality"""
        with patch(
            'tacacs_server.web.admin.routers.monitoring_get_tacacs_server'
        ) as mock_get_server:
            mock_server = Mock()
            mock_server.reset_stats = Mock()
            mock_get_server.return_value = mock_server
            
            result = await reset_server_stats()
            assert result["success"] is True
            assert "Statistics reset" in result["message"]
            mock_server.reset_stats.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_server_logs(self):
        """Test server logs retrieval"""
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.readlines.return_value = [
                "2024-01-01 12:00:00 - INFO - Server started\n",
                "2024-01-01 12:01:00 - INFO - User authenticated\n"
            ]
            
            result = await get_server_logs(lines=10)
            assert "logs" in result
            assert result["count"] == 2
            assert len(result["logs"]) == 2
    
    @pytest.mark.asyncio
    async def test_get_server_status(self):
        """Test server status retrieval"""
        with patch(
            'tacacs_server.web.admin.routers.monitoring_get_tacacs_server'
        ) as mock_get_tacacs, \
             patch(
                 'tacacs_server.web.admin.routers.monitoring_get_radius_server'
             ) as mock_get_radius:
            
            # Mock TACACS server
            mock_tacacs = Mock()
            mock_tacacs.running = True
            mock_tacacs.get_stats.return_value = {
                'connections_active': 5,
                'connections_total': 100,
                'auth_requests': 50,
                'auth_success': 45,
                'auth_failures': 5
            }
            mock_tacacs.get_health_status.return_value = {
                'uptime_seconds': 3600
            }
            mock_get_tacacs.return_value = mock_tacacs
            
            # Mock RADIUS server
            mock_radius = Mock()
            mock_radius.get_stats.return_value = {
                'running': True,
                'auth_requests': 10,
                'auth_accepts': 8,
                'auth_rejects': 2
            }
            mock_get_radius.return_value = mock_radius
            
            result = await get_server_status()
            assert "tacacs" in result
            assert result["tacacs"]["running"] is True
            assert "radius" in result
            assert result["radius"]["enabled"] is True


class TestDeviceAPI:
    """Test device management API functions"""
    
    @pytest.mark.asyncio
    async def test_create_device(self):
        """Test device creation"""
        with patch(
            'tacacs_server.web.admin.routers.get_device_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_device = Mock()
            mock_device.id = 1
            mock_service.create_device.return_value = mock_device
            mock_get_service.return_value = mock_service
            
            # payload = {"name": "router1", "network": "192.168.1.0/24"}  # Unused
            from fastapi import Request
            mock_request = Mock(spec=Request)
            result = await create_device(mock_request, mock_service)
            assert result["id"] == 1
            mock_service.create_device.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_device(self):
        """Test device retrieval"""
        with patch(
            'tacacs_server.web.admin.routers.get_device_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_device = Mock()
            mock_device.id = 1
            mock_device.name = "router1"
            mock_device.network = "192.168.1.0/24"
            mock_device.group = None
            mock_service.get_device.return_value = mock_device
            mock_get_service.return_value = mock_service
            
            result = await get_device(1, mock_service)
            assert result["id"] == 1
            assert result["name"] == "router1"
    
    @pytest.mark.asyncio
    async def test_update_device(self):
        """Test device update"""
        with patch(
            'tacacs_server.web.admin.routers.get_device_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_device = Mock()
            mock_device.id = 1
            mock_service.update_device.return_value = mock_device
            mock_get_service.return_value = mock_service
            
            payload = {"name": "router1-updated"}
            from fastapi import Request
            mock_request = Mock(spec=Request)
            mock_request.json = AsyncMock(return_value=payload)
            result = await update_device(mock_request, 1, mock_service)
            assert result["id"] == 1
    
    @pytest.mark.asyncio
    async def test_delete_device(self):
        """Test device deletion"""
        with patch(
            'tacacs_server.web.admin.routers.get_device_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_service.delete_device.return_value = True
            mock_get_service.return_value = mock_service
            
            from fastapi import Request
            mock_request = Mock(spec=Request)
            result = await delete_device(mock_request, 1, mock_service)
            assert result is None  # 204 No Content
            mock_service.delete_device.assert_called_once_with(1)


class TestGroupAPI:
    """Test device group management API functions"""
    
    @pytest.mark.asyncio
    async def test_create_group(self):
        """Test group creation"""
        with patch(
            'tacacs_server.web.admin.routers.get_device_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_group = Mock()
            mock_group.id = 1
            mock_service.create_group.return_value = mock_group
            mock_get_service.return_value = mock_service
            
            payload = {"name": "routers", "description": "Router group"}
            from fastapi import Request
            mock_request = Mock(spec=Request)
            mock_request.json = AsyncMock(return_value=payload)
            result = await create_group(mock_request, mock_service)
            assert result["id"] == 1
    
    @pytest.mark.asyncio
    async def test_get_group_details(self):
        """Test group retrieval"""
        with patch(
            'tacacs_server.web.admin.routers.get_device_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_group = Mock()
            mock_group.id = 1
            mock_group.name = "routers"
            mock_group.description = "Router group"
            mock_group.metadata = {}
            mock_group.radius_secret = None
            mock_group.tacacs_secret = None
            mock_group.device_config = None
            mock_group.allowed_user_groups = []
            mock_service.get_group.return_value = mock_group
            mock_get_service.return_value = mock_service
            
            result = await get_group_details(1, mock_service)
            assert result["id"] == 1
            assert result["name"] == "routers"


class TestUserAPI:
    """Test user management API functions"""
    
    @pytest.mark.asyncio
    async def test_create_user(self):
        """Test user creation"""
        with patch(
            'tacacs_server.web.admin.routers.get_user_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_user = Mock()
            mock_user.username = "testuser"
            mock_service.create_user.return_value = mock_user
            mock_get_service.return_value = mock_service
            
            payload = {
                "username": "testuser",
                "password": "Password123",
                "privilege_level": 1
            }
            from fastapi import Request
            mock_request = Mock(spec=Request)
            mock_request.json = AsyncMock(return_value=payload)
            result = await create_user(mock_request, mock_service)
            assert result["username"] == "testuser"
    
    @pytest.mark.asyncio
    async def test_get_user_details(self):
        """Test user retrieval"""
        with patch(
            'tacacs_server.web.admin.routers.get_user_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_user = Mock()
            mock_user.username = "testuser"
            mock_user.privilege_level = 1
            mock_user.service = "exec"
            mock_user.shell_command = ["show"]
            mock_user.groups = ["users"]
            mock_user.enabled = True
            mock_user.description = None
            mock_service.get_user.return_value = mock_user
            mock_get_service.return_value = mock_service
            
            result = await get_user_details("testuser", mock_service)
            assert result["username"] == "testuser"
            assert result["privilege_level"] == 1
    
    @pytest.mark.asyncio
    async def test_set_user_password(self):
        """Test user password update"""
        with patch(
            'tacacs_server.web.admin.routers.get_user_service'
        ) as mock_get_service, \
             patch('tacacs_server.web.admin.routers.InputValidator') as mock_validator:
            
            mock_service = Mock()
            mock_user = Mock()
            mock_user.username = "testuser"
            mock_service.set_password.return_value = mock_user
            mock_get_service.return_value = mock_service
            
            mock_validator.validate_username.return_value = "testuser"
            mock_validator.validate_password.return_value = "NewPassword123"
            
            payload = {"password": "NewPassword123"}
            from fastapi import Request
            mock_request = Mock(spec=Request)
            mock_request.json = AsyncMock(return_value=payload)
            result = await set_user_password(mock_request, "testuser", mock_service)
            assert result["username"] == "testuser"


class TestUserGroupAPI:
    """Test user group management API functions"""
    
    @pytest.mark.asyncio
    async def test_create_user_group(self):
        """Test user group creation"""
        with patch(
            'tacacs_server.web.admin.routers.get_user_group_service'
        ) as mock_get_service, \
             patch('tacacs_server.web.admin.routers._parse_int') as mock_parse_int:
            
            mock_service = Mock()
            mock_group = Mock()
            mock_group.name = "admins"
            mock_service.create_group.return_value = mock_group
            mock_get_service.return_value = mock_service
            mock_parse_int.return_value = 15
            
            payload = {
                "name": "admins",
                "description": "Administrator group",
                "privilege_level": 15
            }
            from fastapi import Request
            mock_request = Mock(spec=Request)
            mock_request.json = AsyncMock(return_value=payload)
            result = await create_user_group(mock_request, mock_service)
            assert result["name"] == "admins"
    
    @pytest.mark.asyncio
    async def test_get_user_group_details(self):
        """Test user group retrieval"""
        with patch(
            'tacacs_server.web.admin.routers.get_user_group_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_group = Mock()
            mock_group.name = "admins"
            mock_group.description = "Administrator group"
            mock_group.metadata = {}
            mock_group.ldap_group = None
            mock_group.okta_group = None
            mock_group.privilege_level = 15
            mock_service.get_group.return_value = mock_group
            mock_get_service.return_value = mock_service
            
            result = await get_user_group_details("admins", mock_service)
            assert result["name"] == "admins"
            assert result["privilege_level"] == 15


class TestConfigurationAPI:
    """Test configuration management API functions"""
    
    @pytest.mark.asyncio
    async def test_update_config(self):
        """Test configuration update"""
        with patch(
            'tacacs_server.web.admin.routers.monitoring_get_config'
        ) as mock_get_config:
            mock_config = Mock()
            mock_config.update_server_config = Mock()
            mock_config.update_auth_config = Mock()
            mock_config.update_ldap_config = Mock()
            mock_get_config.return_value = mock_config
            
            payload = {
                "server": {"host": "0.0.0.0", "port": "49"},
                "auth": {"backends": "local"},
                "ldap": {"server": "ldap://localhost"}
            }
            
            from fastapi import Request
            mock_request = Mock(spec=Request)
            mock_request.json = AsyncMock(return_value=payload)
            result = await update_config(mock_request)
            assert result["success"] is True
            assert "Configuration updated" in result["message"]
            
            mock_config.update_server_config.assert_called_once_with(
                host="0.0.0.0", port="49"
            )
            mock_config.update_auth_config.assert_called_once_with(backends="local")
            mock_config.update_ldap_config.assert_called_once_with(server="ldap://localhost")


class TestErrorHandling:
    """Test API error handling"""
    
    @pytest.mark.asyncio
    async def test_server_unavailable(self):
        """Test handling when server is unavailable"""
        from fastapi import HTTPException
        
        with patch(
            'tacacs_server.web.admin.routers.monitoring_get_tacacs_server'
        ) as mock_get_server:
            mock_get_server.return_value = None
            
            with pytest.raises(HTTPException) as exc_info:
                await reload_server_config()
            
            assert exc_info.value.status_code == 503
            assert "TACACS server unavailable" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_device_not_found(self):
        """Test handling when device is not found"""
        from fastapi import HTTPException

        from tacacs_server.devices.service import DeviceNotFound
        
        with patch(
            'tacacs_server.web.admin.routers.get_device_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_service.get_device.side_effect = DeviceNotFound("Device not found")
            mock_get_service.return_value = mock_service
            
            with pytest.raises(HTTPException) as exc_info:
                await get_device(999, mock_service)
            
            assert exc_info.value.status_code == 404
    
    @pytest.mark.asyncio
    async def test_validation_error(self):
        """Test handling validation errors"""
        from fastapi import HTTPException

        from tacacs_server.devices.service import DeviceValidationError
        
        with patch(
            'tacacs_server.web.admin.routers.get_device_service'
        ) as mock_get_service:
            mock_service = Mock()
            mock_service.create_device.side_effect = DeviceValidationError(
                "Invalid data"
            )
            mock_get_service.return_value = mock_service
            
            with pytest.raises(HTTPException) as exc_info:
                from fastapi import Request
                mock_request = Mock(spec=Request)
                mock_request.json = AsyncMock(
                    return_value={"name": "", "network": "invalid"}
                )
                await create_device(mock_request, mock_service)
            
            assert exc_info.value.status_code == 422


if __name__ == "__main__":
    pytest.main([__file__])