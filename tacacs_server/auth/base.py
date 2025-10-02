"""
Abstract Authentication Backend Base Class
"""

from abc import ABC, abstractmethod
from typing import Any


class AuthenticationBackend(ABC):
    """Abstract authentication backend"""
    
    def __init__(self, name: str):
        self.name = name
    
    @abstractmethod
    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        """
        Authenticate user credentials
        
        Args:
            username: Username to authenticate
            password: Password to verify
            **kwargs: Additional authentication parameters
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        pass
    
    @abstractmethod
    def get_user_attributes(self, username: str) -> dict[str, Any]:
        """
        Get user attributes for authorization
        
        Args:
            username: Username to get attributes for
            
        Returns:
            Dict containing user attributes like privilege_level, groups, etc.
        """
        pass
    
    def is_available(self) -> bool:
        """
        Check if backend is available and configured properly
        
        Returns:
            bool: True if backend is ready to use
        """
        return True
    
    def validate_user(self, username: str) -> bool:
        """
        Check if user exists in backend (without password verification)
        
        Args:
            username: Username to validate
            
        Returns:
            bool: True if user exists
        """
        try:
            attrs = self.get_user_attributes(username)
            return bool(attrs)
        except Exception:
            return False
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """
        Change user password (if supported by backend)
        
        Args:
            username: Username
            old_password: Current password
            new_password: New password
            
        Returns:
            bool: True if password changed successfully
        """
        return False  # Not supported by default
    
    def get_user_groups(self, username: str) -> list:
        """
        Get user group memberships
        
        Args:
            username: Username
            
        Returns:
            list: List of group names user belongs to
        """
        attrs = self.get_user_attributes(username)
        return attrs.get('groups', [])
    
    def get_privilege_level(self, username: str) -> int:
        """
        Get user privilege level
        
        Args:
            username: Username
            
        Returns:
            int: Privilege level (0-15)
        """
        attrs = self.get_user_attributes(username)
        return attrs.get('privilege_level', 1)
    
    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"
    
    def __repr__(self) -> str:
        return self.__str__()