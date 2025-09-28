"""
Local File-Based Authentication Backend
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any
from .base import AuthenticationBackend

logger = logging.getLogger(__name__)

class LocalAuthBackend(AuthenticationBackend):
    """Local file-based authentication backend"""
    
    def __init__(self, users_file: str = "config/users.json"):
        super().__init__("local")
        self.users_file = users_file
        self.users = self._load_users()
    
    def _load_users(self) -> Dict[str, Dict[str, Any]]:
        """Load users from JSON file"""
        try:
            with open(self.users_file, 'r') as f:
                users_data = json.load(f)
                logger.info(f"Loaded {len(users_data)} users from {self.users_file}")
                return users_data
        except FileNotFoundError:
            logger.warning(f"Users file {self.users_file} not found, creating default")
            return self._create_default_users()
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {self.users_file}: {e}")
            return self._create_default_users()
    
    def _create_default_users(self) -> Dict[str, Dict[str, Any]]:
        """Create default users file"""
        default_users = {
            "admin": {
                "password": "admin123",
                "password_hash": None,  # Plain text for demo
                "privilege_level": 15,
                "service": "exec",
                "shell_command": ["show", "configure", "debug", "enable"],
                "groups": ["administrators"],
                "enabled": True,
                "description": "Default administrator account"
            },
            "operator": {
                "password": "operator123",
                "password_hash": None,
                "privilege_level": 7,
                "service": "exec", 
                "shell_command": ["show", "configure"],
                "groups": ["operators"],
                "enabled": True,
                "description": "Network operator account"
            },
            "user": {
                "password": "user123",
                "password_hash": None,
                "privilege_level": 1,
                "service": "exec",
                "shell_command": ["show"],
                "groups": ["users"],
                "enabled": True,
                "description": "Default user account"
            }
        }
        
        try:
            # Create directory if it doesn't exist
            import os
            os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
            
            with open(self.users_file, 'w') as f:
                json.dump(default_users, f, indent=2)
            logger.info(f"Default users created in {self.users_file}")
        except Exception as e:
            logger.error(f"Could not create default users file: {e}")
        
        return default_users
    
    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        """Authenticate against local user database"""
        user_data = self.users.get(username)
        if not user_data:
            logger.debug(f"User {username} not found in local database")
            return False
        
        if not user_data.get('enabled', True):
            logger.info(f"User {username} is disabled")
            return False
        
        # Check password hash if available, otherwise plain text
        if user_data.get('password_hash'):
            return self._verify_password_hash(password, user_data['password_hash'])
        else:
            # Plain text comparison (for demo purposes)
            result = user_data.get('password') == password
            if result:
                logger.info(f"Authentication successful for {username}")
            else:
                logger.info(f"Authentication failed for {username}")
            return result
    
    def get_user_attributes(self, username: str) -> Dict[str, Any]:
        """Get user attributes"""
        user_data = self.users.get(username, {})
        # Remove password from returned attributes for security
        attrs = {k: v for k, v in user_data.items() if k not in ['password', 'password_hash']}
        return attrs
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change user password"""
        if not self.authenticate(username, old_password):
            return False
        
        try:
            self.users[username]['password'] = new_password
            # Optionally hash the password
            # self.users[username]['password_hash'] = self._hash_password(new_password)
            # self.users[username]['password'] = None
            
            self._save_users()
            logger.info(f"Password changed for user {username}")
            return True
        except Exception as e:
            logger.error(f"Failed to change password for {username}: {e}")
            return False
    
    def add_user(self, username: str, password: str, **attributes) -> bool:
        """Add new user"""
        if username in self.users:
            logger.warning(f"User {username} already exists")
            return False
        
        try:
            self.users[username] = {
                "password": password,
                "password_hash": None,
                "privilege_level": attributes.get('privilege_level', 1),
                "service": attributes.get('service', 'exec'),
                "shell_command": attributes.get('shell_command', ['show']),
                "groups": attributes.get('groups', ['users']),
                "enabled": attributes.get('enabled', True),
                "description": attributes.get('description', f'User {username}')
            }
            
            self._save_users()
            logger.info(f"User {username} added successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to add user {username}: {e}")
            return False
    
    def remove_user(self, username: str) -> bool:
        """Remove user"""
        if username not in self.users:
            return False
        
        try:
            del self.users[username]
            self._save_users()
            logger.info(f"User {username} removed")
            return True
        except Exception as e:
            logger.error(f"Failed to remove user {username}: {e}")
            return False
    
    def reload_users(self) -> bool:
        """Reload users from file"""
        try:
            self.users = self._load_users()
            logger.info("Users reloaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to reload users: {e}")
            return False
    
    def _save_users(self):
        """Save users to file"""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def _verify_password_hash(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return self._hash_password(password) == password_hash
    
    def is_available(self) -> bool:
        """Check if backend is available"""
        return bool(self.users)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get backend statistics"""
        enabled_users = sum(1 for user in self.users.values() if user.get('enabled', True))
        return {
            'total_users': len(self.users),
            'enabled_users': enabled_users,
            'disabled_users': len(self.users) - enabled_users,
            'users_file': self.users_file
        }