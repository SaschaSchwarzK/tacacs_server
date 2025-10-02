"""
LDAP Authentication Backend
"""

from typing import Any

from tacacs_server.utils.logger import get_logger

from .base import AuthenticationBackend

logger = get_logger(__name__)

try:
    import ldap3
    LDAP_AVAILABLE = True
except ImportError:
    logger.warning("ldap3 module not available. Install with: pip install ldap3")
    LDAP_AVAILABLE = False

class LDAPAuthBackend(AuthenticationBackend):
    """LDAP authentication backend"""
    
    def __init__(self, ldap_server: str, base_dn: str, user_attribute: str = 'uid',
                 bind_dn: str | None = None, bind_password: str | None = None,
                 use_tls: bool = False, timeout: int = 10):
        super().__init__("ldap")
        self.ldap_server = ldap_server
        self.base_dn = base_dn
        self.user_attribute = user_attribute
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.use_tls = use_tls
        self.timeout = timeout
        
        # Default privilege mappings based on group membership
        self.group_privilege_map = {
            'administrators': 15,
            'network-admins': 15,
            'operators': 7,
            'users': 1
        }
        
        # Default command mappings
        self.privilege_commands = {
            15: ['show', 'configure', 'debug', 'enable', 'disable'],
            7: ['show', 'configure'],
            1: ['show']
        }
    
    def authenticate(self, username: str, password: str, **kwargs) -> bool:
        """Authenticate against LDAP server"""
        if not LDAP_AVAILABLE:
            logger.error("LDAP authentication unavailable - ldap3 module not installed")
            return False
        
        try:
            # Create server connection
            server = ldap3.Server(
                self.ldap_server,
                use_ssl=self.use_tls,
                connect_timeout=self.timeout
            )
            
            # Build user DN
            if self.bind_dn and self.bind_password:
                # Use service account to search for user
                user_dn = self._find_user_dn(username)
                if not user_dn:
                    logger.debug(f"User {username} not found in LDAP directory")
                    return False
            else:
                # Direct bind - construct DN from username
                user_dn = f"{self.user_attribute}={username},{self.base_dn}"
            
            # Attempt to bind with user credentials
            with ldap3.Connection(server, user_dn, password) as conn:
                if conn.bind():
                    logger.info(f"LDAP authentication successful for {username}")
                    return True
                else:
                    logger.info(f"LDAP authentication failed for {username}")
                    return False
                    
        except ldap3.core.exceptions.LDAPException as e:
            logger.error(f"LDAP authentication error for {username}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected LDAP error for {username}: {e}")
            return False
    
    def get_user_attributes(self, username: str) -> dict[str, Any]:
        """Get user attributes from LDAP"""
        if not LDAP_AVAILABLE:
            return {}
        
        try:
            user_info = self._get_ldap_user_info(username)
            if not user_info:
                return {}
            
            # Extract groups
            groups = self._extract_groups(user_info)
            
            # Determine privilege level based on group membership
            privilege_level = self._determine_privilege_level(groups)
            
            # Get allowed commands based on privilege level
            shell_command = self.privilege_commands.get(privilege_level, ['show'])
            
            return {
                'privilege_level': privilege_level,
                'service': 'exec',
                'shell_command': shell_command,
                'groups': groups,
                'full_name': user_info.get('displayName', username),
                'email': user_info.get('mail', ''),
                'department': user_info.get('department', ''),
                'title': user_info.get('title', ''),
                'enabled': True
            }
            
        except Exception as e:
            logger.error(f"Error getting LDAP attributes for {username}: {e}")
            return {}
    
    def _find_user_dn(self, username: str) -> str | None:
        """Find user DN using service account"""
        if not LDAP_AVAILABLE:
            return None
        
        try:
            server = ldap3.Server(self.ldap_server, use_ssl=self.use_tls)
            
            with ldap3.Connection(server, self.bind_dn, self.bind_password) as conn:
                if not conn.bind():
                    logger.error("Failed to bind with service account")
                    return None
                
                search_filter = f"({self.user_attribute}={username})"
                conn.search(
                    search_base=self.base_dn,
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=['dn']
                )
                
                if conn.entries:
                    return str(conn.entries[0].entry_dn)
                
        except Exception as e:
            logger.error(f"Error finding user DN for {username}: {e}")
        
        return None
    
    def _get_ldap_user_info(self, username: str) -> dict[str, Any] | None:
        """Get detailed user information from LDAP"""
        if not LDAP_AVAILABLE:
            return None
        
        try:
            server = ldap3.Server(self.ldap_server, use_ssl=self.use_tls)
            
            # Use service account if available, otherwise anonymous bind
            if self.bind_dn and self.bind_password:
                connection = ldap3.Connection(server, self.bind_dn, self.bind_password)
            else:
                connection = ldap3.Connection(server)
            
            with connection as conn:
                if not conn.bind():
                    logger.error("Failed to bind to LDAP server")
                    return None
                
                # Search for user
                search_filter = f"({self.user_attribute}={username})"
                conn.search(
                    search_base=self.base_dn,
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=['*']
                )
                
                if not conn.entries:
                    return None
                
                entry = conn.entries[0]
                user_info = {}
                
                # Extract attributes
                for attr in entry.entry_attributes:
                    values = entry[attr].values
                    if len(values) == 1:
                        user_info[attr] = values[0]
                    else:
                        user_info[attr] = values
                
                return user_info
                
        except Exception as e:
            logger.error(f"Error getting LDAP user info for {username}: {e}")
        
        return None
    
    def _extract_groups(self, user_info: dict[str, Any]) -> list:
        """Extract group memberships from user info"""
        groups = []
        
        # Common group attributes
        group_attrs = ['memberOf', 'groups', 'groupMembership']
        
        for attr in group_attrs:
            if attr in user_info:
                group_dns = user_info[attr]
                if isinstance(group_dns, str):
                    group_dns = [group_dns]
                
                for group_dn in group_dns:
                    # Extract CN from DN
                    # (e.g., "CN=administrators,OU=Groups,DC=example,DC=com")
                    if group_dn.upper().startswith('CN='):
                        cn_part = group_dn.split(',')[0]
                        group_name = cn_part[3:].lower()  # Remove "CN=" prefix
                        groups.append(group_name)
        
        return groups
    
    def _determine_privilege_level(self, groups: list) -> int:
        """Determine privilege level based on group membership"""
        highest_privilege = 1  # Default privilege level
        
        for group in groups:
            group_lower = group.lower()
            if group_lower in self.group_privilege_map:
                privilege = self.group_privilege_map[group_lower]
                if privilege > highest_privilege:
                    highest_privilege = privilege
        
        return highest_privilege
    
    def is_available(self) -> bool:
        """Check if LDAP backend is available"""
        if not LDAP_AVAILABLE:
            return False
        
        try:
            server = ldap3.Server(self.ldap_server, connect_timeout=5)
            with ldap3.Connection(server) as conn:
                return conn.bind()
        except Exception:
            return False
    
    def test_connection(self) -> dict[str, Any]:
        """Test LDAP connection and return status"""
        result = {
            'available': False,
            'server': self.ldap_server,
            'base_dn': self.base_dn,
            'error': None
        }
        
        if not LDAP_AVAILABLE:
            result['error'] = "ldap3 module not available"
            return result
        
        try:
            server = ldap3.Server(self.ldap_server, connect_timeout=5)
            
            if self.bind_dn and self.bind_password:
                with ldap3.Connection(server, self.bind_dn, self.bind_password) as conn:
                    if conn.bind():
                        result['available'] = True
                        result['bind_type'] = 'service_account'
                    else:
                        result['error'] = "Service account bind failed"
            else:
                with ldap3.Connection(server) as conn:
                    if conn.bind():
                        result['available'] = True
                        result['bind_type'] = 'anonymous'
                    else:
                        result['error'] = "Anonymous bind failed"
                        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def set_group_privilege_mapping(self, group_mappings: dict[str, int]):
        """Set custom group to privilege level mappings"""
        self.group_privilege_map.update(group_mappings)
        logger.info(f"Updated group privilege mappings: {group_mappings}")
    
    def set_privilege_commands(self, privilege_mappings: dict[int, list]):
        """Set custom privilege level to commands mappings"""
        self.privilege_commands.update(privilege_mappings)
        logger.info(f"Updated privilege command mappings: {privilege_mappings}")
    
    def get_stats(self) -> dict[str, Any]:
        """Get backend statistics"""
        connection_test = self.test_connection()
        return {
            'ldap_server': self.ldap_server,
            'base_dn': self.base_dn,
            'user_attribute': self.user_attribute,
            'use_tls': self.use_tls,
            'available': connection_test['available'],
            'bind_type': connection_test.get('bind_type', 'none'),
            'error': connection_test.get('error')
        }
