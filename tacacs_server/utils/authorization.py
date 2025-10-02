"""
Enhanced authorization utilities
"""
import re


class CommandMatcher:
    """Enhanced command matching with regex support"""
    
    def __init__(self):
        self.patterns: dict[int, list[re.Pattern]] = {}
    
    def add_patterns(self, privilege_level: int, patterns: list[str]):
        """Add command patterns for privilege level"""
        compiled_patterns = []
        for pattern in patterns:
            if pattern.startswith('regex:'):
                compiled_patterns.append(re.compile(pattern[6:]))
            else:
                # Convert shell-style wildcards to regex
                regex_pattern = pattern.replace('*', '.*').replace('?', '.')
                compiled_patterns.append(re.compile(f'^{regex_pattern}$'))
        self.patterns[privilege_level] = compiled_patterns
    
    def is_authorized(self, command: str, user_privilege: int) -> bool:
        """Check if command is authorized for user privilege level"""
        # Check from user's privilege level up to 15
        for priv_level in range(user_privilege, 16):
            if priv_level in self.patterns:
                for pattern in self.patterns[priv_level]:
                    if pattern.match(command):
                        return True
        return False
    
    def get_allowed_commands(self, user_privilege: int) -> list[str]:
        """Get list of allowed command patterns for user"""
        allowed = []
        for priv_level in range(user_privilege, 16):
            if priv_level in self.patterns:
                allowed.extend([p.pattern for p in self.patterns[priv_level]])
        return allowed