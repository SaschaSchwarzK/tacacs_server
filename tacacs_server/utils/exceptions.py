"""
Custom exceptions for TACACS+ server
"""

class TacacsException(Exception):
    """Base TACACS+ exception"""
    pass

class AuthenticationError(TacacsException):
    """Authentication specific error"""
    pass

class AuthorizationError(TacacsException):
    """Authorization specific error"""
    pass

class ConfigurationError(TacacsException):
    """Configuration specific error"""
    pass

class DatabaseError(TacacsException):
    """Database specific error"""
    pass

class ValidationError(TacacsException):
    """Input validation error"""
    pass