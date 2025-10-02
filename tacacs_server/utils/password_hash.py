"""
Secure password hashing utilities using bcrypt.
Replaces weak SHA-256 hashing with industry-standard bcrypt.
"""

import secrets

from .logger import get_logger

logger = get_logger(__name__)

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    logger.warning("bcrypt module not available. Install with: pip install bcrypt")
    BCRYPT_AVAILABLE = False


class PasswordHasher:
    """Secure password hashing using bcrypt."""
    
    DEFAULT_ROUNDS = 12  # Good balance of security and performance
    
    @classmethod
    def hash_password(cls, password: str, rounds: int | None = None) -> str:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Plain text password to hash
            rounds: Number of bcrypt rounds (default: 12)
            
        Returns:
            Bcrypt hash string
            
        Raises:
            RuntimeError: If bcrypt is not available
        """
        if not BCRYPT_AVAILABLE:
            raise RuntimeError("bcrypt module not available for secure password hashing")
        
        if rounds is None:
            rounds = cls.DEFAULT_ROUNDS
        
        # Ensure password is bytes
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
        
        # Generate salt and hash
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        return hashed.decode('utf-8')
    
    @classmethod
    def verify_password(cls, password: str, hashed: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password to verify
            hashed: Bcrypt hash to verify against
            
        Returns:
            True if password matches hash, False otherwise
        """
        if not BCRYPT_AVAILABLE:
            logger.error("bcrypt module not available for password verification")
            return False
        
        try:
            # Ensure inputs are bytes
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
            
            if isinstance(hashed, str):
                hashed_bytes = hashed.encode('utf-8')
            else:
                hashed_bytes = hashed
            
            return bcrypt.checkpw(password_bytes, hashed_bytes)
        
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    @classmethod
    def is_bcrypt_hash(cls, hashed: str) -> bool:
        """Check if a string is a bcrypt hash."""
        return hashed.startswith('$2a$') or hashed.startswith('$2b$') or hashed.startswith('$2y$')
    
    @classmethod
    def needs_rehash(cls, hashed: str, rounds: int | None = None) -> bool:
        """
        Check if a hash needs to be rehashed (e.g., due to increased rounds).
        
        Args:
            hashed: Existing hash to check
            rounds: Desired number of rounds (default: DEFAULT_ROUNDS)
            
        Returns:
            True if hash should be regenerated
        """
        if not BCRYPT_AVAILABLE:
            return False
        
        if rounds is None:
            rounds = cls.DEFAULT_ROUNDS
        
        try:
            # Extract rounds from existing hash
            if not cls.is_bcrypt_hash(hashed):
                return True  # Not a bcrypt hash, needs upgrade
            
            # Parse bcrypt hash format: $2a$rounds$salt+hash
            parts = hashed.split('$')
            if len(parts) < 4:
                return True
            
            current_rounds = int(parts[2])
            return current_rounds < rounds
        
        except Exception:
            return True  # If we can't parse it, rehash it


class LegacyPasswordMigrator:
    """Helper for migrating from legacy SHA-256 hashes to bcrypt."""
    
    @classmethod
    def is_legacy_hash(cls, hashed: str) -> bool:
        """Check if a hash is a legacy SHA-256 hash (64 hex characters)."""
        return len(hashed) == 64 and all(c in '0123456789abcdef' for c in hashed.lower())
    
    @classmethod
    def verify_legacy_password(cls, password: str, legacy_hash: str) -> bool:
        """Verify password against legacy SHA-256 hash."""
        import hashlib
        import warnings
        
        # SHA-256 for legacy compatibility only - not for new passwords
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            computed_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return secrets.compare_digest(computed_hash, legacy_hash)
    
    @classmethod
    def migrate_password(cls, password: str, legacy_hash: str) -> str | None:
        """
        Migrate a password from legacy SHA-256 to bcrypt.
        
        Args:
            password: Plain text password
            legacy_hash: Legacy SHA-256 hash
            
        Returns:
            New bcrypt hash if migration successful, None otherwise
        """
        # Verify the password matches the legacy hash
        if not cls.verify_legacy_password(password, legacy_hash):
            return None
        
        # Generate new bcrypt hash
        try:
            return PasswordHasher.hash_password(password)
        except RuntimeError:
            logger.error("Cannot migrate password: bcrypt not available")
            return None


def hash_password(password: str) -> str:
    """Convenience function for hashing passwords."""
    return PasswordHasher.hash_password(password)


def verify_password(password: str, hashed: str) -> bool:
    """
    Convenience function for verifying passwords.
    Supports both bcrypt and legacy SHA-256 hashes.
    """
    # Try bcrypt first
    if PasswordHasher.is_bcrypt_hash(hashed):
        return PasswordHasher.verify_password(password, hashed)
    
    # Fall back to legacy SHA-256 verification
    if LegacyPasswordMigrator.is_legacy_hash(hashed):
        logger.warning("Using legacy SHA-256 password verification - consider migrating to bcrypt")
        # Legacy SHA-256 support for backward compatibility only
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return LegacyPasswordMigrator.verify_legacy_password(password, hashed)
    
    logger.error(f"Unknown password hash format: {hashed[:20]}...")
    return False


def migrate_legacy_password(password: str, legacy_hash: str) -> str | None:
    """Convenience function for migrating legacy passwords."""
    return LegacyPasswordMigrator.migrate_password(password, legacy_hash)