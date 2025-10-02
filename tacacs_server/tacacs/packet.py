"""
TACACS+ Packet Structure and Encryption Handling
"""

import hashlib
import struct
import warnings

from .constants import TAC_PLUS_FLAGS, TAC_PLUS_HEADER_SIZE, TAC_PLUS_VERSION


class TacacsPacket:
    """TACACS+ packet structure"""
    
    def __init__(self, version=TAC_PLUS_VERSION, packet_type=0, seq_no=0, flags=0, 
                 session_id=0, length=0, body=b''):
        self.version = version
        self.packet_type = packet_type
        self.seq_no = seq_no
        self.flags = flags
        self.session_id = session_id
        self.length = length
        self.body = body
    
    def pack_header(self) -> bytes:
        """Pack TACACS+ header into bytes"""
        return struct.pack('!BBBBLL', 
                          self.version, self.packet_type, self.seq_no,
                          self.flags, self.session_id, self.length)
    
    @classmethod
    def unpack_header(cls, data: bytes) -> 'TacacsPacket':
        """Unpack TACACS+ header from bytes.
        
        Args:
            data: Raw packet data containing at least the header
            
        Returns:
            TacacsPacket instance with header fields populated
            
        Raises:
            ValueError: If data is too short or contains invalid values
            struct.error: If data format is invalid
        """
        if len(data) < TAC_PLUS_HEADER_SIZE:
            raise ValueError(
                f"Invalid packet header length: {len(data)} < {TAC_PLUS_HEADER_SIZE}"
            )
        
        try:
            version, packet_type, seq_no, flags, session_id, length = struct.unpack(
                '!BBBBLL', data[:TAC_PLUS_HEADER_SIZE]
            )
        except struct.error as e:
            raise ValueError(f"Failed to unpack header: {e}") from e
        
        # Validate packet length to prevent buffer overflow
        if length > 65535:  # Maximum reasonable packet size
            raise ValueError(f"Packet length too large: {length}")
        
        return cls(version, packet_type, seq_no, flags, session_id, length)
    
    def pack(self, key: str = '') -> bytes:
        """Pack complete packet with optional encryption"""
        encrypted_body = self.encrypt_body(key)
        self.length = len(encrypted_body)
        return self.pack_header() + encrypted_body
    
    def encrypt_body(self, key: str) -> bytes:
        """Encrypt packet body using MD5-based encryption"""
        if not key or self.flags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG:
            return self.body
        
        pad = self._generate_pad(key, len(self.body))
        return bytes(a ^ b for a, b in zip(self.body, pad))
    
    def decrypt_body(self, key: str, encrypted_body: bytes) -> bytes:
        """Decrypt packet body"""
        if not key or self.flags & TAC_PLUS_FLAGS.TAC_PLUS_UNENCRYPTED_FLAG:
            return encrypted_body
        
        pad = self._generate_pad(key, len(encrypted_body))
        return bytes(a ^ b for a, b in zip(encrypted_body, pad))
    
    def _generate_pad(self, key: str, length: int) -> bytes:
        """Generate encryption pad using MD5 as specified by TACACS+ RFC 8907.
        
        Note: MD5 is used here as required by the TACACS+ protocol specification,
        not for general cryptographic purposes. This is protocol-mandated legacy.
        
        Args:
            key: Shared secret key for encryption
            length: Required pad length in bytes
            
        Returns:
            Encryption pad bytes of specified length
        """
        if length <= 0:
            return b''
            
        pad = b''
        # Pre-compute static components for efficiency
        session_id_bytes = struct.pack('!L', self.session_id)
        key_bytes = key.encode('utf-8')
        version_bytes = bytes([self.version])
        seq_no_bytes = bytes([self.seq_no])
        base_input = session_id_bytes + key_bytes + version_bytes + seq_no_bytes
        
        while len(pad) < length:
            md5_input = base_input + (pad if pad else b'')
            
            # MD5 required by TACACS+ RFC 8907 - not for general cryptographic use
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                pad += hashlib.md5(md5_input).digest()
        
        return pad[:length]
    
    def __str__(self) -> str:
        """String representation for debugging"""
        return (f"TacacsPacket(version=0x{self.version:02x}, type={self.packet_type}, "
                f"seq={self.seq_no}, flags=0x{self.flags:02x}, "
                f"session=0x{self.session_id:08x}, length={self.length})")
    
    def __repr__(self) -> str:
        return self.__str__()