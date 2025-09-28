"""
TACACS+ Packet Structure and Encryption Handling
"""

import struct
import hashlib
from typing import Optional
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
        """Unpack TACACS+ header from bytes"""
        if len(data) < TAC_PLUS_HEADER_SIZE:
            raise ValueError(f"Invalid packet header length: {len(data)} < {TAC_PLUS_HEADER_SIZE}")
        
        version, packet_type, seq_no, flags, session_id, length = struct.unpack(
            '!BBBBLL', data[:TAC_PLUS_HEADER_SIZE]
        )
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
        """Generate encryption pad using MD5"""
        pad = b''
        session_id_bytes = struct.pack('!L', self.session_id)
        key_bytes = key.encode('utf-8')
        version_bytes = bytes([self.version])
        seq_no_bytes = bytes([self.seq_no])
        
        while len(pad) < length:
            if len(pad) == 0:
                # First iteration: session_id + key + version + seq_no
                md5_input = session_id_bytes + key_bytes + version_bytes + seq_no_bytes
            else:
                # Subsequent iterations: session_id + key + version + seq_no + previous_pad
                md5_input = session_id_bytes + key_bytes + version_bytes + seq_no_bytes + pad
            
            pad += hashlib.md5(md5_input).digest()
        
        return pad[:length]
    
    def __str__(self) -> str:
        """String representation for debugging"""
        return (f"TacacsPacket(version=0x{self.version:02x}, type={self.packet_type}, "
                f"seq={self.seq_no}, flags=0x{self.flags:02x}, "
                f"session=0x{self.session_id:08x}, length={self.length})")
    
    def __repr__(self) -> str:
        return self.__str__()