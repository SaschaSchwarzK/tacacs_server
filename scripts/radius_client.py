#!/usr/bin/env python3
"""
RADIUS Test Client

Usage: python test_radius_client.py [server] [port] [secret] [username] [password]
"""

import socket
import hashlib
import struct
import secrets
import sys

def create_access_request(username: str, password: str, 
                         identifier: int, secret: bytes) -> bytes:
    """Create RADIUS Access-Request packet"""
    
    # Generate random authenticator
    authenticator = secrets.token_bytes(16)
    
    # Create attributes
    attributes = b''
    
    # User-Name attribute
    username_bytes = username.encode('utf-8')
    attributes += struct.pack('BB', 1, len(username_bytes) + 2) + username_bytes
    
    # User-Password attribute (encrypted)
    password_bytes = password.encode('utf-8')
    # Pad to 16 byte boundary
    pad_length = 16 - (len(password_bytes) % 16)
    password_bytes += b'\x00' * pad_length
    
    # Encrypt password
    encrypted_password = b''
    prev = authenticator
    for i in range(0, len(password_bytes), 16):
        chunk = password_bytes[i:i+16]
        hash_input = secret + prev
        key = hashlib.md5(hash_input).digest()
        encrypted_chunk = bytes(a ^ b for a, b in zip(chunk, key))
        encrypted_password += encrypted_chunk
        prev = encrypted_chunk
    
    attributes += struct.pack('BB', 2, len(encrypted_password) + 2) + encrypted_password
    
    # IP-Address attribute (0.0.0.0)
    attributes += struct.pack('BB', 4, 6) + bytes([0, 0, 0, 0])
    
    # Service-Type attribute (Administrative)
    attributes += struct.pack('BBBBBB', 6, 6, 0, 0, 0, 6)
    
    # Calculate length
    length = 20 + len(attributes)
    
    # Create packet
    packet = struct.pack('!BBH', 1, identifier, length) + authenticator + attributes
    
    return packet, authenticator

def test_radius_auth(server='localhost', port=1812, secret='radius123',
                    username='admin', password='admin123'):
    """Test RADIUS authentication"""
    
    print(f"Testing RADIUS authentication:")
    print(f"  Server: {server}:{port}")
    print(f"  Username: {username}")
    print(f"  Password: {'*' * len(password)}")
    print()
    
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        
        # Create Access-Request
        identifier = secrets.randbelow(256)
        secret_bytes = secret.encode('utf-8')
        request, request_auth = create_access_request(
            username, password, identifier, secret_bytes
        )
        
        # Send request
        print("Sending Access-Request...")
        sock.sendto(request, (server, port))
        
        # Receive response
        response_data, addr = sock.recvfrom(4096)
        
        if len(response_data) < 20:
            print("Invalid response received")
            return False
        
        # Parse response
        code, resp_id, length = struct.unpack('!BBH', response_data[:4])
        
        code_names = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject"}
        print(f"Response received: {code_names.get(code, f'Unknown({code})')}")
        
        if code == 2:  # Access-Accept
            print("✓ Authentication SUCCESSFUL")
            
            # Parse attributes
            offset = 20
            while offset < length:
                if offset + 2 > len(response_data):
                    break
                attr_type, attr_len = struct.unpack('BB', response_data[offset:offset+2])
                if attr_len < 2 or offset + attr_len > len(response_data):
                    break
                
                attr_value = response_data[offset+2:offset+attr_len]
                
                # Reply-Message
                if attr_type == 18:
                    message = attr_value.decode('utf-8', errors='replace')
                    print(f"  Reply-Message: {message}")
                
                offset += attr_len
            
            return True
            
        elif code == 3:  # Access-Reject
            print("✗ Authentication FAILED")
            return False
        else:
            print(f"Unexpected response code: {code}")
            return False
            
    except socket.timeout:
        print("✗ Request timed out - server not responding")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    finally:
        sock.close()

def main():
    """Main function"""
    server = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1812
    secret = sys.argv[3] if len(sys.argv) > 3 else 'radius123'
    username = sys.argv[4] if len(sys.argv) > 4 else 'admin'
    password = sys.argv[5] if len(sys.argv) > 5 else 'admin123'
    
    success = test_radius_auth(server, port, secret, username, password)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()