#!/usr/bin/env python3
"""
TACACS+ Test Client
Usage: python test_client.py [host] [port] [secret] [username] [password]
"""

import socket
import struct
import hashlib
import sys
import time

def md5_pad(session_id, key, version, seq_no, length):
    """Generate MD5 encryption pad"""
    pad = b''
    session_id_bytes = struct.pack('!L', session_id)
    key_bytes = key.encode('utf-8')
    version_bytes = bytes([version])
    seq_no_bytes = bytes([seq_no])
    
    while len(pad) < length:
        if len(pad) == 0:
            md5_input = session_id_bytes + key_bytes + version_bytes + seq_no_bytes
        else:
            md5_input = session_id_bytes + key_bytes + version_bytes + seq_no_bytes + pad
        pad += hashlib.md5(md5_input).digest()
    
    return pad[:length]

def encrypt_body(body, session_id, key, version, seq_no):
    """Encrypt packet body"""
    if not key:
        return body
    pad = md5_pad(session_id, key, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))

def decrypt_body(body, session_id, key, version, seq_no):
    """Decrypt packet body"""
    if not key:
        return body
    pad = md5_pad(session_id, key, version, seq_no, len(body))
    return bytes(a ^ b for a, b in zip(body, pad))

def pap_authentication(host='localhost', port=49, key='tacacs123', 
                       username='admin', password='admin123'):
    """Test TACACS+ PAP authentication"""
    print(f"Testing TACACS+ PAP authentication:")
    print(f"  Server: {host}:{port}")
    print(f"  Username: {username}")
    print(f"  Password: {'*' * len(password)}")
    print()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        
        # Create authentication request (PAP)
        session_id = int(time.time()) & 0xFFFFFFFF
        
        # Prepare packet data
        user_bytes = username.encode('utf-8')
        port_bytes = b"console"
        rem_addr_bytes = b"127.0.0.1"
        data_bytes = password.encode('utf-8')
        
        body = struct.pack('!BBBBBBBB',
                          1,  # action: LOGIN
                          15, # priv_lvl
                          2,  # authen_type: PAP
                          1,  # service: LOGIN
                          len(user_bytes),
                          len(port_bytes),
                          len(rem_addr_bytes),
                          len(data_bytes))
        
        body += user_bytes + port_bytes + rem_addr_bytes + data_bytes
        
        # Encrypt body
        version = 0xc0
        seq_no = 1
        encrypted_body = encrypt_body(body, session_id, key, version, seq_no)
        
        # Create packet header
        header = struct.pack('!BBBBLL',
                           version,     # version
                           1,          # type: Authentication
                           seq_no,     # seq_no
                           0,          # flags
                           session_id, # session_id
                           len(encrypted_body))  # length
        
        # Send packet
        print("Sending authentication request...")
        sock.send(header + encrypted_body)
        
        # Receive response
        response_header = sock.recv(12)
        if len(response_header) == 12:
            r_version, r_type, r_seq, r_flags, r_session, r_length = struct.unpack('!BBBBLL', response_header)
            print(f"Response received: type={r_type}, seq={r_seq}, length={r_length}")
            
            if r_length > 0:
                response_body = sock.recv(r_length)
                if len(response_body) >= r_length:
                    # Decrypt response body
                    decrypted = decrypt_body(response_body, r_session, key, r_version, r_seq)
                    
                    if len(decrypted) >= 4:
                        status, flags, msg_len, data_len = struct.unpack('!BBHH', decrypted[:6])
                        
                        if status == 1:  # PASS
                            print("✓ Authentication PASSED")
                            result = True
                        elif status == 2:  # FAIL
                            print("✗ Authentication FAILED")
                            result = False
                        else:
                            print(f"Authentication status: {status}")
                            result = False
                        
                        # Print server message if present
                        if msg_len > 0 and len(decrypted) > 6:
                            server_msg = decrypted[6:6+msg_len].decode('utf-8', errors='replace')
                            print(f"Server message: {server_msg}")
                        
                        return result
            else:
                print("Empty response body")
                return False
        else:
            print("Invalid response header")
            return False
            
    except Exception as e:
        print(f"Test error: {e}")
        return False
    finally:
        try:
            sock.close()
        except:
            pass

def main():
    """Main test function"""
    # Parse command line arguments
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 49
    key = sys.argv[3] if len(sys.argv) > 3 else 'tacacs123'
    username = sys.argv[4] if len(sys.argv) > 4 else 'admin'
    password = sys.argv[5] if len(sys.argv) > 5 else 'admin123'
    
    success = pap_authentication(host, port, key, username, password)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
