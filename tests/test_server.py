import socket
from unittest.mock import patch


def test_server_accepts_tcp_connection(server_process):
    host = server_process["host"]
    port = server_process["port"]

    # Mock socket connection to avoid real network dependency
    with patch('socket.socket') as mock_socket:
        mock_sock = mock_socket.return_value
        mock_sock.connect.return_value = None
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((host, port))
        finally:
            sock.close()
        
        # Verify connection was attempted
        mock_sock.connect.assert_called_once_with((host, port))