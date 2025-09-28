import socket
import pytest

def test_server_accepts_tcp_connection(server_process):
    host = server_process["host"]
    port = server_process["port"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host, port))
    finally:
        sock.close()