import importlib.util
import json
import sys

print("=== inside pytest process ===")
print("cwd:", __import__("os").getcwd())
print("sys.path[0..5]:", json.dumps(sys.path[:6]))
print("find_spec tacacs_server:", importlib.util.find_spec("tacacs_server"))
print("find_spec tacacs_server.auth:", importlib.util.find_spec("tacacs_server.auth"))
# Try importing the specific modules
try:
    import tacacs_server

    print("tacacs_server.__file__:", getattr(tacacs_server, "__file__", None))
    print("tacacs_server.__path__:", list(tacacs_server.__path__))
except Exception as e:
    print("import tacacs_server failed:", e)
try:
    from tacacs_server.auth import local

    print("import tacacs_server.auth.local OK:", local)
except Exception as e:
    print("import tacacs_server.auth.local failed:", e)
