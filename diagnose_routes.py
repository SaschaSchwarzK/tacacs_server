#!/usr/bin/env python3
"""
Diagnostic script to check admin CRUD route status.
Run this from the tacacs_server root directory.
"""

import sys
from pathlib import Path


def check_routes():
    print("🔍 Checking Admin CRUD Routes...\n")

    router_file = Path("tacacs_server/web/admin/routers.py")

    if not router_file.exists():
        print(f"❌ Router file not found: {router_file}")
        return False

    content = router_file.read_text()

    # Routes to check
    routes_to_check = [
        ("POST /admin/users", '@admin_router.post("/users"'),
        ("POST /admin/groups", '@admin_router.post("/groups"'),
        ("POST /admin/user-groups", '@admin_router.post("/user-groups"'),
        ("POST /admin/devices", '@admin_router.post("/devices"'),
        ("PUT /admin/users/{username}", '@admin_router.put("/users/{username}"'),
        ("DELETE /admin/users/{username}", '@admin_router.delete("/users/{username}"'),
    ]

    print("Route Status:")
    print("-" * 60)

    all_found = True
    for route_name, pattern in routes_to_check:
        if pattern in content:
            print(f"✅ {route_name:40} FOUND")
        else:
            print(f"❌ {route_name:40} MISSING")
            all_found = False

    print()

    # Check if routes use await request.json()
    print("Checking JSON parsing method:")
    print("-" * 60)

    if "await request.json()" in content:
        count = content.count("await request.json()")
        print(f"✅ Found {count} uses of 'await request.json()'")
    else:
        print("⚠️  No 'await request.json()' found - routes may use Form()")

    print()

    # Check FormValidator usage
    if "FormValidator.validate" in content:
        print("✅ Using FormValidator for validation")
    else:
        print("⚠️  No FormValidator usage found")

    print()

    return all_found


def check_router_registration():
    print("\n🔍 Checking Router Registration...\n")

    possible_files = [
        "tacacs_server/web/web.py",
        "tacacs_server/web/__init__.py",
        "tacacs_server/main.py",
        "tacacs_server/app.py",
    ]

    for file_path in possible_files:
        path = Path(file_path)
        if path.exists():
            content = path.read_text()
            if "admin_router" in content and "include_router" in content:
                print(f"✅ Router registration found in: {file_path}")
                # Show the line
                for i, line in enumerate(content.split("\n"), 1):
                    if "admin_router" in line and "include_router" in line:
                        print(f"   Line {i}: {line.strip()}")
                return True

    print("❌ Router registration not found in any common files")
    return False


def check_dependencies():
    print("\n🔍 Checking Dependencies...\n")

    try:
        import fastapi

        print(f"✅ FastAPI version: {fastapi.__version__}")
    except ImportError:
        print("❌ FastAPI not installed")
        return False

    try:
        import requests

        print(f"✅ requests version: {requests.__version__}")
    except ImportError:
        print("❌ requests not installed")

    return True


def main():
    print("=" * 60)
    print("Admin CRUD Diagnostic Tool")
    print("=" * 60)
    print()

    routes_ok = check_routes()
    registration_ok = check_router_registration()
    deps_ok = check_dependencies()

    print()
    print("=" * 60)
    print("Summary:")
    print("=" * 60)

    if routes_ok and registration_ok and deps_ok:
        print("✅ All checks passed!")
        print()
        print("If tests still fail, the issue is likely:")
        print("1. Request body being consumed by middleware")
        print("2. Dependency injection reading the request before the handler")
        print("3. JSON parsing happening in the wrong order")
        print()
        print("Next step: Enable debug logging and check actual request/response")
    else:
        print("❌ Some checks failed. See above for details.")
        print()
        if not routes_ok:
            print("→ Routes are missing from routers.py")
        if not registration_ok:
            print("→ Router not registered with FastAPI app")
        if not deps_ok:
            print("→ Dependencies not installed")

    print("=" * 60)


if __name__ == "__main__":
    main()
