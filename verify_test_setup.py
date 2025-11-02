#!/usr/bin/env python3
"""
Quick verification script to check if test setup is working correctly.
Run this before running the full test suite.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def check_test_setup():
    """Run basic checks on test setup."""
    print("=" * 60)
    print("TACACS+ Server - Test Setup Verification")
    print("=" * 60)
    print()

    issues = []

    # Check 1: pytest is installed
    print("✓ Checking pytest installation...")
    try:
        import pytest

        print(f"  ✓ pytest {pytest.__version__} found")
    except ImportError:
        issues.append("pytest not installed - run: pip install pytest")
        print("  ✗ pytest not found")

    # Check 2: conftest files exist
    print("\n✓ Checking conftest files...")
    root_conftest = project_root / "conftest.py"
    tests_conftest = project_root / "tests" / "conftest.py"

    if root_conftest.exists():
        print("  ✓ Root conftest.py found")
    else:
        issues.append("Missing root conftest.py")
        print("  ✗ Root conftest.py missing")

    if tests_conftest.exists():
        print("  ✓ tests/conftest.py found")
    else:
        issues.append("Missing tests/conftest.py")
        print("  ✗ tests/conftest.py missing")

    # Check 3: pytest.ini exists
    print("\n✓ Checking pytest.ini...")
    pytest_ini = project_root / "pytest.ini"
    if pytest_ini.exists():
        print("  ✓ pytest.ini found")
    else:
        issues.append("Missing pytest.ini")
        print("  ✗ pytest.ini missing")

    # Check 4: Test directory structure
    print("\n✓ Checking test directory...")
    tests_dir = project_root / "tests"
    if tests_dir.exists() and tests_dir.is_dir():
        test_files = list(tests_dir.rglob("test_*.py"))
        print(f"  ✓ Found {len(test_files)} test files")
    else:
        issues.append("Tests directory not found")
        print("  ✗ Tests directory missing")

    # Check 5: Config file exists
    print("\n✓ Checking config file...")
    config_file = project_root / "config" / "tacacs.conf"
    if config_file.exists():
        print("  ✓ config/tacacs.conf found")
    else:
        issues.append("Missing config/tacacs.conf (needed as template)")
        print("  ✗ config/tacacs.conf missing")

    # Check 6: Required dependencies
    print("\n✓ Checking required dependencies...")
    required_packages = [
        "requests",
        "configparser",
    ]

    for package in required_packages:
        try:
            __import__(package)
            print(f"  ✓ {package} found")
        except ImportError:
            issues.append(f"Missing package: {package}")
            print(f"  ✗ {package} not found")

    # Summary
    print("\n" + "=" * 60)
    if issues:
        print("ISSUES FOUND:")
        print("=" * 60)
        for i, issue in enumerate(issues, 1):
            print(f"{i}. {issue}")
        print("\nPlease fix these issues before running tests.")
        return False
    else:
        print("✓ ALL CHECKS PASSED")
        print("=" * 60)
        print("\nTest setup looks good! You can now run:")
        print("  pytest tests/test_setup_verification.py -v")
        print("  pytest")
        return True


def run_smoke_test():
    """Run a quick smoke test to verify setup works."""
    print("\n" + "=" * 60)
    print("Running Smoke Test")
    print("=" * 60)
    print()

    try:
        import pytest

        # Run only the setup verification test
        exit_code = pytest.main(
            [
                str(project_root / "tests" / "test_setup_verification.py"),
                "-v",
                "--tb=short",
                "-m",
                "not integration",  # Skip integration tests for quick check
            ]
        )

        print("\n" + "=" * 60)
        if exit_code == 0:
            print("✓ SMOKE TEST PASSED")
            print("=" * 60)
            print("\nTest isolation is working correctly!")
            print("You can now safely run the full test suite:")
            print("  pytest")
            return True
        else:
            print("✗ SMOKE TEST FAILED")
            print("=" * 60)
            print("\nSome tests failed. Check the output above.")
            print("See tests/TEST_SETUP_FIX.md for troubleshooting.")
            return False

    except Exception as e:
        print(f"\n✗ Error running smoke test: {e}")
        return False


if __name__ == "__main__":
    print()

    # Run basic checks
    checks_passed = check_test_setup()

    if not checks_passed:
        print("\n❌ Setup verification failed!")
        sys.exit(1)

    # Ask if user wants to run smoke test
    print("\nWould you like to run a quick smoke test? (y/n): ", end="")
    try:
        response = input().strip().lower()
        if response in ["y", "yes"]:
            smoke_passed = run_smoke_test()
            if not smoke_passed:
                sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nSkipping smoke test.")

    print("\n✅ Verification complete!\n")
    sys.exit(0)
