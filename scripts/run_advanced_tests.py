#!/usr/bin/env python3
"""
Script to run advanced tests with automatic server management

This script demonstrates how the server fixture automatically starts and stops
the TACACS+ server for tests that need it.

Usage:
    python scripts/run_advanced_tests.py
    python scripts/run_advanced_tests.py --test-type chaos
    python scripts/run_advanced_tests.py --test-type security
    python scripts/run_advanced_tests.py --test-type contract
    python scripts/run_advanced_tests.py --test-type e2e
"""

import argparse
import subprocess
import sys


def run_tests(test_type: str = "all"):
    """Run advanced tests with server fixture"""

    test_commands = {
        "chaos": [
            "poetry",
            "run",
            "pytest",
            "tests/chaos/test_chaos.py::TestResourceChaos::test_memory_pressure_resilience",
            "tests/chaos/test_chaos.py::TestResourceChaos::test_cpu_saturation_resilience",
            "-v",
            "--tb=short",
            "--timeout=120",
        ],
        "security": [
            "poetry",
            "run",
            "pytest",
            "tests/security/test_security_pentest.py::TestInjectionVulnerabilities::test_sql_injection_login",
            "-v",
            "--tb=short",
            "--timeout=60",
        ],
        "contract": [
            "poetry",
            "run",
            "pytest",
            "tests/contract/test_api_contracts.py::TestUserAPIContract::test_list_users_contract",
            "-v",
            "--tb=short",
            "--timeout=30",
        ],
        "e2e": [
            "poetry",
            "run",
            "pytest",
            "tests/e2e/test_e2e_integration.py::TestBasicE2E",
            "-v",
            "--tb=short",
            "--timeout=180",
        ],
        "all": [
            "poetry",
            "run",
            "pytest",
            "tests/chaos/test_chaos.py::TestResourceChaos::test_memory_pressure_resilience",
            "tests/security/test_security_pentest.py::TestInjectionVulnerabilities::test_sql_injection_login",
            "tests/contract/test_api_contracts.py::TestUserAPIContract::test_list_users_contract",
            "tests/e2e/test_e2e_integration.py::TestBasicE2E",
            "-v",
            "--tb=short",
            "--timeout=300",
        ],
    }

    if test_type not in test_commands:
        print(f"❌ Unknown test type: {test_type}")
        print(f"Available types: {', '.join(test_commands.keys())}")
        return 1

    print(f"🚀 Running {test_type} tests with automatic server management...")
    print("📝 The server fixture will:")
    print("   1. Start TACACS+ server automatically")
    print("   2. Wait for server to be ready")
    print("   3. Run the tests")
    print("   4. Stop server when tests complete")
    print()

    try:
        result = subprocess.run(test_commands[test_type], check=False)

        if result.returncode == 0:
            print(f"✅ {test_type.title()} tests completed successfully!")
        else:
            print(f"⚠️  {test_type.title()} tests completed with failures")
            print("💡 Note: Failures may be due to test logic, not server issues")

        return result.returncode

    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
        return 130
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Run advanced tests with server fixture"
    )
    parser.add_argument(
        "--test-type",
        choices=["chaos", "security", "contract", "e2e", "all"],
        default="all",
        help="Type of tests to run (default: all)",
    )
    parser.add_argument(
        "--list-tests",
        action="store_true",
        help="List available tests without running them",
    )

    args = parser.parse_args()

    if args.list_tests:
        print("📋 Available test types:")
        print("  chaos    - Chaos engineering tests (network, resource exhaustion)")
        print("  security - Security penetration tests (OWASP Top 10)")
        print("  contract - API contract tests (JSON schema validation)")
        print("  e2e      - End-to-end integration tests")
        print("  all      - Run all advanced test suites")
        return 0

    return run_tests(args.test_type)


if __name__ == "__main__":
    sys.exit(main())
