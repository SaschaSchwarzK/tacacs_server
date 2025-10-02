#!/usr/bin/env python3
"""
Configuration Validation Tool

Validates TACACS+ server configuration without starting the server.
Useful for CI/CD pipelines and pre-deployment checks.

Usage: python validate_config.py [config_file]
"""

import argparse
import os
import sys
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tacacs_server.config.config import TacacsConfig


def validate_configuration(config_file: str = None) -> bool:
    """Validate TACACS+ configuration file"""
    
    print("TACACS+ Configuration Validator")
    print("=" * 40)
    
    # Use provided file or default
    if config_file:
        if not os.path.exists(config_file):
            print(f"❌ Configuration file not found: {config_file}")
            return False
        print(f"📁 Configuration file: {config_file}")
    else:
        config_file = os.getenv('TACACS_CONFIG', 'config/tacacs.conf')
        print(f"📁 Configuration file: {config_file} (default)")
    
    try:
        # Load configuration
        print("\n🔍 Loading configuration...")
        config = TacacsConfig(config_file)
        
        # Validate configuration
        print("🔍 Validating configuration...")
        issues = config.validate_config()
        
        if not issues:
            print("✅ Configuration validation PASSED")
            print("\n📊 Configuration Summary:")
            
            # Display key configuration details
            server_config = config.get_server_config()
            print(f"   Server: {server_config['host']}:{server_config['port']}")
            
            auth_backends = config.get_auth_backends()
            print(f"   Auth backends: {', '.join(auth_backends)}")
            
            security_config = config.get_security_config()
            print(f"   Max auth attempts: {security_config['max_auth_attempts']}")
            print(f"   Auth timeout: {security_config['auth_timeout']}s")
            
            if config.get_radius_config()['enabled']:
                radius_config = config.get_radius_config()
                print(f"   RADIUS: enabled on port {radius_config['auth_port']}")
            else:
                print("   RADIUS: disabled")
            
            return True
        else:
            print("❌ Configuration validation FAILED")
            print(f"\n🚨 Found {len(issues)} issue(s):")
            for i, issue in enumerate(issues, 1):
                print(f"   {i}. {issue}")
            return False
            
    except Exception as e:
        print(f"❌ Configuration validation ERROR: {e}")
        return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Validate TACACS+ server configuration"
    )
    parser.add_argument(
        "config_file", 
        nargs="?", 
        help="Configuration file path (default: config/tacacs.conf or TACACS_CONFIG env var)"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet mode - only show errors"
    )
    
    args = parser.parse_args()
    
    if args.quiet:
        # Redirect stdout to suppress normal output, keep stderr for errors
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
    
    try:
        success = validate_configuration(args.config_file)
        
        if args.quiet:
            sys.stdout = old_stdout
            if not success:
                print("Configuration validation failed", file=sys.stderr)
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        if args.quiet:
            sys.stdout = old_stdout
        print("\n⚠️  Validation interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()