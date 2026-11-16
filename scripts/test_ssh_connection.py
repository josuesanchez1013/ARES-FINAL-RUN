"""
Test SSH Connection to RHEL8-STIG-Lab

Run this script to verify SSH connectivity before starting development.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli_executor.config import SSHConfig
from fabric import Connection
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_connection():
    """Test SSH connection to target system."""
    print("=" * 60)
    print("ARES SSH Connection Test")
    print("=" * 60)
    
    # Load configuration
    config = SSHConfig.from_env()
    
    print(f"\nTarget: {config.user}@{config.host}:{config.port}")
    print(f"Timeout: {config.timeout}s")
    
    # Prompt for password if not in environment
    if not config.password and not config.key_path:
        from getpass import getpass
        config.password = getpass("SSH Password: ")
    
    print("\nAttempting connection...")
    
    try:
        # Create connection
        conn = Connection(
            host=config.host,
            port=config.port,
            user=config.user,
            connect_kwargs={
                "password": config.password,
                "key_filename": config.key_path,
                "timeout": config.timeout
            }
        )
        
        # Test basic commands
        print("\n✓ Connection established")
        
        print("\nTesting read-only commands:")
        
        # Test 1: whoami
        print("\n1. whoami")
        result = conn.run("whoami", hide=True)
        print(f"   Output: {result.stdout.strip()}")
        print(f"   ✓ Exit code: {result.return_code}")
        
        # Test 2: uname -a
        print("\n2. uname -a")
        result = conn.run("uname -a", hide=True)
        print(f"   Output: {result.stdout.strip()}")
        print(f"   ✓ Exit code: {result.return_code}")
        
        # Test 3: grep (STIG validation example)
        print("\n3. grep -i PermitRootLogin /etc/ssh/sshd_config")
        result = conn.run("grep -i PermitRootLogin /etc/ssh/sshd_config", hide=True, warn=True)
        print(f"   Output: {result.stdout.strip() if result.stdout else '(empty)'}")
        print(f"   ✓ Exit code: {result.return_code}")
        
        # Test 4: systemctl status
        print("\n4. systemctl status sshd")
        result = conn.run("systemctl status sshd | head -n 5", hide=True, warn=True)
        print(f"   Output: {result.stdout.strip()}")
        print(f"   ✓ Exit code: {result.return_code}")
        
        # Close connection
        conn.close()
        
        print("\n" + "=" * 60)
        print("✓ SSH CONNECTION TEST PASSED")
        print("=" * 60)
        print("\nYou can now proceed with ARES development.")
        print("The CLI Executor will use these same credentials.\n")
        
        return True
        
    except Exception as e:
        print(f"\n✗ CONNECTION FAILED: {e}")
        print("\nTroubleshooting:")
        print("1. Verify VM is running")
        print("2. Check IP address (should be 10.0.2.15)")
        print("3. Verify SSH credentials")
        print("4. Ensure SSH service is running on VM")
        print("5. Check firewall rules\n")
        return False


if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)
