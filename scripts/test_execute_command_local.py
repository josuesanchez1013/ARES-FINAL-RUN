"""
Test execute_command tool locally (direct Python import, not via MCP server).

This tests:
1. SSH connection to ares-validator@192.168.56.102
2. Command execution via CLI executor
3. Command validation (blacklist enforcement)
4. Sudo command execution
5. Output parsing and error handling

Run this BEFORE deploying to MCP server to verify VM connectivity.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cli_executor.ares_mcp_tool import ARESCliMcpTool

print("="*80)
print("ARES execute_command Local Test")
print("="*80)
print(f"Testing SSH connection to RHEL8-STIG-Lab VM")
print(f"Mode: Direct Python import (NOT via MCP server)")
print("="*80)

load_dotenv()

SSH_HOST = os.getenv("ARES_SSH_HOST")
SSH_USER = os.getenv("ARES_SSH_USER")
SSH_PASSWORD = os.getenv("ARES_SSH_PASSWORD")
SSH_PORT = os.getenv("ARES_SSH_PORT", "22")

print(f"\nSSH Configuration:")
print(f"  Host: {SSH_HOST}")
print(f"  User: {SSH_USER}")
print(f"  Port: {SSH_PORT}")
print(f"  Password: {'***' if SSH_PASSWORD else 'NOT SET'}")

if not SSH_PASSWORD:
    print("\n❌ ERROR: ARES_SSH_PASSWORD not set in .env file")
    sys.exit(1)

tool = ARESCliMcpTool()

print("\n" + "="*80)
print("TEST 1: Config File Read with Sudo (STIG Check)")
print("="*80)
print("Command: grep PermitRootLogin /etc/ssh/sshd_config")
print("Rule ID: V-230225")
print("Use Sudo: YES (sshd_config requires root access per STIG)")

try:
    result = tool.run(
        command="grep PermitRootLogin /etc/ssh/sshd_config",
        rule_id="V-230225",
        use_sudo=True
    )
    print(f"\n✅ Status: {result['status']}")
    print(f"Exit Code: {result['exit_code']}")
    print(f"Output:\n{result['output']}")
    if result.get('error'):
        print(f"Error: {result['error']}")
except Exception as e:
    print(f"\n❌ FAILED: {e}")

print("\n" + "="*80)
print("TEST 2: Permission Check (NO sudo)")
print("="*80)
print("Command: ls -l /etc/passwd")
print("Rule ID: V-230300")

try:
    result = tool.run(
        command="ls -l /etc/passwd",
        rule_id="V-230300"
    )
    print(f"\n✅ Status: {result['status']}")
    print(f"Exit Code: {result['exit_code']}")
    print(f"Output:\n{result['output']}")
except Exception as e:
    print(f"\n❌ FAILED: {e}")

print("\n" + "="*80)
print("TEST 3: Sudo Command (Shadow File)")
print("="*80)
print("Command: cat /etc/shadow | head -1")
print("Rule ID: V-230230")
print("Use Sudo: YES")

try:
    result = tool.run(
        command="cat /etc/shadow | head -1",
        rule_id="V-230230",
        use_sudo=True
    )
    print(f"\n✅ Status: {result['status']}")
    print(f"Exit Code: {result['exit_code']}")
    print(f"Output: {result['output'][:100]}..." if len(result['output']) > 100 else f"Output: {result['output']}")
    if result.get('error'):
        print(f"Error: {result['error']}")
except Exception as e:
    print(f"\n❌ FAILED: {e}")

print("\n" + "="*80)
print("TEST 4: Service Status Check")
print("="*80)
print("Command: systemctl status sshd")
print("Rule ID: V-230400")

try:
    result = tool.run(
        command="systemctl status sshd",
        rule_id="V-230400"
    )
    print(f"\n✅ Status: {result['status']}")
    print(f"Exit Code: {result['exit_code']}")
    print(f"Output (first 200 chars):\n{result['output'][:200]}...")
except Exception as e:
    print(f"\n❌ FAILED: {e}")

print("\n" + "="*80)
print("TEST 5: Dangerous Command (SHOULD BE BLOCKED)")
print("="*80)
print("Command: rm -rf /tmp/test")
print("Rule ID: TEST-BLOCK")
print("Expected: exit_code = -2 (blocked by validator)")

try:
    result = tool.run(
        command="rm -rf /tmp/test",
        rule_id="TEST-BLOCK"
    )
    print(f"\n✅ Status: {result['status']}")
    print(f"Exit Code: {result['exit_code']}")
    if result['exit_code'] == -2:
        print("✅ CORRECT: Command blocked by validator")
    else:
        print("❌ ERROR: Command should have been blocked!")
    print(f"Error: {result.get('error', 'N/A')}")
except Exception as e:
    print(f"\n❌ FAILED: {e}")

print("\n" + "="*80)
print("TEST 6: Another Dangerous Command (SHOULD BE BLOCKED)")
print("="*80)
print("Command: chmod 777 /etc/passwd")
print("Rule ID: TEST-BLOCK-2")

try:
    result = tool.run(
        command="chmod 777 /etc/passwd",
        rule_id="TEST-BLOCK-2"
    )
    print(f"\n✅ Status: {result['status']}")
    print(f"Exit Code: {result['exit_code']}")
    if result['exit_code'] == -2:
        print("✅ CORRECT: Command blocked by validator")
    else:
        print("❌ ERROR: Command should have been blocked!")
    print(f"Error: {result.get('error', 'N/A')}")
except Exception as e:
    print(f"\n❌ FAILED: {e}")

print("\n" + "="*80)
print("TEST 7: Write Redirection (SHOULD BE BLOCKED)")
print("="*80)
print("Command: echo 'test' > /etc/test.txt")
print("Rule ID: TEST-BLOCK-3")

try:
    result = tool.run(
        command="echo 'test' > /etc/test.txt",
        rule_id="TEST-BLOCK-3"
    )
    print(f"\n✅ Status: {result['status']}")
    print(f"Exit Code: {result['exit_code']}")
    if result['exit_code'] == -2:
        print("✅ CORRECT: Command blocked by validator")
    else:
        print("❌ ERROR: Command should have been blocked!")
    print(f"Error: {result.get('error', 'N/A')}")
except Exception as e:
    print(f"\n❌ FAILED: {e}")

print("\n" + "="*80)
print("TEST SUMMARY")
print("="*80)
print("""
Expected Results:
- Tests 1-4: Should PASS (exit_code 0 or positive)
- Tests 5-7: Should be BLOCKED (exit_code -2)

If all tests pass:
✅ SSH connection to ares-validator@192.168.56.102 works
✅ Command execution works (with and without sudo)
✅ Command validator blocking dangerous commands
✅ Ready to deploy to MCP server!

If any test fails:
❌ Check .env file has correct credentials
❌ Check VM is running and reachable at 192.168.56.102
❌ Check ares-validator user has sudo NOPASSWD access
""")
print("="*80)
