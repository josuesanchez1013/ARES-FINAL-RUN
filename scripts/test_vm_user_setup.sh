#!/bin/bash
# Test script for ares-validator VM user setup
# Run this script ON the RHEL8-STIG-Lab VM as root

set -e

echo "============================================"
echo "ARES Validator VM User Setup Test"
echo "============================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_count=0
pass_count=0
fail_count=0

run_test() {
    test_count=$((test_count + 1))
    echo -n "[Test $test_count] $1... "
    if eval "$2" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        pass_count=$((pass_count + 1))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        fail_count=$((fail_count + 1))
        return 1
    fi
}

echo "Step 1: Verify ares-validator user exists"
run_test "User exists" "id ares-validator"

echo ""
echo "Step 2: Verify SSH directory setup"
run_test "SSH directory exists" "test -d /home/ares-validator/.ssh"
run_test "SSH directory permissions" "stat -c '%a' /home/ares-validator/.ssh | grep -q '700'"

echo ""
echo "Step 3: Verify home directory permissions"
run_test "Home directory is read-only" "test \$(stat -c '%U' /home/ares-validator) = 'root'"

echo ""
echo "Step 4: Verify sudoers configuration"
run_test "Sudoers file exists" "test -f /etc/sudoers.d/ares-validator"
run_test "Sudoers file permissions" "stat -c '%a' /etc/sudoers.d/ares-validator | grep -q '440'"
run_test "Sudoers syntax valid" "visudo -c -f /etc/sudoers.d/ares-validator"

echo ""
echo "Step 5: Test sudo commands (run as ares-validator)"
echo -e "${YELLOW}Note: Run these manually as ares-validator user:${NC}"
echo "  sudo su - ares-validator"
echo "  sudo cat /etc/shadow | head -1   # Should work"
echo "  sudo systemctl restart sshd       # Should fail"

echo ""
echo "Step 6: Verify audit rules"
ARES_UID=$(id -u ares-validator)
run_test "Audit rules loaded" "auditctl -l | grep -q 'uid=$ARES_UID'"

echo ""
echo "Step 7: Test read-only filesystem"
echo -e "${YELLOW}Testing write protection (expect failures):${NC}"
sudo su - ares-validator -c "touch /etc/test_file 2>&1" | grep -q "Permission denied" && \
    echo -e "[Test write to /etc] ${GREEN}✅ BLOCKED (expected)${NC}" || \
    echo -e "[Test write to /etc] ${RED}❌ NOT BLOCKED (security issue!)${NC}"

sudo su - ares-validator -c "rm /etc/hosts 2>&1" | grep -q "Permission denied" && \
    echo -e "[Test delete from /etc] ${GREEN}✅ BLOCKED (expected)${NC}" || \
    echo -e "[Test delete from /etc] ${RED}❌ NOT BLOCKED (security issue!)${NC}"

echo ""
echo "Step 8: Test STIG validation commands"
echo -e "${YELLOW}Testing common STIG commands (expect success):${NC}"
sudo su - ares-validator -c "cat /etc/passwd | head -1" > /dev/null 2>&1 && \
    echo -e "[Test cat /etc/passwd] ${GREEN}✅ PASS${NC}" || \
    echo -e "[Test cat /etc/passwd] ${RED}❌ FAIL${NC}"

sudo su - ares-validator -c "grep PermitRootLogin /etc/ssh/sshd_config" > /dev/null 2>&1 && \
    echo -e "[Test grep sshd_config] ${GREEN}✅ PASS${NC}" || \
    echo -e "[Test grep sshd_config] ${RED}❌ FAIL${NC}"

sudo su - ares-validator -c "systemctl status sshd" > /dev/null 2>&1 && \
    echo -e "[Test systemctl status] ${GREEN}✅ PASS${NC}" || \
    echo -e "[Test systemctl status] ${RED}❌ FAIL${NC}"

sudo su - ares-validator -c "stat /etc/passwd" > /dev/null 2>&1 && \
    echo -e "[Test stat command] ${GREEN}✅ PASS${NC}" || \
    echo -e "[Test stat command] ${RED}❌ FAIL${NC}"

echo ""
echo "============================================"
echo "Test Summary"
echo "============================================"
echo "Total tests: $test_count"
echo -e "Passed: ${GREEN}$pass_count${NC}"
echo -e "Failed: ${RED}$fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed! ares-validator user is configured correctly.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Review the output above and fix issues.${NC}"
    exit 1
fi
