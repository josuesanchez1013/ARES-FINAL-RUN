#!/bin/bash
# Setup read-only user on RHEL 8 for ARES
# Run this script on the target VM (rhel8-stig-lab)

set -e

echo "====================================="
echo "ARES Read-Only User Setup"
echo "====================================="

# TODO: Implement user creation with read-only permissions
# 
# # Create ARES user
# useradd -m -s /bin/bash stig-checker
# 
# # Set password
# echo "stig-checker:SecurePassword123!" | chpasswd
# 
# # Add to necessary groups for read access (but not write)
# usermod -aG systemd-journal stig-checker
# 
# # Configure sudo for read-only commands only
# cat > /etc/sudoers.d/stig-checker << 'EOF'
# # ARES STIG Checker - Read-only commands only
# stig-checker ALL=(ALL) NOPASSWD: /usr/bin/cat, /usr/bin/grep, /usr/bin/less, /usr/bin/systemctl status *
# EOF
# 
# chmod 0440 /etc/sudoers.d/stig-checker
# 
# echo "✓ User 'stig-checker' created with read-only access"
# echo "✓ Password: SecurePassword123! (change in production)"
# echo ""
# echo "Test connection:"
# echo "  ssh stig-checker@10.0.2.15"

echo "TODO: Implement user creation script"
echo "For now, use existing user 'labuser' with read-only mindset"
