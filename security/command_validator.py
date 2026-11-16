"""
Command Validator for ARES.

Validates that commands are read-only and safe to execute.
"""

import re
import logging
from typing import List

logger = logging.getLogger(__name__)


class CommandValidator:
    """Validates commands against a blacklist (and optionally a whitelist).

    In default mode, only known-dangerous commands are blocked.
    In strict mode, only explicitly whitelisted commands are allowed.
    """

    DANGEROUS_COMMANDS = [
        'rm', 'rmdir', 'del', 'delete',
        'dd', 'mkfs', 'fdisk', 'parted',
        'shutdown', 'reboot', 'init', 'halt', 'poweroff',
        'useradd', 'userdel', 'usermod',
        'groupadd', 'groupdel', 'groupmod',
        'passwd', 'chpasswd',
        'chmod', 'chown', 'chgrp',
        'iptables -A', 'iptables -I', 'iptables -D', 'iptables -F',
        'firewall-cmd --add-', 'firewall-cmd --remove-', 'firewall-cmd --permanent',
        'firewall-cmd --reload', 'firewall-cmd --complete-reload',
        'systemctl start', 'systemctl stop', 'systemctl restart',
        'systemctl enable', 'systemctl disable', 'systemctl mask',
        'service start', 'service stop', 'service restart',
        'killall', 'pkill', 'kill',
        'mv', 'cp', 'touch',
        'tee',
        'sed -i',
        'yum install', 'yum remove', 'dnf install', 'dnf remove',
        'rpm -i', 'rpm -e',
    ]
    
    # Paths that don't exist on RHEL 8 VM (LLM hallucinations)
    HALLUCINATED_PATHS = [
        '/home/ansible/gen_rag',
        '/opt/STIG_Compliance',
        '/media/sf_evaluate-stig-main',
        '/etc/Evaluate-STIG',
        '/home/ansible/RHEL_8_STIG',
    ]

    def __init__(self):
        """Initialize command validator with blacklist only (no whitelist)."""
        # Pre-compile dangerous command regexes for performance.
        # NOTE: matching is done against a lower-cased command, so patterns must be
        # lower-cased too (otherwise upper-case flags like "iptables -F" never match).
        # Trailing boundary:
        #   - patterns ending in a word char use ([.\s]|$) so "mkfs" also matches "mkfs.ext4"
        #     but "rm" does NOT match "rmdir";
        #   - patterns ending in a non-word char (e.g. "firewall-cmd --add-") don't require a
        #     following separator, so "firewall-cmd --add-port=22/tcp" is caught.
        self._dangerous_regexes: List[re.Pattern[str]] = []
        # A dangerous command counts when it starts the command, follows a separator, sits
        # inside a subshell / command substitution / "sh -c" string / find -exec, or follows
        # any chain of privilege and launcher wrappers (sudo, env, nohup, xargs, ...), with or
        # without an absolute path. Without the wrapper part "sudo rm -rf /x" was let through.
        start = (r'(?:^|[|;&({`\n]\s*|\$\(\s*'
                 r'|\b(?:sh|bash|ksh|zsh|dash|csh|tcsh)\s+(?:-\w+\s+)*-\w*c\s+["\']?\s*'
                 r'|\s-(?:exec|execdir|ok|okdir)\s+'
                 r'|\b(?:then|do|else|elif|eval|source|trap)\s+|(?:^|\s)[!.]\s+)')
        # things that may sit in front of a command without changing which command runs:
        # VAR=value assignments and redirections such as "0<&-" or "2>/dev/null"
        filler = r'(?:(?:\w+=\S*|\d*[<>]+&?[\w./-]*)\s+)*'
        wrapper = (r'(?:(?:/[\w.-]+)*/)?(?:sudo|doas|pfexec|pbrun|dzdo|nohup|time|nice|ionice|command|exec|'
                   r'builtin|env|stdbuf|timeout|setsid|xargs|chroot|watch|strace|script|unbuffer)'
                   r'(?:\s+(?:-\S+\s+[\w./:@-]+|-\S+|\w+=\S*|\d+(?:\.\d+)?[smhd]?))*\s+')
        prefix = rf'{start}{filler}(?:{wrapper}{filler})*["\']?(?:(?:/[\w.-]+)*/)?'
        # a command name that only exists after expansion ("$cmd x", "${a}m x") cannot be checked
        self._expanded_command = re.compile(rf'{prefix}[\w./-]*\$'
                                            r'|(?:^|[|;&({\n]|\b(?:then|do|else|sudo|eval|exec|env|xargs))\s*`')
        for pattern in self.DANGEROUS_COMMANDS:
            escaped = re.escape(pattern.lower())
            trailing = r'([.\s]|$)' if pattern[-1].isalnum() else ''
            self._dangerous_regexes.append(re.compile(rf'{prefix}{escaped}{trailing}'))

    def validate_command(self, command: str) -> bool:
        """
        Validate that command is safe to execute using blacklist only.
        
        Blocks:
        - Empty commands
        - Commands with dangerous file write redirections
        - Commands matching dangerous patterns (destructive operations)
        - Commands referencing hallucinated paths (LLM errors)

        Returns True if command passes validation, False if blocked.
        """
        if not command or not command.strip():
            logger.error("Empty command rejected")
            return False

        command_stripped = command.strip()

        if self._has_write_redirect(command_stripped):
            logger.error(f"Output redirection detected: {command_stripped}")
            return False

        if self._matches_dangerous(command_stripped):
            return False
        
        # Check for hallucinated paths (LLM making up directories)
        for path in self.HALLUCINATED_PATHS:
            if path in command_stripped:
                logger.error(f"Hallucinated path detected: {path} in command: {command_stripped[:100]}")
                return False

        return True

    def _has_write_redirect(self, command: str) -> bool:
        """Check for output redirection operators that write to files.
        
        Allows safe redirections:
        - 2>/dev/null (stderr to null)
        - 2>&1 (stderr to stdout)
        - >/dev/null (stdout to null)
        - 1>/dev/null (stdout to null)
        - Awk/sed regex patterns: /pattern/
        
        Blocks dangerous redirections:
        - > /path/to/file (write to file)
        - >> /path/to/file (append to file)
        """
        # Step 1: Remove quoted strings (they're safe)
        cleaned = re.sub(r'"[^"]*"', '', command)
        cleaned = re.sub(r"'[^']*'", '', cleaned)
        
        # Step 2: Remove safe redirections to /dev/null
        safe_patterns = [
            r'2>/dev/null',
            r'2>&1',
            r'>/dev/null',
            r'1>/dev/null',
            r'&>/dev/null',
        ]
        for pattern in safe_patterns:
            cleaned = cleaned.replace(pattern, '')
        # the same redirections written with a space before the target ("2> /dev/null")
        cleaned = re.sub(r'(?:\d|&)?>\s*/dev/null\b', '', cleaned)
        cleaned = re.sub(r'\d?>&\s*\d', '', cleaned)
        
        # Step 3: Remove awk/sed regex patterns (/pattern/) BEFORE splitting on |
        # This prevents false positives from regex pipes like /pattern|other/
        cleaned = re.sub(r'/[^/]*/', '', cleaned)
        
        # Step 4: Now split on pipes and check each segment
        segments = cleaned.split('|')
        for segment in segments:
            stripped = segment.strip()
            
            # Check if any > or >> remains (those would be dangerous file writes)
            if '>>' in stripped or '>' in stripped:
                logger.error(f"Dangerous file write redirection detected: {command[:100]}")
                return True
        return False

    def _matches_dangerous(self, command: str) -> bool:
        """Check if command matches any dangerous pattern using pre-compiled regexes."""
        command_lower = command.lower()
        # "fdisk -l" only lists partitions; every other fdisk form stays blocked
        command_lower = re.sub(r'\bfdisk\s+-l\b', 'lsblk', command_lower)
        # quoting that the shell removes before it looks up the command: "rm", r''m, r\m
        plain = re.sub(r'(["\'])([\w./-]*)\1', r'\2', command_lower)
        plain = re.sub(r'\\(?=\w)', '', plain)

        # single-quoted text is never expanded (awk programs), and "command -v x" only looks x up
        unquoted = re.sub(r"'[^']*'", "''", command_lower)
        unquoted = re.sub(r'\bcommand\s+-v\s+', 'type ', unquoted)
        if self._expanded_command.search(unquoted):
            logger.error(f"Command name built from a variable or substitution rejected: {command}")
            return True
        for i, regex in enumerate(self._dangerous_regexes):
            if regex.search(command_lower) or regex.search(plain):
                logger.error(
                    f"Dangerous pattern '{self.DANGEROUS_COMMANDS[i]}' matched in: {command}"
                )
                return True
        return False

    def get_dangerous_patterns(self) -> List[str]:
        """Get list of dangerous command patterns."""
        return self.DANGEROUS_COMMANDS
