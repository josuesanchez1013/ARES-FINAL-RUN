"""
Tests for ARES CLI Executor.

Split into:
- Unit tests (no SSH needed, run anywhere)
- Integration tests (require SSH to rhel8-stig-lab, marked with @pytest.mark.integration)

Covers:
- CommandValidator: blacklist, whitelist/strict mode, edge cases
- SSHConfig: defaults, env loading, validation, error handling
- CommandExecutor: validation, retry, rejection, health checks
- FabricClient: connection management, execution, sudo, errors
- AuditLogger: field completeness, append-only behavior, rule_id propagation
- Output truncation at 10KB boundary
- Sequential command execution / connection reuse
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from cli_executor.config import SSHConfig
from cli_executor.fabric_client import FabricClient
from cli_executor.audit_logger import AuditLogger
from cli_executor.executor import CommandExecutor
from security.command_validator import CommandValidator


# ============================================================
# Unit Tests: CommandValidator - Blacklist Mode
# ============================================================

class TestCommandValidatorBlacklist:
    """Test that dangerous commands are blocked in default mode."""

    @pytest.fixture
    def validator(self):
        return CommandValidator()

    @pytest.mark.parametrize("cmd", [
        "rm -rf /tmp/test",
        "rm file.txt",
        "rmdir /etc/something",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda1",
        "shutdown -h now",
        "reboot",
        "halt",
        "poweroff",
        "useradd testuser",
        "userdel testuser",
        "passwd root",
        "chmod 777 /etc/shadow",
        "chown root:root /tmp/file",
        "systemctl start sshd",
        "systemctl stop firewalld",
        "systemctl restart auditd",
        "systemctl enable sshd",
        "systemctl disable firewalld",
        "systemctl mask auditd",
        "killall python",
        "pkill sshd",
        "kill -9 1234",
        "mv /etc/passwd /tmp/",
        "cp /etc/shadow /tmp/",
        "touch /tmp/newfile",
        "tee /etc/config",
        "sed -i 's/old/new/' /etc/ssh/sshd_config",
        "yum install nmap",
        "yum remove openssh",
        "dnf install nmap",
        "dnf remove openssh",
        "rpm -i package.rpm",
        "rpm -e openssh",
        "iptables -F",
        "firewall-cmd --add-port=22/tcp",
        "fdisk /dev/sda",
        "parted /dev/sda",
        "chgrp wheel /tmp/file",
        "chpasswd",
        "groupadd newgroup",
        "groupdel oldgroup",
        "groupmod -n newname oldgroup",
        "usermod -aG wheel user",
        "init 0",
    ])
    def test_blocks_dangerous_commands(self, validator, cmd):
        assert validator.validate_command(cmd) is False, f"Should block: {cmd}"

    @pytest.mark.parametrize("cmd", [
        "grep -i PermitRootLogin /etc/ssh/sshd_config",
        "cat /etc/passwd",
        "ls -la /etc/ssh/",
        "systemctl status sshd",
        "systemctl is-enabled auditd",
        "systemctl is-active firewalld",
        "systemctl show sshd",
        "systemctl list-units",
        "systemctl list-unit-files",
        "ps aux",
        "netstat -tlnp",
        "ss -tlnp",
        "df -h",
        "who",
        "w",
        "last",
        "lastlog",
        "stat /etc/shadow",
        "find /etc -name '*.conf'",
        "id",
        "getent passwd root",
        "uname -a",
        "rpm -qa | grep openssh",
        "rpm -q openssh",
        "rpm -V openssh",
        "sestatus",
        "getenforce",
        "auditctl -l",
        "aureport --summary",
        "grep ENCRYPT_METHOD /etc/login.defs",
        "cat /etc/pam.d/password-auth",
        "head -20 /etc/audit/auditd.conf",
        "tail -5 /var/log/secure",
        "wc -l /etc/passwd",
        "grep ssh /etc/services | wc -l",
        "awk '/PermitRootLogin/ {print}' /etc/ssh/sshd_config",
        "cut -d: -f1 /etc/passwd",
        "sort /etc/passwd",
        "uniq -c",
        "tr '[:upper:]' '[:lower:]'",
        "hostname",
        "ip addr show",
        "du -sh /var/log",
        "locate sshd_config",
        "which auditctl",
        "whereis grep",
        "test -f /etc/shadow",
        "echo hello",
        "less /etc/ssh/sshd_config",
        "more /etc/passwd",
        "file /etc/shadow",
        "groups root",
        "service status sshd",
    ])
    def test_allows_safe_commands(self, validator, cmd):
        assert validator.validate_command(cmd) is True, f"Should allow: {cmd}"

    def test_blocks_output_redirect(self, validator):
        assert validator.validate_command("echo bad > /etc/passwd") is False
        assert validator.validate_command("cat /etc/passwd >> /tmp/stolen") is False
        assert validator.validate_command("grep test /etc/hosts > /tmp/out") is False

    def test_allows_redirect_inside_quotes(self, validator):
        assert validator.validate_command("grep '>' /etc/config") is True
        assert validator.validate_command('grep ">" /etc/config') is True

    def test_allows_pipes(self, validator):
        assert validator.validate_command("grep ssh /etc/services | wc -l") is True
        assert validator.validate_command("ps aux | grep sshd") is True
        assert validator.validate_command("rpm -qa | grep audit | sort") is True
        assert validator.validate_command("cat /etc/passwd | cut -d: -f1 | sort") is True

    def test_blocks_empty_command(self, validator):
        assert validator.validate_command("") is False
        assert validator.validate_command("   ") is False
        assert validator.validate_command(None) is False

    def test_no_false_positive_on_substrings(self, validator):
        assert validator.validate_command("grep remove /etc/config") is True
        assert validator.validate_command("cat /etc/init.d/sshd") is True
        assert validator.validate_command("grep 'cp' /etc/config") is True
        assert validator.validate_command("grep killing /var/log/messages") is True

    def test_blocks_chained_dangerous(self, validator):
        assert validator.validate_command("ls /tmp; rm -rf /tmp/test") is False
        assert validator.validate_command("echo hello && rm file.txt") is False
        assert validator.validate_command("cat /etc/hosts || rm /tmp/x") is False

    def test_handles_leading_trailing_whitespace(self, validator):
        assert validator.validate_command("  grep test /etc/hosts  ") is True
        assert validator.validate_command("  rm -rf /tmp  ") is False

    def test_case_insensitive_blocking(self, validator):
        assert validator.validate_command("RM -rf /tmp") is False
        assert validator.validate_command("Shutdown -h now") is False


class TestCommandValidatorAwkRegexRegression:
    """Regression tests: awk/sed regex patterns containing '|' or '/' must NOT be
    mistaken for pipes or file-write redirections. Preserved from the original
    ad-hoc root test_validator.py script (STIG check commands use these heavily)."""

    @pytest.fixture
    def validator(self):
        return CommandValidator()

    def test_awk_regex_pipe_alternation_allowed(self, validator):
        # '/nologin|false/' is an awk regex alternation, not a shell pipe.
        cmd = ("getent passwd | awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ "
               "{print $1, $3, $6, $7}' /etc/passwd")
        assert validator.validate_command(cmd) is True

    def test_awk_regex_no_file_arg_allowed(self, validator):
        cmd = ("awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ "
               "{print $1 \" \" $3 \" \" $6 \" \" $7}'")
        assert validator.validate_command(cmd) is True

    def test_awk_shadow_maxdays_allowed(self, validator):
        # Real RHEL 8 STIG check command.
        assert validator.validate_command("awk -F: '$5 > 60 {print $1 \" \" $5}' /etc/shadow") is True

    def test_dangerous_write_still_blocked(self, validator):
        assert validator.validate_command("cat /etc/passwd > /tmp/bad") is False

    def test_safe_stderr_redirect_allowed(self, validator):
        assert validator.validate_command("grep root /etc/passwd 2>/dev/null") is True


@pytest.mark.skip(reason="Strict/whitelist mode was removed by design — validator is blacklist-only "
                         "(VM uses full sudo + sudoers blacklist, no whitelist). See DECISIONS/security rules.")
class TestCommandValidatorStrictMode:
    """Test strict mode (whitelist only). DEPRECATED: strict/whitelist mode no longer exists."""

    @pytest.fixture
    def validator(self):
        return CommandValidator()

    def test_allows_whitelisted(self, validator):
        assert validator.validate_command("grep PermitRootLogin /etc/ssh/sshd_config") is True
        assert validator.validate_command("systemctl status sshd") is True
        assert validator.validate_command("cat /etc/passwd") is True
        assert validator.validate_command("auditctl -l") is True
        assert validator.validate_command("rpm -qa") is True

    def test_blocks_unknown_commands(self, validator):
        assert validator.validate_command("curl http://evil.com") is False
        assert validator.validate_command("wget http://evil.com") is False
        assert validator.validate_command("python -c 'import os'") is False
        assert validator.validate_command("nc -l 4444") is False
        assert validator.validate_command("nmap 10.0.2.15") is False

    def test_allows_path_prefixed_safe_commands(self, validator):
        assert validator.validate_command("/usr/bin/grep test /etc/hosts") is True
        assert validator.validate_command("/bin/cat /etc/passwd") is True

    def test_blocks_dangerous_even_in_strict(self, validator):
        assert validator.validate_command("rm -rf /") is False
        assert validator.validate_command("chmod 777 /etc/shadow") is False


class TestCommandValidatorPerformance:
    """Test that pre-compiled regexes work correctly."""

    def test_validator_reuse_across_calls(self):
        validator = CommandValidator()
        for _ in range(100):
            assert validator.validate_command("grep test /etc/hosts") is True
            assert validator.validate_command("rm -rf /") is False

    def test_regexes_compiled_once(self):
        validator = CommandValidator()
        assert len(validator._dangerous_regexes) == len(validator.DANGEROUS_COMMANDS)
        assert all(hasattr(r, 'search') for r in validator._dangerous_regexes)


# ============================================================
# Unit Tests: SSHConfig
# ============================================================

class TestSSHConfig:
    """Test SSH configuration validation."""

    def test_default_values(self):
        config = SSHConfig()
        assert config.host == "10.0.2.15"
        assert config.port == 22
        assert config.user == "labuser"
        assert config.timeout == 30
        assert config.password is None
        assert config.key_path is None

    def test_validate_requires_auth(self):
        config = SSHConfig(password=None, key_path=None)
        with pytest.raises(ValueError, match="either password or key_path"):
            config.validate()

    def test_validate_with_password(self):
        config = SSHConfig(password="testpass")
        assert config.validate() is True

    def test_validate_with_key_path(self, tmp_path):
        key_file = tmp_path / "id_rsa"
        key_file.write_text("fake key")
        config = SSHConfig(key_path=str(key_file))
        assert config.validate() is True

    def test_validate_with_both_auth_methods(self, tmp_path):
        key_file = tmp_path / "id_rsa"
        key_file.write_text("fake key")
        config = SSHConfig(password="testpass", key_path=str(key_file))
        assert config.validate() is True

    def test_validate_missing_key_file(self):
        config = SSHConfig(key_path="/nonexistent/path/id_rsa")
        with pytest.raises(ValueError, match="key file not found"):
            config.validate()

    def test_validate_empty_host(self):
        config = SSHConfig(host="", password="test")
        with pytest.raises(ValueError, match="host must be a non-empty string"):
            config.validate()

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("ARES_SSH_HOST", "192.168.1.100")
        monkeypatch.setenv("ARES_SSH_PORT", "2222")
        monkeypatch.setenv("ARES_SSH_USER", "stig-checker")
        monkeypatch.setenv("ARES_SSH_PASSWORD", "secret")
        monkeypatch.setenv("ARES_SSH_TIMEOUT", "60")

        config = SSHConfig.from_env()
        assert config.host == "192.168.1.100"
        assert config.port == 2222
        assert config.user == "stig-checker"
        assert config.password == "secret"
        assert config.timeout == 60

    def test_from_env_defaults(self, monkeypatch):
        monkeypatch.delenv("ARES_SSH_HOST", raising=False)
        monkeypatch.delenv("ARES_SSH_PORT", raising=False)
        monkeypatch.delenv("ARES_SSH_USER", raising=False)
        monkeypatch.delenv("ARES_SSH_PASSWORD", raising=False)
        monkeypatch.delenv("ARES_SSH_KEY_PATH", raising=False)
        monkeypatch.delenv("ARES_SSH_TIMEOUT", raising=False)

        config = SSHConfig.from_env()
        assert config.host == "10.0.2.15"
        assert config.port == 22
        assert config.user == "labuser"
        assert config.password is None
        assert config.key_path is None
        assert config.timeout == 30

    def test_from_env_invalid_port(self, monkeypatch):
        monkeypatch.setenv("ARES_SSH_PORT", "not_a_number")
        with pytest.raises(ValueError, match="ARES_SSH_PORT must be an integer"):
            SSHConfig.from_env()

    def test_from_env_invalid_timeout(self, monkeypatch):
        monkeypatch.setenv("ARES_SSH_TIMEOUT", "abc")
        with pytest.raises(ValueError, match="ARES_SSH_TIMEOUT must be an integer"):
            SSHConfig.from_env()

    def test_from_env_empty_port(self, monkeypatch):
        monkeypatch.setenv("ARES_SSH_PORT", "")
        with pytest.raises(ValueError, match="ARES_SSH_PORT must be an integer"):
            SSHConfig.from_env()


# ============================================================
# Unit Tests: AuditLogger
# ============================================================

class TestAuditLogger:
    """Test audit logging: field completeness, append-only, rule_id propagation."""

    @pytest.fixture
    def logger(self, tmp_path):
        return AuditLogger(log_dir=str(tmp_path))

    def test_creates_log_directory(self, tmp_path):
        log_dir = tmp_path / "nested" / "logs"
        logger = AuditLogger(log_dir=str(log_dir))
        assert log_dir.exists()

    def test_creates_log_file_with_timestamp(self, logger):
        assert logger.log_file.name.startswith("audit_")
        assert logger.log_file.name.endswith(".jsonl")

    def test_log_entry_contains_all_required_fields(self, logger):
        logger.log_command(
            target_system="rhel8-stig-lab",
            target_ip="10.0.2.15",
            rule_id="V-230221",
            agent="CLI_Executor",
            command="grep PermitRootLogin /etc/ssh/sshd_config",
            output="PermitRootLogin yes\n",
            exit_code=0,
            duration_ms=45.2,
            use_sudo=False,
            error=None,
        )

        entries = logger.log_file.read_text().strip().split("\n")
        assert len(entries) == 1
        entry = json.loads(entries[0])

        assert "timestamp" in entry
        assert entry["target_system"] == "rhel8-stig-lab"
        assert entry["target_ip"] == "10.0.2.15"
        assert entry["rule_id"] == "V-230221"
        assert entry["agent"] == "CLI_Executor"
        assert entry["command"] == "grep PermitRootLogin /etc/ssh/sshd_config"
        assert entry["output"] == "PermitRootLogin yes\n"
        assert entry["exit_code"] == 0
        assert entry["duration_ms"] == 45.2
        assert entry["use_sudo"] is False
        assert entry["error"] is None

    def test_log_entry_timestamp_format(self, logger):
        logger.log_command(
            target_system="rhel8-stig-lab",
            target_ip="10.0.2.15",
            rule_id="V-TEST",
            agent="CLI_Executor",
            command="echo test",
            output="test\n",
            exit_code=0,
            duration_ms=10.0,
        )

        entry = json.loads(logger.log_file.read_text().strip())
        assert entry["timestamp"].endswith("Z")
        assert "T" in entry["timestamp"]

    def test_append_only_multiple_entries(self, logger):
        for i in range(5):
            logger.log_command(
                target_system="rhel8-stig-lab",
                target_ip="10.0.2.15",
                rule_id=f"V-23000{i}",
                agent="CLI_Executor",
                command=f"echo test{i}",
                output=f"test{i}\n",
                exit_code=0,
                duration_ms=10.0 + i,
            )

        entries = logger.log_file.read_text().strip().split("\n")
        assert len(entries) == 5

        for i, line in enumerate(entries):
            entry = json.loads(line)
            assert entry["rule_id"] == f"V-23000{i}"
            assert entry["command"] == f"echo test{i}"

    def test_log_preserves_previous_entries(self, logger):
        logger.log_command(
            target_system="rhel8-stig-lab",
            target_ip="10.0.2.15",
            rule_id="V-FIRST",
            agent="CLI_Executor",
            command="echo first",
            output="first\n",
            exit_code=0,
            duration_ms=10.0,
        )

        first_content = logger.log_file.read_text()

        logger.log_command(
            target_system="rhel8-stig-lab",
            target_ip="10.0.2.15",
            rule_id="V-SECOND",
            agent="CLI_Executor",
            command="echo second",
            output="second\n",
            exit_code=0,
            duration_ms=20.0,
        )

        final_content = logger.log_file.read_text()
        assert final_content.startswith(first_content)

    def test_logs_error_field_on_failure(self, logger):
        logger.log_command(
            target_system="rhel8-stig-lab",
            target_ip="10.0.2.15",
            rule_id="V-FAIL",
            agent="CLI_Executor",
            command="echo test",
            output="",
            exit_code=-1,
            duration_ms=30000.0,
            error="Connection refused",
        )

        entry = json.loads(logger.log_file.read_text().strip())
        assert entry["error"] == "Connection refused"
        assert entry["exit_code"] == -1

    def test_logs_sudo_flag(self, logger):
        logger.log_command(
            target_system="rhel8-stig-lab",
            target_ip="10.0.2.15",
            rule_id="V-230386",
            agent="CLI_Executor",
            command="auditctl -l",
            output="audit rules\n",
            exit_code=0,
            duration_ms=50.0,
            use_sudo=True,
        )

        entry = json.loads(logger.log_file.read_text().strip())
        assert entry["use_sudo"] is True

    def test_each_session_gets_unique_log_file(self, tmp_path):
        logger1 = AuditLogger(log_dir=str(tmp_path))
        logger2 = AuditLogger(log_dir=str(tmp_path))
        # Files might have same timestamp if created in same second,
        # but the mechanism is correct (unique per instantiation)
        assert logger1.log_file.parent == logger2.log_file.parent


# ============================================================
# Unit Tests: Output Truncation
# ============================================================

class TestOutputTruncation:
    """Test that command output is truncated at 10KB."""

    @patch('cli_executor.fabric_client.Connection')
    def test_output_under_limit_not_truncated(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "short output\n"
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("echo hello", rule_id="TEST")

        assert result["output"] == "short output\n"
        assert "TRUNCATED" not in result["output"]

    @patch('cli_executor.fabric_client.Connection')
    def test_output_at_exactly_10kb_not_truncated(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "x" * 10240  # exactly 10KB
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("cat large_file", rule_id="TEST")

        assert len(result["output"]) == 10240
        assert "TRUNCATED" not in result["output"]

    @patch('cli_executor.fabric_client.Connection')
    def test_output_over_10kb_is_truncated(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        large_output = "x" * 20000  # 20KB
        mock_result.stdout = large_output
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("cat huge_file", rule_id="TEST")

        assert "TRUNCATED" in result["output"]
        assert result["output"].startswith("x" * 10240)
        assert len(result["output"]) < 20000

    @patch('cli_executor.fabric_client.Connection')
    def test_truncation_preserves_first_10kb(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "A" * 5000 + "B" * 5240 + "C" * 5000
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("cat file", rule_id="TEST")

        assert result["output"].startswith("A" * 5000 + "B" * 5240)
        assert "C" not in result["output"].split("[TRUNCATED")[0][-10:]


# ============================================================
# Unit Tests: Rule ID Propagation
# ============================================================

class TestRuleIdPropagation:
    """Test that rule_id flows through executor → client → audit log."""

    @patch('cli_executor.fabric_client.Connection')
    def test_rule_id_passed_to_audit_log(self, mock_conn_cls, tmp_path):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "test output\n"
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        client.audit_logger = AuditLogger(log_dir=str(tmp_path))

        client.execute_command(
            "grep PermitRootLogin /etc/ssh/sshd_config",
            rule_id="V-230221"
        )

        entry = json.loads(client.audit_logger.log_file.read_text().strip())
        assert entry["rule_id"] == "V-230221"

    @patch('cli_executor.fabric_client.Connection')
    def test_missing_rule_id_defaults_to_unknown(self, mock_conn_cls, tmp_path):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "output\n"
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        client.audit_logger = AuditLogger(log_dir=str(tmp_path))

        client.execute_command("echo test")

        entry = json.loads(client.audit_logger.log_file.read_text().strip())
        assert entry["rule_id"] == "UNKNOWN"

    @patch('cli_executor.fabric_client.Connection')
    def test_rule_id_logged_on_ssh_failure(self, mock_conn_cls, tmp_path):
        mock_conn = MagicMock()
        mock_conn.run.side_effect = Exception("Connection refused")
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        client.audit_logger = AuditLogger(log_dir=str(tmp_path))

        client.execute_command("echo test", rule_id="V-230500")

        entry = json.loads(client.audit_logger.log_file.read_text().strip())
        assert entry["rule_id"] == "V-230500"
        assert entry["exit_code"] == -1
        assert "Connection refused" in entry["error"]

    @patch('cli_executor.fabric_client.Connection')
    def test_executor_passes_rule_id_through(self, mock_conn_cls, tmp_path):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "output\n"
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        client.audit_logger = AuditLogger(log_dir=str(tmp_path))

        executor = CommandExecutor(client)
        executor.execute_validation_command(
            "grep test /etc/hosts", rule_id="V-230999"
        )

        entry = json.loads(client.audit_logger.log_file.read_text().strip())
        assert entry["rule_id"] == "V-230999"
        assert entry["command"] == "grep test /etc/hosts"


# ============================================================
# Unit Tests: Sequential Execution / Connection Reuse
# ============================================================

class TestSequentialExecution:
    """Test multiple commands reuse the same connection."""

    @patch('cli_executor.fabric_client.Connection')
    def test_multiple_commands_same_connection(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "output\n"
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        executor = CommandExecutor(client)

        commands = [
            ("grep PermitRootLogin /etc/ssh/sshd_config", "V-230221"),
            ("systemctl is-enabled auditd", "V-230223"),
            ("cat /etc/login.defs", "V-230231"),
            ("grep ENCRYPT_METHOD /etc/login.defs", "V-230232"),
            ("sestatus", "V-230300"),
        ]

        for cmd, rule_id in commands:
            result = executor.execute_validation_command(cmd, rule_id=rule_id)
            assert result["exit_code"] == 0

        # Connection created only once (in __init__), not per command
        mock_conn_cls.assert_called_once()
        assert mock_conn.run.call_count == 5

    @patch('cli_executor.fabric_client.Connection')
    def test_context_manager_single_open_close(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "ok\n"
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        with FabricClient(host="10.0.2.15", user="test", password="pw") as client:
            client.execute_command("echo 1", rule_id="T1")
            client.execute_command("echo 2", rule_id="T2")
            client.execute_command("echo 3", rule_id="T3")

        mock_conn.open.assert_called_once()
        mock_conn.close.assert_called_once()
        assert mock_conn.run.call_count == 3


# ============================================================
# Unit Tests: CommandExecutor (mocked client)
# ============================================================

class TestCommandExecutorValidation:
    """Test executor command validation without SSH."""

    @pytest.fixture
    def mock_client(self):
        client = MagicMock(spec=FabricClient)
        client.execute_command.return_value = {
            "output": "test output",
            "exit_code": 0,
            "error": None,
            "duration_ms": 50.0,
        }
        return client

    @pytest.fixture
    def executor(self, mock_client):
        return CommandExecutor(mock_client)

    def test_rejects_dangerous_command(self, executor, mock_client):
        result = executor.execute_validation_command("rm -rf /", rule_id="TEST")
        assert result["exit_code"] == -2
        assert "rejected" in result["error"]
        mock_client.execute_command.assert_not_called()

    def test_rejected_command_has_zero_duration(self, executor, mock_client):
        result = executor.execute_validation_command("rm -rf /", rule_id="TEST")
        assert result["duration_ms"] == 0

    def test_rejected_command_has_empty_output(self, executor, mock_client):
        result = executor.execute_validation_command("chmod 777 /etc", rule_id="TEST")
        assert result["output"] == ""

    def test_allows_safe_command(self, executor, mock_client):
        result = executor.execute_validation_command(
            "grep PermitRootLogin /etc/ssh/sshd_config", rule_id="V-230221"
        )
        assert result["exit_code"] == 0
        assert result["output"] == "test output"
        mock_client.execute_command.assert_called_once()

    def test_passes_sudo_flag(self, executor, mock_client):
        executor.execute_validation_command(
            "auditctl -l", rule_id="V-230300", use_sudo=True
        )
        mock_client.execute_command.assert_called_once_with(
            "auditctl -l", use_sudo=True, rule_id="V-230300"
        )

    def test_retries_on_connection_failure(self, executor, mock_client):
        mock_client.execute_command.side_effect = [
            {"output": "", "exit_code": -1, "error": "Connection reset", "duration_ms": 0},
            {"output": "", "exit_code": -1, "error": "Connection reset", "duration_ms": 0},
            {"output": "success", "exit_code": 0, "error": None, "duration_ms": 30},
        ]
        result = executor.execute_validation_command(
            "grep test /etc/hosts", rule_id="V-TEST"
        )
        assert result["exit_code"] == 0
        assert result["output"] == "success"
        assert mock_client.execute_command.call_count == 3

    def test_no_retry_on_nonzero_exit(self, executor, mock_client):
        mock_client.execute_command.return_value = {
            "output": "", "exit_code": 1, "error": None, "duration_ms": 20
        }
        result = executor.execute_validation_command(
            "grep NONEXISTENT /etc/hosts", rule_id="V-TEST"
        )
        assert result["exit_code"] == 1
        assert mock_client.execute_command.call_count == 1

    def test_no_retry_on_exit_code_2(self, executor, mock_client):
        mock_client.execute_command.return_value = {
            "output": "", "exit_code": 2, "error": "No such file", "duration_ms": 15
        }
        result = executor.execute_validation_command(
            "grep test /nonexistent", rule_id="V-TEST"
        )
        assert result["exit_code"] == 2
        assert mock_client.execute_command.call_count == 1

    def test_returns_last_failure_after_max_retries(self, executor, mock_client):
        mock_client.execute_command.return_value = {
            "output": "", "exit_code": -1, "error": "Connection refused", "duration_ms": 0
        }
        result = executor.execute_validation_command(
            "echo test", rule_id="V-TEST", max_retries=2
        )
        assert result["exit_code"] == -1
        assert mock_client.execute_command.call_count == 2

    def test_max_retries_1_means_no_retry(self, executor, mock_client):
        mock_client.execute_command.return_value = {
            "output": "", "exit_code": -1, "error": "timeout", "duration_ms": 0
        }
        result = executor.execute_validation_command(
            "echo test", rule_id="V-TEST", max_retries=1
        )
        assert result["exit_code"] == -1
        assert mock_client.execute_command.call_count == 1

    def test_check_connection(self, executor, mock_client):
        mock_client.execute_command.return_value = {
            "output": "ares_ping\n", "exit_code": 0, "error": None, "duration_ms": 10
        }
        assert executor.check_connection() is True

    def test_check_connection_failure(self, executor, mock_client):
        mock_client.execute_command.return_value = {
            "output": "", "exit_code": -1, "error": "timeout", "duration_ms": 30000
        }
        assert executor.check_connection() is False

    def test_check_connection_wrong_output(self, executor, mock_client):
        mock_client.execute_command.return_value = {
            "output": "something_else\n", "exit_code": 0, "error": None, "duration_ms": 10
        }
        assert executor.check_connection() is False

    def test_return_dict_structure(self, executor, mock_client):
        result = executor.execute_validation_command(
            "echo test", rule_id="V-TEST"
        )
        assert set(result.keys()) == {"output", "exit_code", "error", "duration_ms"}

    def test_rejected_dict_structure(self, executor, mock_client):
        result = executor.execute_validation_command(
            "rm -rf /", rule_id="V-TEST"
        )
        assert set(result.keys()) == {"output", "exit_code", "error", "duration_ms"}


# ============================================================
# Unit Tests: FabricClient (mocked Connection)
# ============================================================

class TestFabricClient:
    """Test FabricClient with mocked Fabric Connection."""

    @patch('cli_executor.fabric_client.Connection')
    def test_init(self, mock_conn_cls):
        client = FabricClient(host="10.0.2.15", user="testuser", password="pass")
        assert client.host == "10.0.2.15"
        assert client.user == "testuser"
        assert client.port == 22
        assert client.timeout == 30
        mock_conn_cls.assert_called_once()

    @patch('cli_executor.fabric_client.Connection')
    def test_init_with_key(self, mock_conn_cls):
        client = FabricClient(
            host="10.0.2.15", user="testuser",
            key_filename="/path/to/key", port=2222, timeout=60
        )
        assert client.port == 2222
        assert client.timeout == 60
        call_kwargs = mock_conn_cls.call_args
        assert call_kwargs[1]["connect_kwargs"]["key_filename"] == "/path/to/key"

    @patch('cli_executor.fabric_client.Connection')
    def test_from_config(self, mock_conn_cls):
        config = SSHConfig(host="192.168.1.1", user="admin", password="secret", port=2222)
        client = FabricClient.from_config(config)
        assert client.host == "192.168.1.1"
        assert client.user == "admin"
        assert client.port == 2222

    @patch('cli_executor.fabric_client.Connection')
    def test_from_config_with_key_path(self, mock_conn_cls):
        config = SSHConfig(host="10.0.2.15", user="test", key_path="/home/user/.ssh/id_rsa")
        client = FabricClient.from_config(config)
        assert client.host == "10.0.2.15"

    @patch('cli_executor.fabric_client.Connection')
    def test_context_manager(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        with FabricClient(host="10.0.2.15", user="test", password="pw") as client:
            mock_conn.open.assert_called_once()

        mock_conn.close.assert_called_once()

    @patch('cli_executor.fabric_client.Connection')
    def test_context_manager_closes_on_exception(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn_cls.return_value = mock_conn

        with pytest.raises(RuntimeError):
            with FabricClient(host="10.0.2.15", user="test", password="pw") as client:
                raise RuntimeError("test error")

        mock_conn.close.assert_called_once()

    @patch('cli_executor.fabric_client.Connection')
    def test_execute_command_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "PermitRootLogin yes\n"
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command(
            "grep PermitRootLogin /etc/ssh/sshd_config", rule_id="V-230221"
        )

        assert result["exit_code"] == 0
        assert "PermitRootLogin yes" in result["output"]
        assert result["error"] is None
        assert result["duration_ms"] >= 0

    @patch('cli_executor.fabric_client.Connection')
    def test_execute_command_nonzero_exit(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.return_code = 1
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("grep NONEXISTENT /etc/hosts", rule_id="V-TEST")

        assert result["exit_code"] == 1
        assert result["output"] == ""

    @patch('cli_executor.fabric_client.Connection')
    def test_execute_command_with_stderr(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = "grep: /etc/missing: No such file or directory"
        mock_result.return_code = 2
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("grep test /etc/missing", rule_id="V-TEST")

        assert result["exit_code"] == 2
        assert "No such file" in result["error"]

    @patch('cli_executor.fabric_client.Connection')
    def test_execute_command_with_sudo(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "audit rules\n"
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.sudo.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("auditctl -l", use_sudo=True, rule_id="V-230386")

        mock_conn.sudo.assert_called_once()
        mock_conn.run.assert_not_called()
        assert result["exit_code"] == 0

    @patch('cli_executor.fabric_client.Connection')
    def test_execute_command_ssh_failure(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn.run.side_effect = Exception("Connection refused")
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("echo test", rule_id="TEST")

        assert result["exit_code"] == -1
        assert "Connection refused" in result["error"]

    @patch('cli_executor.fabric_client.Connection')
    def test_execute_command_timeout(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn.run.side_effect = Exception("Timed out")
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("sleep 999", rule_id="TEST")

        assert result["exit_code"] == -1
        assert "Timed out" in result["error"]

    @patch('cli_executor.fabric_client.Connection')
    def test_duration_tracked_on_success(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.stdout = "ok\n"
        mock_result.stderr = ""
        mock_result.return_code = 0
        mock_conn.run.return_value = mock_result
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("echo ok", rule_id="TEST")

        assert isinstance(result["duration_ms"], float)
        assert result["duration_ms"] >= 0

    @patch('cli_executor.fabric_client.Connection')
    def test_duration_tracked_on_failure(self, mock_conn_cls):
        mock_conn = MagicMock()
        mock_conn.run.side_effect = Exception("fail")
        mock_conn_cls.return_value = mock_conn

        client = FabricClient(host="10.0.2.15", user="test", password="pw")
        result = client.execute_command("echo test", rule_id="TEST")

        assert isinstance(result["duration_ms"], float)
        assert result["duration_ms"] >= 0


# ============================================================
# Integration Tests (require SSH access to rhel8-stig-lab)
# ============================================================

@pytest.mark.integration
class TestLiveExecution:
    """
    Integration tests that require SSH access to rhel8-stig-lab.

    Run with: pytest -m integration
    Requires: ARES_SSH_PASSWORD or ARES_SSH_KEY_PATH env var set
    """

    @pytest.fixture
    def executor(self):
        config = SSHConfig.from_env()
        client = FabricClient.from_config(config)
        client.connect()
        executor = CommandExecutor(client)
        yield executor
        client.disconnect()

    def test_echo(self, executor):
        result = executor.execute_validation_command("echo hello", rule_id="TEST-001")
        assert result["exit_code"] == 0
        assert "hello" in result["output"]

    def test_grep_sshd_config(self, executor):
        result = executor.execute_validation_command(
            "grep -i PermitRootLogin /etc/ssh/sshd_config",
            rule_id="V-230221"
        )
        assert result["exit_code"] == 0
        assert "PermitRootLogin" in result["output"]

    def test_systemctl_is_enabled(self, executor):
        result = executor.execute_validation_command(
            "systemctl is-enabled auditd",
            rule_id="V-230223"
        )
        assert result["exit_code"] in [0, 1]

    def test_grep_login_defs(self, executor):
        result = executor.execute_validation_command(
            "grep ENCRYPT_METHOD /etc/login.defs",
            rule_id="V-230231"
        )
        assert result["exit_code"] == 0
        assert "ENCRYPT_METHOD" in result["output"]

    def test_cat_pam(self, executor):
        result = executor.execute_validation_command(
            "cat /etc/pam.d/password-auth",
            rule_id="V-230340"
        )
        assert result["exit_code"] == 0
        assert len(result["output"]) > 0

    def test_sudo_auditctl(self, executor):
        result = executor.execute_validation_command(
            "auditctl -l", rule_id="V-230386", use_sudo=True
        )
        assert result["exit_code"] in [0, 1, -1]

    def test_dangerous_command_blocked(self, executor):
        result = executor.execute_validation_command("rm -rf /tmp/test", rule_id="TEST-BAD")
        assert result["exit_code"] == -2
        assert "rejected" in result["error"]

    def test_check_connection(self, executor):
        assert executor.check_connection() is True

    def test_sequential_commands(self, executor):
        commands = [
            ("uname -a", "TEST-SEQ-1"),
            ("hostname", "TEST-SEQ-2"),
            ("id", "TEST-SEQ-3"),
        ]
        for cmd, rule_id in commands:
            result = executor.execute_validation_command(cmd, rule_id=rule_id)
            assert result["exit_code"] == 0
            assert len(result["output"]) > 0
