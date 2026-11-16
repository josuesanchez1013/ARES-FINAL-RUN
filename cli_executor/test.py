"""Quick manual test script for CLI executor (run directly, not via pytest)."""

from cli_executor.config import SSHConfig
from cli_executor.fabric_client import FabricClient
from cli_executor.executor import CommandExecutor


def test_config():
    cfg = SSHConfig.from_env()
    print("Loaded config:", cfg)
    cfg.validate()
    print("Config is valid\n")


def test_connection():
    cfg = SSHConfig.from_env()
    client = FabricClient.from_config(cfg)

    with client:
        executor = CommandExecutor(client, strict_mode=False)

        print("--- Connection health check ---")
        print("Connected:", executor.check_connection())

        print("\n--- STIG validation: V-230221 ---")
        result = executor.execute_validation_command(
            "grep -i PermitRootLogin /etc/ssh/sshd_config",
            rule_id="V-230221"
        )
        print(f"Exit code: {result['exit_code']}")
        print(f"Output: {result['output']}")
        print(f"Duration: {result['duration_ms']:.1f}ms")

        print("\n--- Dangerous command (should be rejected) ---")
        result = executor.execute_validation_command("rm -rf /tmp", rule_id="TEST-BAD")
        print(f"Exit code: {result['exit_code']}")
        print(f"Error: {result['error']}")


if __name__ == "__main__":
    test_config()
    print("=" * 50)
    test_connection()
