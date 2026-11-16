"""
Command execution logic for ARES.

Higher-level wrapper around FabricClient with retry logic and validation.
"""

import time
from typing import Any, Dict
import logging
from .fabric_client import FabricClient
from security.command_validator import CommandValidator

logger = logging.getLogger(__name__)


class CommandExecutor:
    """High-level command executor with validation and retry logic."""

    def __init__(self, client: FabricClient):
        self.client = client
        self.validator = CommandValidator()

    def execute_validation_command(self, command: str, rule_id: str,
                                   use_sudo: bool = False,
                                   max_retries: int = 3) -> Dict[str, Any]:
        """
        Execute a STIG validation command with safety checks and retry logic.

        Args:
            command: Command to execute on target system
            rule_id: STIG Rule ID for audit trail
            use_sudo: Whether to run with sudo
            max_retries: Max retries on connection failures only

        Returns:
            Dict with: output, exit_code, error, duration_ms
            exit_code -2 means command was rejected by validator
            exit_code -1 means SSH/connection failure
        """
        if not self.validator.validate_command(command):
            logger.error(f"Command rejected by validator: {command}")
            return {
                "output": "",
                "exit_code": -2,
                "error": f"Command rejected by safety validator: {command}",
                "duration_ms": 0,
            }

        last_result = None
        for attempt in range(max_retries):
            result = self.client.execute_command(
                command, use_sudo=use_sudo, rule_id=rule_id
            )

            # If we got a real result (even non-zero exit), return it.
            # Non-zero exit codes are expected for STIG checks (e.g., grep not found = 1).
            # Only retry on connection/SSH errors (exit_code == -1).
            if result["exit_code"] != -1:
                return result

            last_result = result

            if attempt < max_retries - 1:
                wait = 2 ** attempt
                logger.warning(
                    f"Connection error on attempt {attempt + 1}/{max_retries}, "
                    f"retrying in {wait}s: {result['error']}"
                )
                time.sleep(wait)

        logger.error(f"All {max_retries} attempts failed for: {command}")
        return last_result

    def check_connection(self) -> bool:
        """Verify SSH connection is alive with a simple echo command."""
        result = self.client.execute_command("echo ares_ping", rule_id="HEALTH_CHECK")
        return result["exit_code"] == 0 and "ares_ping" in result["output"]
