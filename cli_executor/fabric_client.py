"""
Fabric SSH client wrapper for ARES.

Connects to rhel8-stig-lab and executes read-only commands.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional
import logging

from fabric import Connection

from .audit_logger import AuditLogger
from .config import SSHConfig

logger = logging.getLogger(__name__)

MAX_OUTPUT_SIZE = 10240  # 10KB truncation limit


class FabricClient:
    """SSH client wrapper using Fabric."""

    def __init__(self, host: str, user: str, password: Optional[str] = None,
                 key_filename: Optional[str] = None, port: int = 22,
                 timeout: int = 30):
        self.host = host
        self.user = user
        self.port = port
        self.timeout = timeout
        self.audit_logger = AuditLogger()

        connect_kwargs = {}
        if password:
            connect_kwargs["password"] = password
        if key_filename:
            connect_kwargs["key_filename"] = key_filename

        self.connection = Connection(
            host=host,
            user=user,
            port=port,
            connect_kwargs=connect_kwargs,
            connect_timeout=timeout,
        )
        logger.info(f"FabricClient initialized for {user}@{host}:{port}")

    @classmethod
    def from_config(cls, config: SSHConfig) -> FabricClient:
        """Create FabricClient from an SSHConfig instance."""
        return cls(
            host=config.host,
            user=config.user,
            password=config.password,
            key_filename=config.key_path,
            port=config.port,
            timeout=config.timeout,
        )

    def connect(self):
        """Establish SSH connection."""
        try:
            self.connection.open()
            logger.info(f"Connected to {self.user}@{self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Connection failed to {self.host}: {e}")
            raise

    def execute_command(self, command: str, use_sudo: bool = False,
                        rule_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute command on target system.

        Args:
            command: Command to execute
            use_sudo: Whether to use sudo
            rule_id: STIG Rule ID (for audit logging)

        Returns:
            Dict with: output, exit_code, error, duration_ms
        """
        start_time = time.time()

        try:
            if use_sudo:
                result = self.connection.sudo(
                    command, hide=True, warn=True, timeout=self.timeout
                )
            else:
                result = self.connection.run(
                    command, hide=True, warn=True, timeout=self.timeout
                )

            duration_ms = (time.time() - start_time) * 1000

            output = result.stdout
            if len(output) > MAX_OUTPUT_SIZE:
                output = output[:MAX_OUTPUT_SIZE] + "\n... [TRUNCATED - output exceeded 10KB]"

            error = result.stderr if result.stderr else None

            self.audit_logger.log_command(
                target_system="rhel8-stig-lab",
                target_ip=self.host,
                rule_id=rule_id or "UNKNOWN",
                agent="CLI_Executor",
                command=command,
                output=output,
                exit_code=result.return_code,
                duration_ms=duration_ms,
                use_sudo=use_sudo,
                error=error,
            )

            return {
                "output": output,
                "exit_code": result.return_code,
                "error": error,
                "duration_ms": duration_ms,
            }
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Command execution failed: {e}")

            self.audit_logger.log_command(
                target_system="rhel8-stig-lab",
                target_ip=self.host,
                rule_id=rule_id or "UNKNOWN",
                agent="CLI_Executor",
                command=command,
                output="",
                exit_code=-1,
                duration_ms=duration_ms,
                use_sudo=use_sudo,
                error=str(e),
            )

            return {
                "output": "",
                "exit_code": -1,
                "error": str(e),
                "duration_ms": duration_ms,
            }

    def disconnect(self):
        """Close SSH connection."""
        if self.connection:
            self.connection.close()
            logger.info(f"Disconnected from {self.host}")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False
