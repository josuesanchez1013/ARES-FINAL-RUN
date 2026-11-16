"""
SSH connection configuration for ARES.
"""

from dataclasses import dataclass
from typing import Optional
import os
from pathlib import Path


@dataclass
class SSHConfig:
    """SSH connection configuration."""
    
    host: str = "10.0.2.15"  # rhel8-stig-lab default
    port: int = 22
    user: str = "labuser"
    password: Optional[str] = None
    key_path: Optional[str] = None
    timeout: int = 30
    
    @classmethod
    def from_env(cls) -> 'SSHConfig':
        """
        Load configuration from environment variables.
        
        Environment variables:
            ARES_SSH_HOST: Target hostname/IP
            ARES_SSH_PORT: SSH port
            ARES_SSH_USER: SSH username
            ARES_SSH_PASSWORD: SSH password (not recommended)
            ARES_SSH_KEY_PATH: Path to SSH private key
            ARES_SSH_TIMEOUT: Connection timeout in seconds
        """
        try:
            port = int(os.getenv("ARES_SSH_PORT", "22"))
        except ValueError:
            raise ValueError(
                f"ARES_SSH_PORT must be an integer, got: {os.getenv('ARES_SSH_PORT')!r}"
            )

        try:
            timeout = int(os.getenv("ARES_SSH_TIMEOUT", "30"))
        except ValueError:
            raise ValueError(
                f"ARES_SSH_TIMEOUT must be an integer, got: {os.getenv('ARES_SSH_TIMEOUT')!r}"
            )

        return cls(
            host=os.getenv("ARES_SSH_HOST", "10.0.2.15"),
            port=port,
            user=os.getenv("ARES_SSH_USER", "labuser"),
            password=os.getenv("ARES_SSH_PASSWORD"),
            key_path=os.getenv("ARES_SSH_KEY_PATH"),
            timeout=timeout,
        )

    def validate(self) -> bool:
        """Validate configuration."""


        # Either password or key_path must be provided
        if not self.password and not self.key_path:
            raise ValueError("SSHConfig: either password or key_path must be set")

        # If key_path is provided, verify it exists
        if self.key_path is not None and self.key_path != "":
            key_file = Path(self.key_path).expanduser()
            if not key_file.exists():
                raise ValueError(f"SSHConfig: key file not found at {key_file}")

        # Basic host check
        if not isinstance(self.host, str) or not self.host:
            raise ValueError("SSHConfig: host must be a non-empty string")

        # You can add more checks later (host format, port range, etc.)
        return True
            
