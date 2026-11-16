"""
Audit logger for ARES command executions.

Logs every command execution to append-only JSON log.
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class AuditLogger:
    """Audit trail logger for CLI command executions."""
    
    def __init__(self, log_dir: str = "data/logs"):
        """
        Initialize audit logger.
        
        Args:
            log_dir: Directory for audit logs
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create new log file for this run
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"audit_{timestamp}.jsonl"
    
    def log_command(self, 
                   target_system: str,
                   target_ip: str,
                   rule_id: str,
                   agent: str,
                   command: str,
                   output: str,
                   exit_code: int,
                   duration_ms: float,
                   use_sudo: bool = False,
                   error: Optional[str] = None):
        """
        Log command execution to audit trail.
        
        All parameters are recorded for security/compliance.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "target_system": target_system,
            "target_ip": target_ip,
            "rule_id": rule_id,
            "agent": agent,
            "command": command,
            "use_sudo": use_sudo,
            "output": output,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "error": error
        }
        
        # Append to log file (append-only, never modify)
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        
        logger.info(f"Audit log: {rule_id} - {command[:50]}... - exit_code={exit_code}")
