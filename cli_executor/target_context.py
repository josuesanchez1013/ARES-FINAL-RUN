"""
The target a run is checking, and the one place commands are run on it.

The ARES API sets the active target for the length of a run step. While it
is set, the agents' execute_command tool goes through run_on_target():
validate with the platform's safety rules, run on the target's backend,
write the audit log. With no active target, execute_command behaves exactly
as it did before (SSH to the host in ARES_SSH_*).
"""

import logging
import threading
import time
from typing import Any, Dict, Optional

from security.platform_validators import validator_for

from .audit_logger import AuditLogger
from .backends import BackendError, build_backend

logger = logging.getLogger(__name__)

_active: Optional[Dict[str, Any]] = None
_backend = None
_audit: Optional[AuditLogger] = None
_lock = threading.RLock()


def set_active_target(target: Optional[Dict[str, Any]]) -> None:
    """Make `target` the one execute_command reaches; None restores the default."""
    global _active, _backend
    with _lock:
        if _backend is not None:
            _backend.close()
        _active, _backend = target, None


def active_target() -> Optional[Dict[str, Any]]:
    return _active


def _audit_log() -> AuditLogger:
    global _audit
    if _audit is None:
        _audit = AuditLogger()
    return _audit


def run_on_target(target: Dict[str, Any], command: str, rule_id: str = "", use_sudo: bool = False,
                  max_retries: int = 3, backend=None, audit: bool = True) -> Dict[str, Any]:
    """Validate, execute and audit one command. Never raises."""
    validator = validator_for(target.get("shell", "none"), target.get("family", ""))
    if not validator.validate_command(command):
        reason = getattr(validator, "reason", None) or "blocked by the read-only command rules"
        logger.error("Command rejected for %s: %s (%s)", target.get("name"), command, reason)
        result = {"output": "", "exit_code": -2, "duration_ms": 0,
                  "error": f"Command rejected by safety validator ({reason}): {command}"}
        _log(target, rule_id, command, result, use_sudo, audit)
        return dict(result, status="error")

    global _backend
    close_after = False
    try:
        with _lock:
            if backend is not None:
                runner = backend
            elif _active is target:
                if _backend is None:
                    _backend = build_backend(target)   # one connection for the whole step
                runner = _backend
            else:
                runner, close_after = build_backend(target), True
    except BackendError as exc:
        result = {"output": "", "exit_code": -1, "error": str(exc), "duration_ms": 0}
        _log(target, rule_id, command, result, use_sudo, audit)
        return dict(result, status="error")
    except Exception as exc:  # bad host, missing key, ...
        result = {"output": "", "exit_code": -1, "error": f"{type(exc).__name__}: {exc}", "duration_ms": 0}
        _log(target, rule_id, command, result, use_sudo, audit)
        return dict(result, status="error")

    sudo = bool(use_sudo and target.get("use_sudo", False))
    result: Dict[str, Any] = {}
    for attempt in range(max(1, max_retries)):
        result = runner.run(command, use_sudo=sudo, rule_id=rule_id)
        if result["exit_code"] != -1:
            break
        if attempt < max_retries - 1:
            time.sleep(min(2 ** attempt, 4))
    if close_after:
        runner.close()
    _log(target, rule_id, command, result, sudo, audit)
    return dict(result, status="success" if result["exit_code"] >= 0 else "error")


def _log(target: Dict[str, Any], rule_id: str, command: str, result: Dict[str, Any],
         use_sudo: bool, audit: bool) -> None:
    if not audit:
        return
    try:
        _audit_log().log_command(
            target_system=target.get("name") or target.get("host") or "target",
            target_ip=target.get("host") or target.get("backend", ""),
            rule_id=rule_id or "UNKNOWN", agent=f"CLI_Executor/{target.get('backend')}",
            command=command, output=result.get("output", ""), exit_code=result.get("exit_code", -1),
            duration_ms=result.get("duration_ms", 0), use_sudo=use_sudo, error=result.get("error"))
    except Exception:  # the audit log must never break a check
        logger.exception("Audit log write failed")
