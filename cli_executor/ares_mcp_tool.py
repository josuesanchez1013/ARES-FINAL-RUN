# cli_executor_mcp_tool.py
"""
MCP‑compatible wrapper around the existing ARES CLI executor.

The wrapper exposes a single method `execute_command` that:
* builds a FabricClient from the environment (or from optional overrides)
* runs the requested command through the existing CommandExecutor
* returns a small, JSON‑serialisable dict (status, output, exit_code, …)
"""

import os
from typing import Dict, Optional

# Import the original library components
from cli_executor.config import SSHConfig
from cli_executor.fabric_client import FabricClient
from cli_executor.executor import CommandExecutor

# ----------------------------------------------------------------------
# Helper – build a FabricClient from env / explicit arguments
# ----------------------------------------------------------------------
def _build_client(
    host: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    port: Optional[int] = None,
    timeout: Optional[int] = None,
) -> FabricClient:
    """
    Create a FabricClient using the same precedence logic that the CLI
    already uses (env vars → function arguments → defaults).
    """
    # Load defaults from the environment first
    env_cfg = SSHConfig.from_env()

    cfg = SSHConfig(
        host=host or env_cfg.host,
        port=port if port is not None else env_cfg.port,
        user=user or env_cfg.user,
        password=password or env_cfg.password,
        key_path=key_path or env_cfg.key_path,
        timeout=timeout if timeout is not None else env_cfg.timeout,
    )
    # Validate early – a mis‑configuration will be reported as a JSON‑RPC error
    cfg.validate()

    # Build the Fabric client that the original executor expects
    return FabricClient.from_config(cfg)


# ----------------------------------------------------------------------
# Public MCP‑tool class – this is what FastMCP will expose
# ----------------------------------------------------------------------
class ARESCliMcpTool:
    """
    FastMCP‑compatible tool that re‑uses the existing CLI executor.

    **Tool name (used by Genesis)** – `execute_command`
    **Parameters (JSON‑RPC)**:
        - `command`  (str, required) – the shell command to run on the target host
        - `rule_id` (str, required) – STIG rule identifier for audit logging
        - `use_sudo` (bool, optional, default: False)
        - `max_retries` (int, optional, default: 3)
        - *optional connection overrides* (`host`, `user`, `password`, `key_path`, `port`, `timeout`)
    **Return value** – dict with the same schema that `CommandExecutor.execute_validation_command`
    returns, plus a top‑level ``status`` field (`"success"` or `"error"`).

    The class is intentionally thin – all heavy lifting lives in the original
    `cli_executor` package.
    """

    # FastMCP expects a **callable** attribute called ``__call__`` or a method
    # that will be registered with ``@mcp.tool()`` later.  We expose a plain
    # method called ``run`` and let the server register it.

    def __init__(self):
        # No persistent state – a new Fabric client is created for each call.
        # This keeps the tool stateless and safe for concurrent requests.
        pass

    # ------------------------------------------------------------------
    # Core entry point – this is what the RPC layer will invoke.
    # ------------------------------------------------------------------
    def run(
        self,
        command: str,
        rule_id: str,
        use_sudo: bool = False,
        max_retries: int = 3,
        host: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> Dict:
        """
        Execute a STIG validation command on the remote host.

        All parameters map 1‑to‑1 to the underlying `CommandExecutor`.
        The function returns the raw dict from `execute_validation_command`
        with an added ``status`` field for easier client‑side handling.
        """
        # A run that chose a saved target (any platform) goes through the
        # target's own backend and safety rules. Without one, the original
        # SSH path below is used unchanged.
        from cli_executor.target_context import active_target, run_on_target
        target = active_target()
        if target is not None:
            return run_on_target(target, command, rule_id=rule_id, use_sudo=use_sudo,
                                 max_retries=max_retries)

        # 1️⃣ Build a fresh Fabric client for this request
        client = _build_client(
            host=host,
            user=user,
            password=password,
            key_path=key_path,
            port=port,
            timeout=timeout,
        )

        # High‑level executor 
        executor = CommandExecutor(client)

        # Run the command with the retry policy 
        result = executor.execute_validation_command(
            command=command,
            rule_id=rule_id,
            use_sudo=use_sudo,
            max_retries=max_retries,
        )

        # top‑level ``status`` flag 
        result["status"] = "success" if result["exit_code"] >= 0 else "error"
        return result
