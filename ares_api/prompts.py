"""
Platform-aware agent prompts.

The agent prompts in genesis_agents/ were written for a RHEL 8 target over
SSH. For a run against a saved target of another platform, the bridge hands
the agent the same prompt with a platform block added at the top and bottom
and the RHEL-specific wording replaced. The files in genesis_agents/ are not
changed, and runs on the default target use them as they are.
"""

import copy
from pathlib import Path
from typing import Any, Dict, List

BAR = "═" * 79


def platform_block(target: Dict[str, Any]) -> str:
    label, shell = target["platform_label"], target["shell"]
    lines = [BAR, f"TARGET PLATFORM: {label}  (this overrides any RHEL 8 or SSH wording below)", BAR, ""]
    if target["backend"] == "config":
        lines += [
            f"The target is a SAVED CONFIGURATION FILE from a {label} device, not a live device.",
            "execute_command answers only configuration queries:",
            "  show running-config",
            "  show running-config | include <text>     (also: exclude, begin, section, count)",
            "Do not use sudo. Do not send any other command.",
            "If the Check Text needs live device state (interface status, logged-in users, clock, "
            "running processes), do not guess: set requires_human_review to true and say which "
            "live command a reviewer should run.",
        ]
    elif shell == "powershell":
        lines += [
            "Commands run in Windows PowerShell over WinRM. There is no sudo: always send use_sudo=false.",
            "Do NOT send Linux commands (grep, cat, awk, systemctl, rpm).",
            target["style"],
            "Only read-only commands are accepted. Anything that changes the system is rejected "
            "(exit_code -2); if that happens, rephrase as a read-only query.",
            "Registry Check Text: read the value with Get-ItemProperty and compare it to the required value. "
            "A missing value usually means the setting is not configured; follow the Check Text on "
            "whether that is a finding.",
        ]
    elif shell == "network":
        lines += [
            "Commands run on the device CLI. There is no sudo: always send use_sudo=false.",
            target["style"],
            "Never enter configuration mode. One command per call.",
        ]
    else:
        sudo = ("Use sudo when the Check Text needs root." if target.get("use_sudo")
                else "sudo is not available on this target: always send use_sudo=false. If a check needs "
                     "more privilege than the account has, say so and set requires_human_review to true.")
        lines += [f"Commands run in a POSIX shell on {label}"
                  + (" on this machine." if target["backend"] == "local" else " over SSH."), target["style"], sudo]
    lines += ["", "Use the commands in the Check Text first, adapted only as far as this platform requires.", ""]
    return "\n".join(lines)


def adapt_prompt(text: str, target: Dict[str, Any]) -> str:
    label = target["platform_label"]
    body = (text.replace("RHEL 8 target system", f"{label} target system")
                .replace("RHEL 8 STIG", f"{label} STIG")
                .replace("RHEL 8", label))
    if target["backend"] != "ssh":
        body = body.replace("via SSH", "on the target").replace("over SSH", "on the target")
    block = platform_block(target)
    return f"{block}\n{body}\n\n{block}"


def write_prompt(source: str, target: Dict[str, Any], folder: Path) -> str:
    """Write the adapted copy of a prompt file into the run folder; return its path."""
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / Path(source).name
    out.write_text(adapt_prompt(Path(source).read_text(encoding="utf-8"), target), encoding="utf-8")
    return str(out)


def adapt_tools(tools: List[Dict[str, Any]], target: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Reword the execute_command tool definition for the target's platform."""
    tools = copy.deepcopy(tools)
    how = {"powershell": "Read-only PowerShell command to run on the Windows target",
           "network": "Show command to run on the network device",
           }.get(target["shell"], "Shell command to execute on target host")
    for tool in tools:
        function = tool.get("function", {})
        if function.get("name") != "execute_command":
            continue
        function["description"] = (
            f"Execute a read-only STIG validation command on the {target['platform_label']} target "
            f"({target['backend']}). Use this to run Check Text commands and validate STIG findings. "
            "Returns command output, exit code, and execution metadata.")
        properties = function.get("parameters", {}).get("properties", {})
        if "command" in properties:
            properties["command"]["description"] = how
        if "use_sudo" in properties and not target.get("use_sudo"):
            properties["use_sudo"]["description"] = "Not available on this target: always false"
            properties["use_sudo"]["default"] = False
    return tools
