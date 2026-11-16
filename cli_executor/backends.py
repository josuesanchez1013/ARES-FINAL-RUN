"""
Execution backends: how ARES runs a read-only check on a target.

Every backend has the same call, run(command, use_sudo, rule_id), and returns
{"output", "exit_code", "error", "duration_ms"}; exit_code -1 means the
target could not be reached. Validation and audit logging happen in
run_on_target() (target_context.py), not here, so no backend can skip them.

    ssh     Linux, Solaris, AIX, HP-UX, macOS, ESXi, and network devices (Fabric)
    local   the machine ARES itself runs on (subprocess; PowerShell on Windows)
    winrm   Windows over WinRM (pywinrm, optional dependency)
    config  a saved device configuration file, queried with show commands
"""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

MAX_OUTPUT_SIZE = 10240


class BackendError(RuntimeError):
    """The backend cannot be set up (missing dependency, bad settings)."""


def _result(output: str, exit_code: int, error: Optional[str], started: float) -> Dict[str, Any]:
    if output and len(output) > MAX_OUTPUT_SIZE:
        output = output[:MAX_OUTPUT_SIZE] + "\n... [TRUNCATED - output exceeded 10KB]"
    return {"output": output or "", "exit_code": exit_code, "error": error or None,
            "duration_ms": (time.time() - started) * 1000}


def _secret(target: Dict[str, Any]) -> Optional[str]:
    """Passwords are never stored with a target: only the NAME of an environment variable."""
    name = target.get("password_env")
    return os.environ.get(name) if name else None


class SSHBackend:
    name = "ssh"

    def __init__(self, target: Dict[str, Any]):
        from fabric import Connection  # imported here so other backends work without it
        connect_kwargs: Dict[str, Any] = {}
        password = _secret(target)
        if password:
            connect_kwargs["password"] = password
        if target.get("key_path"):
            connect_kwargs["key_filename"] = str(Path(target["key_path"]).expanduser())
        if not connect_kwargs:
            raise BackendError("SSH needs a key file or a password environment variable for this target")
        self.timeout = int(target.get("timeout") or 30)
        self.sudo_allowed = bool(target.get("use_sudo", True))
        self.connection = Connection(host=target["host"], user=target.get("user") or None,
                                     port=int(target.get("port") or 22),
                                     connect_kwargs=connect_kwargs, connect_timeout=self.timeout)

    def run(self, command: str, use_sudo: bool = False, rule_id: str = "") -> Dict[str, Any]:
        started = time.time()
        try:
            runner = self.connection.sudo if (use_sudo and self.sudo_allowed) else self.connection.run
            result = runner(command, hide=True, warn=True, timeout=self.timeout)
            return _result(result.stdout, result.return_code, result.stderr, started)
        except Exception as exc:  # connection, auth, timeout
            return _result("", -1, str(exc), started)

    def close(self) -> None:
        try:
            self.connection.close()
        except Exception:
            pass


class LocalBackend:
    name = "local"

    def __init__(self, target: Dict[str, Any]):
        self.timeout = int(target.get("timeout") or 30)
        self.powershell = target.get("shell") == "powershell"
        self.sudo_allowed = bool(target.get("use_sudo", False))

    def run(self, command: str, use_sudo: bool = False, rule_id: str = "") -> Dict[str, Any]:
        started = time.time()
        if self.powershell:
            argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command]
        elif use_sudo and self.sudo_allowed:
            argv = ["sudo", "-n", "sh", "-c", command]
        else:
            argv = ["sh", "-c", command]
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout,
                                  stdin=subprocess.DEVNULL)
            return _result(done.stdout, done.returncode, done.stderr, started)
        except subprocess.TimeoutExpired:
            return _result("", -1, f"timed out after {self.timeout}s", started)
        except OSError as exc:
            return _result("", -1, str(exc), started)

    def close(self) -> None:
        pass


class WinRMBackend:
    name = "winrm"

    def __init__(self, target: Dict[str, Any]):
        try:
            import winrm  # optional: pip install pywinrm
        except ImportError:
            raise BackendError("Windows targets need the pywinrm package (pip install pywinrm). "
                               "It is listed in requirements-windows.txt.") from None
        password = _secret(target)
        transport = (target.get("winrm_transport") or "ntlm").lower()
        if transport != "kerberos" and not (target.get("user") and password):
            raise BackendError("WinRM needs a user and a password environment variable "
                               "(or the kerberos transport with a valid ticket)")
        https = bool(target.get("winrm_https", True))
        port = int(target.get("port") or (5986 if https else 5985))
        endpoint = f"{'https' if https else 'http'}://{target['host']}:{port}/wsman"
        self.timeout = int(target.get("timeout") or 60)
        options: Dict[str, Any] = {
            "transport": transport, "server_cert_validation": "validate",   # never "ignore"
            "operation_timeout_sec": self.timeout, "read_timeout_sec": self.timeout + 10,
        }
        ca_bundle = target.get("ca_bundle") or os.environ.get("SSL_CERT_FILE")
        if ca_bundle:
            options["ca_trust_path"] = ca_bundle
        self.session = winrm.Session(endpoint, auth=(target.get("user") or "", password or ""), **options)

    def run(self, command: str, use_sudo: bool = False, rule_id: str = "") -> Dict[str, Any]:
        started = time.time()
        try:
            reply = self.session.run_ps(command)
            output = reply.std_out.decode("utf-8", errors="replace")
            error = reply.std_err.decode("utf-8", errors="replace")
            if error.startswith("#< CLIXML"):   # progress records, not an error
                error = "" if "<S S=\"Error\">" not in error else error
            return _result(output, reply.status_code, error, started)
        except Exception as exc:
            return _result("", -1, str(exc), started)

    def close(self) -> None:
        pass


class ConfigBackend:
    """Answer show commands from a saved device configuration.

    Supports the commands STIG Check Text uses against a configuration:
    `show running-config` / `show startup-config` / `show configuration`
    (and abbreviations) with the filters include, exclude, begin, section,
    match, except, count and `display set` (passed through). Anything that
    needs live device state returns a clear message so the agent can mark
    the rule for manual review instead of guessing.
    """
    name = "config"
    _SHOW_CONFIG = re.compile(r"(?i)^(sh|sho|show|display)\s+(run\S*|start\S*|conf\S*|current-configuration)"
                              r"(\s+(all|full|brief))?\s*$")

    def __init__(self, target: Dict[str, Any]):
        path = target.get("config_path")
        if not path or not Path(path).is_file():
            raise BackendError("No configuration file has been uploaded for this target")
        self.lines = Path(path).read_text(errors="replace").splitlines()

    def run(self, command: str, use_sudo: bool = False, rule_id: str = "") -> Dict[str, Any]:
        started = time.time()
        head, *filters = [part.strip() for part in command.strip().split("|")]
        if not self._SHOW_CONFIG.match(head):
            return _result("", 1, "This target is a saved configuration file, not a live device. Only "
                                  "'show running-config' with include/section/begin/exclude/count filters "
                                  "can be answered. Live state must be reviewed manually.", started)
        lines = list(self.lines)
        for item in filters:
            keyword, _, argument = item.partition(" ")
            keyword, argument = keyword.lower(), argument.strip()
            try:
                pattern = re.compile(argument, re.IGNORECASE) if argument else None
            except re.error:
                pattern = re.compile(re.escape(argument), re.IGNORECASE)
            if keyword in ("include", "inc", "i", "match", "grep", "find") and pattern:
                lines = [line for line in lines if pattern.search(line)]
            elif keyword in ("exclude", "exc", "except") and pattern:
                lines = [line for line in lines if not pattern.search(line)]
            elif keyword in ("begin", "beg") and pattern:
                start = next((i for i, line in enumerate(lines) if pattern.search(line)), len(lines))
                lines = lines[start:]
            elif keyword in ("section", "sec") and pattern:
                lines = self._sections(lines, pattern)
            elif keyword == "count":
                lines = [f"Number of lines which match regexp = {len(lines)}" if not pattern else
                         f"Number of lines which match regexp = {sum(1 for l in lines if pattern.search(l))}"]
            # display set / no-more / display inheritance: nothing to do for a saved file
        return _result("\n".join(lines), 0, None, started)

    @staticmethod
    def _sections(lines: List[str], pattern: "re.Pattern[str]") -> List[str]:
        """Each matching top-level line plus the indented lines under it (Cisco `| section`)."""
        out, keeping = [], False
        for line in lines:
            indented = line[:1] in (" ", "\t")
            if not indented:
                keeping = bool(pattern.search(line))
            elif not keeping and pattern.search(line):
                out.append(line)
                continue
            if keeping:
                out.append(line)
        return out

    def close(self) -> None:
        pass


BACKENDS = {"ssh": SSHBackend, "local": LocalBackend, "winrm": WinRMBackend, "config": ConfigBackend}


def build_backend(target: Dict[str, Any]):
    kind = target.get("backend")
    if kind not in BACKENDS:
        raise BackendError(f"Unknown connection type: {kind!r}")
    return BACKENDS[kind](target)
