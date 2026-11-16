"""
Targets: the systems ARES can run read-only checks on, of any platform.

A target records how to reach one system (connection type, host, account)
and what it is (platform family). Passwords are never stored: a target holds
only the NAME of an environment variable that carries the password, or the
path of an SSH key. Targets live in data/targets/targets.json (git-ignored).

The "default" target is the one configured in the environment (ARES_SSH_*),
exactly as before this feature; runs that use it are unchanged.
"""

import json
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from cli_executor.target_context import run_on_target
from stig_library import platforms

from . import config, stigs

DEFAULT = "default"
MAX_CONFIG_BYTES = 20 * 1024 * 1024
_ID = re.compile(r"[a-f0-9]{12}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_lock = threading.RLock()


def _fail(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


class TargetBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    family: str
    backend: str
    host: str = ""
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    user: str = ""
    key_path: str = ""
    password_env: str = ""
    use_sudo: bool = False
    winrm_https: bool = True
    winrm_transport: str = "ntlm"
    ca_bundle: str = ""
    timeout: int = Field(default=30, ge=5, le=600)
    notes: str = Field(default="", max_length=500)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

def _root() -> Path:
    return config.targets_dir()


def _load() -> Dict[str, Dict[str, Any]]:
    try:
        return json.loads((_root() / "targets.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(data: Dict[str, Dict[str, Any]]) -> None:
    _root().mkdir(parents=True, exist_ok=True)
    tmp = _root() / "targets.tmp"
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(_root() / "targets.json")


def _config_path(target_id: str) -> Path:
    return _root() / "configs" / f"{target_id}.cfg"


def describe(target: Dict[str, Any]) -> Dict[str, Any]:
    """A stored target plus what the pipeline derives from it."""
    prof = platforms.profile(target["family"])
    out = dict(target, shell=prof["shell"], platform_label=prof["label"], style=prof["style"])
    path = _config_path(target["id"])
    out["has_config"] = path.is_file()
    out["config_path"] = str(path) if path.is_file() else ""
    if target["backend"] != "ssh" and target["backend"] != "local":
        out["use_sudo"] = False
    return out


def get(target_id: str) -> Optional[Dict[str, Any]]:
    if not _ID.fullmatch(target_id or ""):
        return None
    target = _load().get(target_id)
    return describe(target) if target else None


def all_targets() -> List[Dict[str, Any]]:
    return sorted((describe(t) for t in _load().values()), key=lambda t: t["name"].lower())


def default_target() -> Dict[str, Any]:
    target = config.target()
    return {"id": DEFAULT, "name": f"{target['host_name']} (service configuration)",
            "family": "linux", "platform_label": "Linux", "backend": "ssh", "shell": "posix",
            "host": target["host_ip"], "builtin": True}


def _validate(body: TargetBody) -> Dict[str, Any]:
    prof = platforms.profile(body.family)
    if body.family not in platforms.PROFILES or not prof["backends"]:
        raise _fail(422, "family", "Choose a platform ARES can connect to.")
    if body.backend not in prof["backends"]:
        raise _fail(422, "backend", f"{prof['label']} targets connect by: {', '.join(prof['backends'])}.")
    if body.backend in ("ssh", "winrm") and not body.host.strip():
        raise _fail(422, "host", "Enter the host name or IP address.")
    if body.host and not re.fullmatch(r"[A-Za-z0-9._:\-\[\]]{1,255}", body.host.strip()):
        raise _fail(422, "host", "The host may contain letters, digits, dots, dashes and colons only.")
    if body.password_env and not _ENV_NAME.fullmatch(body.password_env):
        raise _fail(422, "password_env", "Enter the NAME of an environment variable (for example "
                                         "ARES_PW_WEB01), not the password itself.")
    if body.backend == "ssh" and not (body.key_path or body.password_env):
        raise _fail(422, "credentials", "SSH needs a key file path or a password environment variable.")
    if body.backend == "winrm":
        if body.winrm_transport not in ("ntlm", "kerberos", "credssp", "basic"):
            raise _fail(422, "transport", "WinRM sign-in must be ntlm, kerberos, credssp or basic.")
        if body.winrm_transport == "basic" and not body.winrm_https:
            raise _fail(422, "transport", "Basic sign-in over plain HTTP would send the password in clear text.")
        if body.winrm_transport != "kerberos" and not (body.user and body.password_env):
            raise _fail(422, "credentials", "WinRM needs a user and a password environment variable.")
    data = body.model_dump()
    data.update(name=body.name.strip(), host=body.host.strip(), user=body.user.strip())
    return data


# ---------------------------------------------------------------------------
# Discovery: what is this system, and which imported STIGs apply to it?
# ---------------------------------------------------------------------------

PROBES = {
    "posix": [
        ("os", "cat /etc/os-release 2>/dev/null; uname -sr; oslevel 2>/dev/null; sw_vers 2>/dev/null"),
        ("software", "for c in httpd apache2 nginx postgres psql mysqld mariadbd mongod java docker podman "
                     "kubelet named sshd firefox google-chrome tomcat catalina.sh; do command -v $c 2>/dev/null; done"),
    ],
    "powershell": [
        ("os", "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | Format-List"),
        ("software", "Get-Service -Name W3SVC, MSSQLSERVER, NTDS, DNS, WinDefend -ErrorAction SilentlyContinue "
                     "| Select-Object Name, Status | Format-Table -HideTableHeaders"),
    ],
    "network": [("os", "show version")],
}

# (regex on probe output, keywords that must all appear in a STIG's title or id)
SIGNATURES = [
    (r'(?ims)^ID="?rhel"?.*?^VERSION_ID="?(\d+)', ["red hat enterprise linux {0}"]),
    (r'(?ims)^VERSION_ID="?(\d+).*?^ID="?rhel"?', ["red hat enterprise linux {0}"]),
    (r'(?ims)^ID="?ol"?.*?^VERSION_ID="?(\d+)', ["oracle linux {0}"]),
    (r'(?ims)^ID="?ubuntu"?.*?^VERSION_ID="?(\d+\.\d+)', ["ubuntu {0}"]),
    (r'(?ims)^VERSION_ID="?(\d+\.\d+).*?^ID="?ubuntu"?', ["ubuntu {0}"]),
    (r'(?ims)^ID="?sles"?.*?^VERSION_ID="?(\d+)', ["suse linux enterprise server {0}"]),
    (r'(?ims)^VERSION_ID="?(\d+).*?^ID="?sles"?', ["suse linux enterprise server {0}"]),
    (r"(?m)^SunOS 5\.(\d+)", ["solaris {0}"]),
    (r"(?m)^AIX\b[\s\S]*?^(\d)\d00-", ["aix {0}"]),
    (r"(?m)^AIX\b", ["aix"]),
    (r"(?m)^ProductVersion:\s*(\d+)", ["macos {0}"]),
    (r"(?i)Windows Server (\d{4})", ["windows server {0}"]),
    (r"(?i)Windows (1[01])\b", ["windows {0}"]),
    (r"(?i)IOS[- ]XE", ["cisco ios xe"]),
    (r"(?i)NX-OS", ["cisco nx-os"]),
    (r"(?i)Adaptive Security Appliance", ["cisco asa"]),
    (r"(?i)Cisco IOS Software(?!.*IOS[- ]XE)", ["cisco ios "]),
    (r"(?i)JUNOS", ["juniper"]),
    (r"(?m)/(httpd|apache2)$", ["apache server 2.4"]),
    (r"(?m)/(postgres|psql)$", ["postgresql"]),
    (r"(?m)/(mysqld)$", ["mysql"]),
    (r"(?m)/(mariadbd)$", ["mariadb"]),
    (r"(?m)/(mongod)$", ["mongodb"]),
    (r"(?m)/(docker)$", ["docker"]),
    (r"(?m)/(kubelet)$", ["kubernetes"]),
    (r"(?m)/(named)$", ["bind"]),
    (r"(?m)/(tomcat|catalina\.sh)$", ["tomcat"]),
    (r"(?m)/(firefox)$", ["firefox"]),
    (r"(?m)/(google-chrome)$", ["chrome"]),
    (r"(?im)^\s*W3SVC\b", ["iis"]),
    (r"(?im)^\s*MSSQLSERVER\b", ["sql server"]),
    (r"(?im)^\s*NTDS\b", ["active directory"]),
    (r"(?im)^\s*DNS\b", ["windows", "dns"]),
    (r"(?im)^\s*WinDefend\b", ["defender antivirus"]),
]


def suggest(output: str, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Imported STIG releases (latest manual ones) that fit what the probes printed."""
    wanted: List[List[str]] = []
    for pattern, keywords in SIGNATURES:
        match = re.search(pattern, output)
        if match:
            filled = [k.format(*match.groups()) for k in keywords]
            if filled not in wanted:
                wanted.append(filled)
    found: List[Dict[str, Any]] = []
    for entry in entries:
        if entry["kind"] != "manual" or not entry.get("latest"):
            continue
        text = f" {entry['title']} {entry['key']} ".lower().replace("_", " ").replace("-", " ")
        for keywords in wanted:
            if all(re.search(rf"(?<![\w.]){re.escape(k.replace('-', ' ').strip())}(?![\w.])", text)
                   for k in keywords):
                if entry["id"] not in [f["id"] for f in found]:
                    found.append({k: entry[k] for k in ("id", "title", "version_label", "platform_label")})
    return found


def discover(target: Dict[str, Any]) -> Dict[str, Any]:
    probes = PROBES.get(target["shell"], [])
    outputs, errors = [], []
    for label, command in probes:
        result = run_on_target(target, command, rule_id=f"DISCOVERY:{label}", max_retries=1)
        if result["exit_code"] == -1 or result["exit_code"] == -2:
            errors.append(result.get("error") or "no response")
            if result["exit_code"] == -1:
                break
        outputs.append(result.get("output", ""))
    combined = "\n".join(outputs)
    suggestions = suggest(combined, stigs.get_library().list()) if combined.strip() else []
    return {"reachable": bool(combined.strip()), "output": combined[:4000], "errors": errors,
            "suggestions": suggestions,
            "library_empty": not stigs.get_library().list()}


def test_connection(target: Dict[str, Any]) -> Dict[str, Any]:
    command = {"posix": "uname -a", "powershell": "hostname", "network": "show version"}.get(target["shell"])
    if not command:
        return {"ok": False, "detail": "This platform has no command access."}
    started = time.time()
    result = run_on_target(target, command, rule_id="CONNECTION_TEST", max_retries=1)
    ok = result["exit_code"] == 0
    detail = (result.get("output") or "").strip().splitlines()[0][:200] if ok else \
        (result.get("error") or f"exit code {result['exit_code']}")[:400]
    return {"ok": ok, "detail": detail, "seconds": round(time.time() - started, 1)}


# ---------------------------------------------------------------------------
# Per-run choice
# ---------------------------------------------------------------------------

def resolve_choice(choice: str) -> Dict[str, Any]:
    """What a run records about its target. Raises HTTPException if it is gone."""
    choice = (choice or DEFAULT).strip()
    if choice == DEFAULT:
        return {"id": DEFAULT, "name": default_target()["name"], "family": "linux",
                "platform_label": "Linux", "backend": "ssh"}
    target = get(choice)
    if target is None:
        raise _fail(422, "target_not_found", "The chosen target no longer exists. Refresh and choose again.")
    if target["backend"] == "config" and not target["has_config"]:
        raise _fail(422, "target_no_config", f"Upload a configuration file for {target['name']} first.")
    return {k: target[k] for k in ("id", "name", "family", "platform_label", "backend", "host")}


def mismatch_note(target_choice: Dict[str, Any], stig_choice: Dict[str, Any]) -> str:
    """Warn when the STIG is for a different kind of system than the target."""
    if target_choice.get("id") == DEFAULT or not stig_choice.get("entry_ids"):
        return ""
    library = stigs.get_library()
    shell = platforms.profile(target_choice["family"])["shell"]
    for ident in stig_choice["entry_ids"]:
        entry = library.summary(ident)
        if not entry:
            continue
        family = platforms.classify(entry["key"], entry["title"])
        if family != "other" and platforms.profile(family)["shell"] != shell:
            return (f"{entry['title']} is a {platforms.profile(family)['label']} STIG, but the target "
                    f"{target_choice['name']} is {target_choice['platform_label']}. Checks on the target "
                    "may not apply.")
    return ""


def active_for(choice: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The live target for a run step; None means the original SSH path."""
    if not choice or choice.get("id") in (None, DEFAULT):
        return None
    target = get(choice["id"])
    if target is None:
        raise RuntimeError(f"The target used by this run ({choice.get('name')}) was deleted.")
    return target


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def register(app: FastAPI) -> None:
    def need(target_id: str) -> Dict[str, Any]:
        target = get(target_id)
        if target is None:
            raise _fail(404, "target_not_found", "That target does not exist.")
        return target

    def public(target: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in target.items() if k not in ("style", "config_path")}

    @app.get("/api/targets")
    def list_targets() -> Dict[str, Any]:
        return {"default": default_target(), "targets": [public(t) for t in all_targets()],
                "platforms": [p for p in platforms.families() if p["backends"]]}

    @app.post("/api/targets", status_code=201)
    def create_target(body: TargetBody) -> Dict[str, Any]:
        data = _validate(body)
        with _lock:
            stored = _load()
            data["id"] = uuid.uuid4().hex[:12]
            data["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            stored[data["id"]] = data
            _save(stored)
        return public(describe(data))

    @app.put("/api/targets/{target_id}")
    def update_target(target_id: str, body: TargetBody) -> Dict[str, Any]:
        need(target_id)
        data = _validate(body)
        with _lock:
            stored = _load()
            data.update(id=target_id, created_at=stored[target_id].get("created_at"))
            stored[target_id] = data
            _save(stored)
        return public(describe(data))

    @app.delete("/api/targets/{target_id}", status_code=204)
    def delete_target(target_id: str) -> None:
        need(target_id)
        with _lock:
            stored = _load()
            stored.pop(target_id, None)
            _save(stored)
            _config_path(target_id).unlink(missing_ok=True)

    @app.post("/api/targets/{target_id}/config")
    async def upload_config(target_id: str, file: UploadFile = File(...)) -> Dict[str, Any]:
        target = need(target_id)
        if target["backend"] != "config":
            raise _fail(422, "backend", "Only targets of type 'saved configuration' take a configuration file.")
        data = await file.read()
        if not data.strip():
            raise _fail(422, "file_empty", "The configuration file is empty.")
        if len(data) > MAX_CONFIG_BYTES:
            raise _fail(422, "file_too_large", "The configuration file is larger than 20 MB.")
        if b"\x00" in data[:4096]:
            raise _fail(422, "file_type", "Upload the configuration as plain text.")
        path = _config_path(target_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return public(need(target_id))

    @app.post("/api/targets/{target_id}/test")
    def test_target(target_id: str) -> Dict[str, Any]:
        return test_connection(need(target_id))

    @app.post("/api/targets/{target_id}/discover")
    def discover_target(target_id: str) -> Dict[str, Any]:
        return discover(need(target_id))
