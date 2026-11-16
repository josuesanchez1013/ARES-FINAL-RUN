"""
Run imported SCAP content with OpenSCAP and keep the results.

A scan evaluates one imported SCAP benchmark (STIG library entry of kind
"scap") against one target:

    this machine       oscap xccdf eval ...
    SSH target         oscap-ssh user@host port xccdf eval ...   (key-based sign-in;
                       OpenSCAP must also be installed on the target)

Results are kept under data/scap_scans/<scan id>/ as the raw XCCDF results
and as a CKL, which can be downloaded or used as a scan file in a run.
OpenSCAP itself is not bundled: install the `openscap-scanner` package
(and `openscap-utils` for oscap-ssh) on the ARES host.
"""

import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from stig_library.convert import ConvertError, xccdf_results_to_ckl

from . import config, stigs, targets

_ID = re.compile(r"[0-9]{8}-[0-9]{6}-[a-f0-9]{6}")
_PROFILE = re.compile(r"[A-Za-z0-9_.:-]{1,200}")
LOCAL = "local"
SCAN_TIMEOUT = 3600


def _fail(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


class ScanBody(BaseModel):
    entry_id: str
    target: str = LOCAL
    profile: str = ""


def tools() -> Dict[str, Optional[str]]:
    return {"oscap": shutil.which("oscap"), "oscap_ssh": shutil.which("oscap-ssh")}


def _folder(scan_id: str) -> Path:
    return config.scap_dir() / scan_id


def _read(scan_id: str) -> Optional[Dict[str, Any]]:
    if not _ID.fullmatch(scan_id or ""):
        return None
    try:
        return json.loads((_folder(scan_id) / "scan.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write(meta: Dict[str, Any]) -> None:
    folder = _folder(meta["id"])
    folder.mkdir(parents=True, exist_ok=True)
    tmp = folder / "scan.tmp"
    tmp.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    for attempt in range(20):
        try:
            tmp.replace(folder / "scan.json")
            return
        except PermissionError:
            # Windows refuses to replace a file another thread is reading; try again shortly
            if attempt == 19:
                raise
            time.sleep(0.05)


def list_scans() -> List[Dict[str, Any]]:
    root = config.scap_dir()
    if not root.is_dir():
        return []
    found = [m for m in (_read(p.name) for p in root.iterdir()) if m]
    for meta in found:   # a scan left "running" by a restart
        if meta["status"] == "running" and meta["id"] not in _running:
            meta.update(status="failed", error="The service restarted while this scan was running.")
            _write(meta)
    return sorted(found, key=lambda m: m["started_at"], reverse=True)


_running: Dict[str, threading.Thread] = {}


def build_command(datastream: Path, results: Path, profile: str, target: Optional[Dict[str, Any]]) -> List[str]:
    """The exact argv; no shell is involved."""
    evaluate = ["xccdf", "eval"]
    if profile:
        evaluate += ["--profile", profile]
    evaluate += ["--results", str(results), str(datastream)]
    if target is None:
        return ["oscap"] + evaluate
    user_host = f"{target['user']}@{target['host']}" if target.get("user") else target["host"]
    command = ["oscap-ssh"]
    if target.get("use_sudo"):
        command.append("--sudo")
    return command + [user_host, str(int(target.get("port") or 22))] + evaluate


def _execute(meta: Dict[str, Any], command: List[str], env: Dict[str, str]) -> None:
    folder = _folder(meta["id"])
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=SCAN_TIMEOUT,
                              stdin=subprocess.DEVNULL, env=env, cwd=str(folder))
        (folder / "oscap.log").write_text((done.stdout or "") + "\n" + (done.stderr or ""),
                                          encoding="utf-8", errors="replace")
        results = folder / "results.xml"
        # oscap exit codes: 0 all rules passed, 2 at least one rule failed, 1 error
        if done.returncode not in (0, 2) or not results.is_file():
            tail = (done.stderr or done.stdout or "").strip().splitlines()[-3:]
            raise RuntimeError("OpenSCAP did not produce results: " + " ".join(tail)[:600])
        ckl = xccdf_results_to_ckl(results.read_bytes(), stigs.get_library(), tool="OpenSCAP")
        (folder / "results.ckl").write_bytes(ckl)
        counts = {status: ckl.count(f"<STATUS>{status}</STATUS>".encode())
                  for status in ("Open", "NotAFinding", "Not_Applicable", "Not_Reviewed")}
        meta.update(status="completed", counts=counts)
    except subprocess.TimeoutExpired:
        meta.update(status="failed", error=f"OpenSCAP did not finish within {SCAN_TIMEOUT // 60} minutes.")
    except (RuntimeError, ConvertError, OSError) as exc:
        meta.update(status="failed", error=str(exc))
    finally:
        meta["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _write(meta)
        _running.pop(meta["id"], None)


def start_scan(body: ScanBody) -> Dict[str, Any]:
    library = stigs.get_library()
    entry = library.summary(body.entry_id)
    if entry is None or entry["kind"] != "scap":
        raise _fail(422, "not_scap", "Choose an imported SCAP benchmark.")
    datastream = library.datastream_path(body.entry_id)
    if not datastream.is_file():
        raise _fail(422, "no_datastream", "The SCAP data stream for this benchmark was not kept. "
                                          "Import the SCAP benchmark zip again.")
    if body.profile and not _PROFILE.fullmatch(body.profile):
        raise _fail(422, "profile", "That profile id is not valid.")
    if body.profile and body.profile not in [p["id"] for p in entry.get("profiles") or []]:
        raise _fail(422, "profile", "That profile is not in this benchmark.")

    have = tools()
    env = dict(os.environ)
    if body.target == LOCAL:
        target, where = None, "This machine"
        if not have["oscap"]:
            raise _fail(503, "oscap_missing", "OpenSCAP is not installed on the ARES host. Install the "
                                              "openscap-scanner package, then try again.")
    else:
        target = targets.get(body.target)
        if target is None:
            raise _fail(422, "target_not_found", "The chosen target no longer exists.")
        if target["backend"] != "ssh" or target["shell"] != "posix":
            raise _fail(422, "target_backend", "OpenSCAP scans run on this machine or on a Linux/UNIX target "
                                               "reached over SSH. For Windows, run SCC and upload its results.")
        if not target.get("key_path"):
            raise _fail(422, "target_key", "OpenSCAP over SSH needs key-based sign-in. Set an SSH key file "
                                           "on the target.")
        if not have["oscap_ssh"]:
            raise _fail(503, "oscap_missing", "oscap-ssh is not installed on the ARES host. Install the "
                                              "openscap-utils package, then try again.")
        where = target["name"]
        env["SSH_ADDITIONAL_OPTIONS"] = (f"-i {Path(target['key_path']).expanduser()} "
                                         "-o BatchMode=yes -o StrictHostKeyChecking=yes")

    scan_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    folder = _folder(scan_id)
    folder.mkdir(parents=True)
    meta = {"id": scan_id, "entry_id": body.entry_id, "stig_title": entry["title"],
            "stig_version": entry["version_label"], "profile": body.profile,
            "target": body.target, "target_name": where, "status": "running", "error": None,
            "counts": None, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "finished_at": None}
    _write(meta)
    command = build_command(datastream, folder / "results.xml", body.profile, target)
    thread = threading.Thread(target=_execute, args=(meta, command, env), name=f"ares-scap-{scan_id}",
                              daemon=True)
    _running[scan_id] = thread
    thread.start()
    return meta


def result_ckl(scan_id: str) -> bytes:
    """The CKL of a finished scan, for use as a scan file in a run."""
    meta = _read(scan_id)
    path = _folder(scan_id) / "results.ckl" if meta else None
    if meta is None or meta["status"] != "completed" or not path.is_file():
        raise _fail(422, "scan_not_ready", "That OpenSCAP scan has no results to use.")
    return path.read_bytes()


def register(app: FastAPI) -> None:
    @app.get("/api/scap")
    def scap_status() -> Dict[str, Any]:
        have = tools()
        benchmarks = [
            {k: e.get(k) for k in ("id", "title", "version_label", "automated_count", "profiles", "latest")}
            for e in stigs.get_library().list() if e["kind"] == "scap" and e.get("datastream")]
        return {"oscap": bool(have["oscap"]), "oscap_ssh": bool(have["oscap_ssh"]),
                "benchmarks": benchmarks, "scans": list_scans()}

    @app.post("/api/scap/scans", status_code=201)
    def create_scan(body: ScanBody) -> Dict[str, Any]:
        return start_scan(body)

    @app.get("/api/scap/scans/{scan_id}")
    def scan_detail(scan_id: str) -> Dict[str, Any]:
        meta = _read(scan_id)
        if meta is None:
            raise _fail(404, "scan_not_found", "That scan does not exist.")
        return meta

    @app.get("/api/scap/scans/{scan_id}/{kind}")
    def scan_file(scan_id: str, kind: str) -> Response:
        meta = _read(scan_id)
        names = {"ckl": ("results.ckl", "application/xml"), "xccdf": ("results.xml", "application/xml"),
                 "log": ("oscap.log", "text/plain")}
        if meta is None or kind not in names:
            raise _fail(404, "scan_not_found", "That scan file does not exist.")
        path = _folder(scan_id) / names[kind][0]
        if not path.is_file():
            raise _fail(404, "scan_not_found", "That scan has no such file yet.")
        suffix = "ckl" if kind == "ckl" else "xml" if kind == "xccdf" else "log"
        return Response(content=path.read_bytes(), media_type=names[kind][1], headers={
            "Content-Disposition": f'attachment; filename="openscap_{scan_id}.{suffix}"'})

    @app.delete("/api/scap/scans/{scan_id}", status_code=204)
    def delete_scan(scan_id: str) -> None:
        meta = _read(scan_id)
        if meta is None:
            raise _fail(404, "scan_not_found", "That scan does not exist.")
        if scan_id in _running:
            raise _fail(409, "scan_running", "This scan is still running.")
        shutil.rmtree(_folder(scan_id), ignore_errors=True)
