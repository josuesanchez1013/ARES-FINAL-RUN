"""
Run store: one shared, refresh-proof run state for every browser tab.

Each run lives in its own folder under the data directory:

    <run_id>/run.json        metadata, step states, decisions
    <run_id>/events.jsonl    append-only event history (replayed to late joiners)
    <run_id>/outputs/*.json  one file per completed pipeline step
    <run_id>/uploads/*       masked copies of the uploaded scan files

Only one run may be active at a time (the run lock). Runs that were active when
the service stopped are reloaded as "interrupted" and can be resumed.
"""

import json
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ACTIVE = {"checking", "running", "paused"}
RESUMABLE = {"interrupted", "ended", "failed"}


class RunEnded(BaseException):
    """Raised inside the worker when the user ends a run.

    Derives from BaseException so the pipeline's own `except Exception`
    handlers (which turn agent errors into review items) do not swallow it.
    """


class RunLocked(Exception):
    def __init__(self, active_id: str):
        super().__init__(f"Run {active_id} is active. Only one run can be active at a time.")
        self.active_id = active_id


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Run:
    def __init__(self, folder: Path, meta: Dict[str, Any]):
        self.folder = folder
        self.meta = meta
        self.outputs: Dict[str, Any] = {}
        self.events: List[Dict[str, Any]] = []
        self.lock = threading.RLock()
        self._resume = threading.Event()
        self._resume.set()
        self._end = False
        self.thread: Optional[threading.Thread] = None

    # -- identity ------------------------------------------------------------
    @property
    def id(self) -> str:
        return self.meta["id"]

    @property
    def status(self) -> str:
        return self.meta["status"]

    @property
    def active(self) -> bool:
        return self.status in ACTIVE

    # -- persistence ---------------------------------------------------------
    def save(self) -> None:
        with self.lock:
            tmp = self.folder / "run.json.tmp"
            tmp.write_text(json.dumps(self.meta, indent=2))
            tmp.replace(self.folder / "run.json")

    def save_output(self, key: str, data: Any) -> None:
        self.outputs[key] = data
        out = self.folder / "outputs"
        out.mkdir(exist_ok=True)
        (out / f"{key}.json").write_text(json.dumps(data, default=str))

    @classmethod
    def load(cls, folder: Path) -> "Run":
        run = cls(folder, json.loads((folder / "run.json").read_text()))
        events = folder / "events.jsonl"
        if events.exists():
            for line in events.read_text().splitlines():
                if line.strip():
                    run.events.append(json.loads(line))
        for path in (folder / "outputs").glob("*.json"):
            run.outputs[path.stem] = json.loads(path.read_text())
        return run

    # -- events --------------------------------------------------------------
    def emit(self, kind: str, **payload: Any) -> Dict[str, Any]:
        with self.lock:
            event = {"seq": len(self.events), "ts": now_iso(), "type": kind, **payload}
            self.events.append(event)
            with open(self.folder / "events.jsonl", "a") as handle:
                handle.write(json.dumps(event, default=str) + "\n")
            return event

    def set_status(self, status: str, **extra: Any) -> None:
        with self.lock:
            self.meta["status"] = status
            self.meta.update(extra)
            if status in ("completed", "failed", "ended"):
                self.meta["finished_at"] = now_iso()
            self.save()
            self.emit("status", status=status, error=self.meta.get("error"))

    def set_step(self, index: int, state: str, duration: Optional[float] = None) -> None:
        with self.lock:
            step = self.meta["steps"][index]
            step["state"] = state
            if duration is not None:
                step["duration"] = round(duration, 2)
            self.save()
            self.emit("step", index=index, key=step["key"], state=state,
                      duration=step.get("duration"))

    def log(self, step_key: str, level: str, message: str) -> None:
        self.emit("log", step=step_key, level=level, message=str(message))

    # -- control -------------------------------------------------------------
    def checkpoint(self) -> None:
        """Called by the worker between rules and steps. Blocks while paused."""
        if self._end:
            raise RunEnded()
        if not self._resume.is_set():
            self._resume.wait()
            if self._end:
                raise RunEnded()

    def pause(self) -> None:
        with self.lock:
            if self.status in ("running", "checking"):
                self._resume.clear()
                self.set_status("paused")

    def unpause(self) -> None:
        with self.lock:
            if self.status == "paused":
                self.set_status("running")
                self._resume.set()

    def end(self) -> None:
        with self.lock:
            if not self.active:
                return
            self._end = True
            self._resume.set()
            worker_alive = self.thread is not None and self.thread.is_alive()
        if not worker_alive:
            self.set_status("ended")

    def reset_control(self) -> None:
        self._end = False
        self._resume.set()

    # -- views ---------------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        with self.lock:
            meta = dict(self.meta)
        started = meta.get("started_at")
        finished = meta.get("finished_at")
        meta["duration"] = sum(s.get("duration") or 0 for s in meta["steps"])
        meta["resumable"] = meta["status"] in RESUMABLE and bool(started)
        meta["has_results"] = "final_report" in self.outputs
        meta["event_count"] = len(self.events)
        meta["finished_at"] = finished
        return meta


class RunStore:
    def __init__(self, root: Path, retention: int = 50):
        self.root = root
        self.retention = retention
        self.root.mkdir(parents=True, exist_ok=True)
        self.runs: Dict[str, Run] = {}
        self.lock = threading.RLock()
        for folder in sorted(self.root.iterdir()):
            if (folder / "run.json").exists():
                try:
                    run = Run.load(folder)
                except (ValueError, OSError):
                    continue
                if run.active:
                    # The service stopped mid-run; nothing is executing any more.
                    run.meta["status"] = "interrupted"
                    run.save()
                    run.emit("status", status="interrupted", error=None)
                self.runs[run.id] = run

    def active(self) -> Optional[Run]:
        with self.lock:
            return next((r for r in self.runs.values() if r.active), None)

    def latest(self) -> Optional[Run]:
        with self.lock:
            ordered = sorted(self.runs.values(), key=lambda r: r.meta.get("created_ts", 0))
            return ordered[-1] if ordered else None

    def get(self, run_id: str) -> Optional[Run]:
        return self.runs.get(run_id)

    def list(self) -> List[Run]:
        with self.lock:
            return sorted(self.runs.values(), key=lambda r: r.meta.get("created_ts", 0), reverse=True)

    def create(self, steps: List[Dict], files: List[Dict], declaration: Dict,
               models: Dict, mock: bool) -> Run:
        """Create a run and take the run lock. Raises RunLocked if one is active."""
        with self.lock:
            current = self.active()
            if current:
                raise RunLocked(current.id)
            run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
            folder = self.root / run_id
            (folder / "uploads").mkdir(parents=True)
            (folder / "outputs").mkdir()
            meta = {
                "id": run_id,
                "created_at": now_iso(),
                "created_ts": time.time(),
                "started_at": now_iso(),
                "finished_at": None,
                "status": "checking",
                "error": None,
                "mock": mock,
                "keep": False,
                "step_index": 0,
                "steps": [dict(s, state="pending", duration=None) for s in steps],
                "files": files,
                "declaration": declaration,
                "models": models,
                "model_check": [],
                "decisions": {},
            }
            run = Run(folder, meta)
            run.save()
            self.runs[run_id] = run
            self._prune()
            return run

    def take_lock_for(self, run: Run) -> None:
        """Re-activate an unfinished run. Raises RunLocked if another is active."""
        with self.lock:
            current = self.active()
            if current and current.id != run.id:
                raise RunLocked(current.id)
            run.reset_control()
            run.meta["error"] = None
            run.meta["finished_at"] = None
            run.set_status("running")

    def delete(self, run: Run) -> None:
        with self.lock:
            self.runs.pop(run.id, None)
            shutil.rmtree(run.folder, ignore_errors=True)

    def _prune(self) -> None:
        finished = [r for r in self.list() if not r.active and not r.meta.get("keep")]
        for run in finished[self.retention:]:
            self.delete(run)
