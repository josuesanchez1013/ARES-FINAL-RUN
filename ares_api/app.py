"""
ARES API application.

Start with:  uvicorn ares_api.main:app --host 0.0.0.0 --port 8080
The built React app (frontend/dist) is served from the same port.
"""

import asyncio
import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from stig_library.convert import ConvertError, to_ckl

from . import __version__, config, exports, scap, stigs, targets
from . import findings as fx
from .pipeline import get_pipeline, mask_upload, run_worker
from .runs import Run, RunLocked, RunStore, now_iso

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
OVERRIDE_STATUSES = ["Open", "NotAFinding", "Not_Applicable"]


class DecisionBody(BaseModel):
    action: str
    status: Optional[str] = None


class KeepBody(BaseModel):
    keep: bool


def _fail(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def create_app(data_dir: Optional[Path] = None) -> FastAPI:
    app = FastAPI(title="ARES API", version=__version__, docs_url="/api/docs",
                  openapi_url="/api/openapi.json", redoc_url=None)
    store = RunStore(Path(data_dir) if data_dir else config.data_dir(), config.retention())
    app.state.store = store

    # -- helpers -------------------------------------------------------------
    def get_run(run_id: str) -> Run:
        run = store.get(run_id)
        if run is None:
            raise _fail(404, "run_not_found", f"Run {run_id} does not exist.")
        return run

    def results(run: Run) -> List[Dict]:
        if "final_report" not in run.outputs:
            raise _fail(409, "results_not_ready",
                        "Results are available when the run has finished.")
        return fx.build_findings(run.outputs)

    def start_worker(run: Run) -> None:
        run.thread = threading.Thread(target=run_worker, args=(run, get_pipeline(), store),
                                      name=f"ares-run-{run.id}", daemon=True)
        run.thread.start()

    def last_model_check() -> List[Dict]:
        latest = store.latest()
        return latest.meta.get("model_check", []) if latest else []

    @app.exception_handler(RunLocked)
    async def locked(_: Request, exc: RunLocked):
        return JSONResponse(status_code=409, content={"detail": {
            "code": "run_active", "message": str(exc), "run_id": exc.active_id}})

    # -- health and settings -------------------------------------------------
    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        pipeline = get_pipeline()
        problem = pipeline.available()
        active = store.active()
        return {"status": "ok", "version": __version__, "mode": pipeline.name,
                "pipeline_ready": problem is None, "pipeline_error": problem,
                "active_run": active.id if active else None,
                "model_check": last_model_check()}

    @app.get("/api/settings")
    def settings() -> Dict[str, Any]:
        pipeline = get_pipeline()
        return {
            "version": __version__, "mode": pipeline.name, "editable": False,
            "pipeline_error": pipeline.available(),
            "models": config.models(),
            "classifications": config.CLASSIFICATIONS,
            "refused_classifications": sorted(config.REFUSED_CLASSIFICATIONS),
            "sensitivity_categories": config.sensitivity_categories(),
            "sensitivity_none": config.SENSITIVITY_NONE,
            "target": config.target(), "stig": config.stig(),
            "stig_library": {"dir": str(config.stig_library_dir()),
                             "count": len(stigs.get_library().list())},
            "mcp_server_url": config.mcp_server_url(),
            "data_dir": str(store.root), "retention": store.retention,
            "model_check": last_model_check(),
            "review_thresholds": {"cat_i": fx.CAT_I_REVIEW_THRESHOLD,
                                  "default": fx.DEFAULT_REVIEW_THRESHOLD},
        }

    # -- run lifecycle -------------------------------------------------------
    @app.post("/api/runs", status_code=201)
    async def start_run(
        tool1: Optional[UploadFile] = File(None), tool2: Optional[UploadFile] = File(None),
        tool1_scan: str = Form(""), tool2_scan: str = Form(""),
        classification: str = Form(""), sensitivity: str = Form(""),
        primary_model: str = Form(""), secondary_model: str = Form(""),
        stig: str = Form(stigs.AUTO), target: str = Form(targets.DEFAULT),
    ) -> Dict[str, Any]:
        # Data-handling declaration first: a refused upload is never stored.
        if classification not in config.CLASSIFICATIONS:
            raise _fail(422, "classification_required", "Choose a classification for these files.")
        if classification in config.REFUSED_CLASSIFICATIONS:
            raise _fail(422, "classified_refused",
                        "ARES does not accept classified data. Nothing was uploaded or stored.")
        chosen = [s.strip() for s in sensitivity.split(",") if s.strip()]
        allowed = config.sensitivity_categories() + [config.SENSITIVITY_NONE]
        if not chosen or any(s not in allowed for s in chosen):
            raise _fail(422, "sensitivity_required",
                        "Choose the sensitivity categories that apply, or None.")
        if config.SENSITIVITY_NONE in chosen and len(chosen) > 1:
            raise _fail(422, "sensitivity_conflict",
                        "None cannot be combined with a sensitivity category.")
        if primary_model not in config.models():
            raise _fail(422, "model_not_listed",
                        "Choose a primary model from the configured list (ARES_LLM_MODELS).")
        if secondary_model and secondary_model not in config.models():
            raise _fail(422, "model_not_listed",
                        "The secondary model is not in the configured list (ARES_LLM_MODELS).")

        active = store.active()
        if active:
            raise RunLocked(active.id)
        pipeline = get_pipeline()
        problem = pipeline.available()
        if problem:
            raise _fail(503, "pipeline_unavailable", f"The pipeline cannot start: {problem}")

        files, payloads = [], []
        for role, upload, scan_id in (("tool1", tool1, tool1_scan), ("tool2", tool2, tool2_scan)):
            if scan_id:   # a finished OpenSCAP scan stands in for an uploaded file
                ckl = scap.result_ckl(scan_id)
                masked, fields = mask_upload(f"openscap_{scan_id}.ckl", ckl)
                files.append({"role": role, "name": f"openscap_{scan_id}.ckl", "size": len(ckl),
                              "stored_as": f"{role}.ckl", "masked_fields": fields,
                              "converted_from": None, "scap_scan": scan_id})
                payloads.append(masked)
                continue
            if upload is None:
                raise _fail(422, "file_required", f"Choose a scan file for {role.replace('tool', 'Tool ')}.")
            name = Path(upload.filename or role).name
            suffix = Path(name).suffix.lower()
            if suffix not in (".ckl", ".csv", ".cklb", ".xml"):
                raise _fail(422, "file_type", f"{name}: upload a .ckl, .cklb or .csv checklist, or an "
                                              "SCC / OpenSCAP XCCDF results .xml file.")
            data = await upload.read()
            if not data:
                raise _fail(422, "file_empty", f"{name} is empty.")
            if len(data) > MAX_UPLOAD_BYTES:
                raise _fail(422, "file_too_large", f"{name} is larger than 50 MB.")
            original = name
            try:   # CKLB and XCCDF results are converted to CKL, which the pipeline reads
                converted = to_ckl(name, data, stigs.get_library())
            except ConvertError as exc:
                raise _fail(422, "file_unreadable", f"{name}: {exc}.")
            if converted is not None:
                data, suffix, name = converted, ".ckl", f"{Path(name).stem}.ckl"
            masked, fields = mask_upload(name, data)
            files.append({"role": role, "name": name, "size": len(data),
                          "stored_as": f"{role}{suffix}", "masked_fields": fields,
                          "converted_from": original if original != name else None})
            payloads.append(masked)
        target_choice = targets.resolve_choice(target)
        stig_choice = stigs.resolve_choice(
            stig, [{"name": f["name"], "data": p} for f, p in zip(files, payloads)])

        run = store.create(
            steps=pipeline.steps, files=files,
            declaration={"classification": classification, "sensitivity": chosen},
            models={"primary": primary_model, "secondary": secondary_model},
            mock=pipeline.name == "mock",
        )
        run.meta["stig"] = stig_choice
        run.meta["target"] = dict(target_choice,
                                  note=targets.mismatch_note(target_choice, stig_choice))
        run.save()
        for item, payload in zip(files, payloads):
            (run.folder / "uploads" / item["stored_as"]).write_bytes(payload)
        run.emit("status", status="checking", error=None)
        start_worker(run)
        return run.summary()

    @app.get("/api/runs")
    def list_runs() -> Dict[str, Any]:
        rows = []
        for run in store.list():
            summary = run.summary()
            counts = None
            if summary["has_results"]:
                found = fx.build_findings(run.outputs)
                review = fx.build_review(found, run.outputs, run.meta["decisions"])
                total = fx.build_summary(found, review, run.meta["decisions"])
                counts = {"total": total["total"], "open": total["by_status"]["Open"],
                          "review_pending": total["review_pending"]}
            summary["counts"] = counts
            rows.append(summary)
        return {"runs": rows}

    @app.get("/api/runs/current")
    def current_run() -> Dict[str, Any]:
        run = store.active() or store.latest()
        return {"run": run.summary() if run else None}

    @app.get("/api/runs/{run_id}")
    def run_detail(run_id: str) -> Dict[str, Any]:
        return get_run(run_id).summary()

    @app.post("/api/runs/{run_id}/pause")
    def pause_run(run_id: str) -> Dict[str, Any]:
        run = get_run(run_id)
        if run.status not in ("running", "checking"):
            raise _fail(409, "not_running", "Only a running run can be paused.")
        run.pause()
        return run.summary()

    @app.post("/api/runs/{run_id}/resume")
    def resume_run(run_id: str) -> Dict[str, Any]:
        run = get_run(run_id)
        if run.status == "paused":
            run.unpause()
        elif run.summary()["resumable"]:
            store.take_lock_for(run)
            start_worker(run)
        else:
            raise _fail(409, "not_resumable", "This run cannot be resumed.")
        return run.summary()

    @app.post("/api/runs/{run_id}/end")
    def end_run(run_id: str) -> Dict[str, Any]:
        run = get_run(run_id)
        if not run.active:
            raise _fail(409, "not_active", "This run is not active.")
        run.end()
        return run.summary()

    @app.put("/api/runs/{run_id}/keep")
    def keep_run(run_id: str, body: KeepBody) -> Dict[str, Any]:
        run = get_run(run_id)
        run.meta["keep"] = body.keep
        run.save()
        return run.summary()

    @app.delete("/api/runs/{run_id}", status_code=204)
    def delete_run(run_id: str) -> Response:
        run = get_run(run_id)
        if run.active:
            raise _fail(409, "run_active", "End the run before deleting it.")
        if run.meta.get("keep"):
            raise _fail(409, "run_kept", "This run is kept. Remove the Keep pin to delete it.")
        store.delete(run)
        return Response(status_code=204)

    # -- events --------------------------------------------------------------
    @app.get("/api/runs/{run_id}/events")
    async def events(run_id: str, request: Request, follow: bool = True) -> StreamingResponse:
        run = get_run(run_id)
        try:
            cursor = int(request.headers.get("last-event-id", "-1")) + 1
        except ValueError:
            cursor = 0

        async def stream():
            position, idle = cursor, 0.0
            while True:
                batch = run.events[position:]
                if batch:
                    idle = 0.0
                    for event in batch:
                        yield f"id: {event['seq']}\ndata: {json.dumps(event, default=str)}\n\n"
                    position += len(batch)
                else:
                    if not follow or await request.is_disconnected():
                        return
                    idle += 0.25
                    if idle >= 15:
                        idle = 0.0
                        yield ": keep-alive\n\n"
                    await asyncio.sleep(0.25)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    # -- results -------------------------------------------------------------
    @app.get("/api/runs/{run_id}/summary")
    def summary(run_id: str) -> Dict[str, Any]:
        run = get_run(run_id)
        found = results(run)
        review = fx.build_review(found, run.outputs, run.meta["decisions"])
        return fx.build_summary(found, review, run.meta["decisions"])

    @app.get("/api/runs/{run_id}/findings")
    def list_findings(run_id: str, q: str = "", severity: str = "", status: str = "",
                      source: str = "", sort: str = "", dir: str = "asc",
                      page: int = 1, page_size: int = 50) -> Dict[str, Any]:
        run = get_run(run_id)
        return fx.query_findings(results(run), run.meta["decisions"], q, severity, status,
                                 source, sort, dir, page, page_size)

    @app.get("/api/runs/{run_id}/findings/{vuln_id}")
    def finding_detail(run_id: str, vuln_id: str) -> Dict[str, Any]:
        run = get_run(run_id)
        for finding in results(run):
            if finding["vuln_id"] == vuln_id:
                decisions = run.meta["decisions"]
                return dict(finding, status=fx.effective_status(finding, decisions),
                            decision=decisions.get(vuln_id),
                            reason=fx.review_reason(finding))
        raise _fail(404, "finding_not_found", f"{vuln_id} is not in this run.")

    @app.get("/api/runs/{run_id}/review")
    def review(run_id: str) -> Dict[str, Any]:
        run = get_run(run_id)
        return fx.build_review(results(run), run.outputs, run.meta["decisions"])

    # -- decisions -----------------------------------------------------------
    @app.get("/api/runs/{run_id}/decisions")
    def list_decisions(run_id: str) -> Dict[str, Any]:
        return {"decisions": get_run(run_id).meta["decisions"]}

    @app.post("/api/runs/{run_id}/decisions/{vuln_id}")
    def decide(run_id: str, vuln_id: str, body: DecisionBody) -> Dict[str, Any]:
        run = get_run(run_id)
        finding = next((f for f in results(run) if f["vuln_id"] == vuln_id), None)
        if finding is None:
            raise _fail(404, "finding_not_found", f"{vuln_id} is not in this run.")
        if body.action == "approve":
            decision = {"action": "approved", "status": finding["final_status"]}
        elif body.action == "override":
            if body.status not in OVERRIDE_STATUSES or body.status == finding["final_status"]:
                raise _fail(422, "override_status",
                            "Choose a status different from the ARES recommendation.")
            decision = {"action": "overridden", "status": body.status}
        elif body.action == "skip":
            decision = {"action": "skipped", "status": finding["final_status"]}
        else:
            raise _fail(422, "decision_action", "Action must be approve, override or skip.")
        decision["at"] = now_iso()
        with run.lock:
            run.meta["decisions"][vuln_id] = decision
            run.save()
        run.emit("decision", vuln_id=vuln_id, decision=decision)
        return {"vuln_id": vuln_id, "decision": decision}

    @app.delete("/api/runs/{run_id}/decisions/{vuln_id}")
    def undo(run_id: str, vuln_id: str) -> Dict[str, Any]:
        run = get_run(run_id)
        with run.lock:
            removed = run.meta["decisions"].pop(vuln_id, None)
            run.save()
        if removed is not None:
            run.emit("decision", vuln_id=vuln_id, decision=None)
        return {"vuln_id": vuln_id, "decision": None}

    # -- exports (built on request, never on page load) ----------------------
    @app.get("/api/runs/{run_id}/export/{fmt}")
    def export(run_id: str, fmt: str) -> Response:
        run = get_run(run_id)
        if fmt not in exports.MEDIA_TYPES:
            raise _fail(404, "export_format", "Export format must be ckl, cklb, csv or json.")
        found, decisions = results(run), run.meta["decisions"]
        if fmt == "csv":
            body = exports.to_csv(found, decisions)
        elif fmt == "ckl":
            body = exports.to_ckl(found, decisions, run.meta)
        elif fmt == "cklb":
            body = exports.to_cklb(found, decisions, run.meta)
        else:
            review = fx.build_review(found, run.outputs, decisions)
            body = exports.to_json(found, decisions,
                                   fx.build_summary(found, review, decisions), run.meta)
        name = f"ares_reconciled_{run.id}.{fmt}"
        return Response(content=body, media_type=exports.MEDIA_TYPES[fmt],
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    stigs.register(app)
    targets.register(app)
    scap.register(app)

    # -- frontend ------------------------------------------------------------
    dist = config.PROJECT_ROOT / "frontend" / "dist"
    if (dist / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> Response:
            if path.startswith("api/"):
                raise _fail(404, "not_found", "Unknown API route.")
            candidate = (dist / path).resolve()
            if path and candidate.is_file() and dist.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")

    return app
