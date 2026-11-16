"""
Pipeline adapters and the run worker.

The API never re-implements the reconciliation pipeline. It drives one of two
adapters through the same six steps:

- BridgePipeline (production): calls the existing `ui.orchestrator_runner`
  step by step. The orchestrator reads and writes `st.session_state`; the
  bridge hands it a plain in-memory state object instead, so the same code
  runs without Streamlit and its status messages become live API events.
  When the CORE service layer lands, replace this adapter with one that calls
  CORE; nothing else in the API changes.
- MockPipeline (ARES_USE_MOCK=true): pre-canned results, fully offline. Used
  by the tests and for demos.
"""

import copy
import re
import time
import traceback
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from cli_executor import target_context

from . import config, prompts, sample_data, stigs, targets
from .runs import Run, RunEnded, RunStore

STEPS: List[Dict[str, Any]] = [
    {"key": "parser_output", "name": "Parse scans", "type": "agent",
     "description": "Normalise both scan files to one schema"},
    {"key": "identified_gaps", "name": "Identify gaps", "type": "script",
     "description": "Find rules that a scanner left unreviewed"},
    {"key": "gap_coverage_results", "name": "Validate gaps", "type": "agent",
     "description": "Check each gap on the target system", "per_rule": True},
    {"key": "comparison_output", "name": "Compare tools", "type": "script",
     "description": "Sort rules into agreements and disagreements"},
    {"key": "determination_output", "name": "Resolve disagreements", "type": "agent",
     "description": "Decide each disagreement from evidence on the target", "per_rule": True},
    {"key": "final_report", "name": "Build report", "type": "agent",
     "description": "Assemble reconciled findings and the checklist"},
]

# ---------------------------------------------------------------------------
# Upload masking: uploads are masked in memory and only the masked copy is
# written to disk and handed to the worker.
# ---------------------------------------------------------------------------

_ASSET_TAGS = (b"HOST_NAME", b"HOST_IP", b"HOST_MAC", b"HOST_FQDN")


def mask_upload(name: str, data: bytes) -> Tuple[bytes, int]:
    """Blank asset identity fields in a CKL. Returns (masked bytes, fields masked)."""
    if not name.lower().endswith(".ckl"):
        return data, 0
    masked_fields = 0
    for tag in _ASSET_TAGS:
        pattern = re.compile(b"<" + tag + b">[^<]+</" + tag + b">")
        data, count = pattern.subn(b"<" + tag + b">MASKED</" + tag + b">", data)
        masked_fields += count
    return data, masked_fields


# ---------------------------------------------------------------------------
# Rule progress: derived from the orchestrator's own status messages so the
# UI can show which rules are in flight without changing the pipeline.
# ---------------------------------------------------------------------------

_RULE_START = re.compile(r"(?:Gap|Disagreement)\s+(\d+)/(\d+):\s*(\S+)")
_RULE_RESULT = re.compile(r"(?:Result|Status|ARES Verdict):\s*([A-Za-z_]+(?: [A-Za-z]+)*)")
_RULE_CONFIDENCE = re.compile(r"Confidence:\s*(\d+)\s*%")


class RuleTracker:
    """Turns 'Gap 3/40: V-230225' ... 'Result: Open, Confidence: 92%' into rule events."""

    def __init__(self, run: Run, step_key: str):
        self.run, self.step_key = run, step_key
        self.current: Optional[Dict[str, Any]] = None
        self.verdict: Optional[str] = None

    def feed(self, message: str) -> None:
        text = message.strip()
        start = _RULE_START.search(text)
        if start:
            self.finish()
            self.current = {"vuln_id": start.group(3), "index": int(start.group(1)),
                            "total": int(start.group(2))}
            self.run.emit("rule", step=self.step_key, state="running", **self.current)
            return
        if not self.current:
            return
        result = _RULE_RESULT.search(text)
        if result:
            self.verdict = result.group(1).strip()
        confidence = _RULE_CONFIDENCE.search(text)
        if self.verdict and confidence:  # same line or the line after the verdict
            self.finish(int(confidence.group(1)))

    def finish(self, confidence: Optional[int] = None) -> None:
        if self.current:
            self.run.emit("rule", step=self.step_key, state="done", verdict=self.verdict,
                          confidence=confidence, **self.current)
        self.current, self.verdict = None, None


# ---------------------------------------------------------------------------
# Mock pipeline
# ---------------------------------------------------------------------------

class MockPipeline:
    name = "mock"
    steps = STEPS

    def available(self) -> Optional[str]:
        return None

    def check_models(self, models: Dict[str, str]) -> List[Dict[str, Any]]:
        return [{"role": role, "model": model, "ok": True,
                 "detail": "Mock mode: model not contacted"}
                for role, model in models.items() if model]

    def run_step(self, index: int, run: Run) -> Any:
        key = STEPS[index]["key"]
        delay = config.mock_delay()

        def log(message: str, level: str = "info") -> None:
            run.checkpoint()
            run.log(key, level, message)

        def rules(items: List[Dict], verdict_key: str) -> None:
            for position, item in enumerate(items, 1):
                run.checkpoint()
                ident = {"vuln_id": item["vuln_id"], "index": position, "total": len(items)}
                run.emit("rule", step=key, state="running", **ident)
                log(f"{item['vuln_id']}: running checks on target")
                time.sleep(delay)
                run.emit("rule", step=key, state="done", verdict=item[verdict_key],
                         confidence=item["confidence_score"], **ident)
                log(f"{item['vuln_id']}: {item[verdict_key]} "
                    f"({item['confidence_score']}% confidence)", "success")

        report = sample_data.MOCK_REPORTING_OUTPUT
        findings = report["reconciled_findings"]
        time.sleep(delay)

        if key == "parser_output":
            def side(tool: str) -> List[Dict]:
                return [{"vuln_id": f["vuln_id"], "rule_id": f["rule_id"],
                         "severity": f["severity"],
                         "status": f[f"{tool}_status"] or "Not_Reviewed"} for f in findings]
            files = {f["role"]: f["name"] for f in run.meta["files"]}
            log("Mock data: uploaded files are stored but not parsed", "warning")
            chosen = run.meta.get("stig") or {}
            if chosen:
                log(f"STIG content: {chosen['title']} {chosen['version']} ({chosen['source']})")
            where = run.meta.get("target") or {}
            if where:
                log(f"Target: {where['name']} ({where['platform_label']}, {where['backend']})")
            output = {
                "tool1_findings": side("tool1"), "tool2_findings": side("tool2"),
                "metadata": {"source_tools": {
                    "tool1": {"file": files.get("tool1", "tool1"), "count": len(findings)},
                    "tool2": {"file": files.get("tool2", "tool2"), "count": len(findings)}},
                    "parser_version": "mock"},
            }
            log(f"Parsed {len(findings)} rules from each tool", "success")
            return output

        if key == "identified_gaps":
            gaps = []
            for f in findings:
                if f["source"] == "gap_coverage_agent":
                    reviewed_by = "tool2_only" if f["tool1_status"] in (None, "Not_Reviewed") else "tool1_only"
                    gaps.append({"vuln_id": f["vuln_id"], "rule_id": f["rule_id"],
                                 "reviewed_by": reviewed_by})
            log(f"{len(gaps)} gaps identified", "success")
            return gaps

        if key == "gap_coverage_results":
            rules(sample_data.MOCK_GAP_COVERAGE_OUTPUT, "status")
            return sample_data.MOCK_GAP_COVERAGE_OUTPUT

        if key == "comparison_output":
            agreements = [dict(f) for f in findings if f["source"] == "agreement"]
            disagreements = [
                {"vuln_id": f["vuln_id"], "rule_id": f["rule_id"], "severity": f["severity"],
                 "tool1_status": f["tool1_status"], "tool2_status": f["tool2_status"],
                 "conflict_type": "status_mismatch"}
                for f in findings if f["source"] == "determination_agent"]
            log(f"{len(agreements)} agreements, {len(disagreements)} disagreements", "success")
            return {"agreements": agreements, "disagreements": disagreements,
                    "summary": {"agreements": len(agreements),
                                "disagreements": len(disagreements),
                                "total_compared": len(findings)}}

        if key == "determination_output":
            rules(sample_data.MOCK_DETERMINATION_OUTPUT, "ares_verdict")
            return sample_data.MOCK_DETERMINATION_OUTPUT

        log("Reconciled findings assembled", "success")
        return report


# ---------------------------------------------------------------------------
# Bridge to the existing orchestrator
# ---------------------------------------------------------------------------

class _State(dict):
    """Stand-in for st.session_state: item and attribute access on one dict."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


class _LiveLog(list):
    def __init__(self, run: Run, step_key: str):
        super().__init__()
        self._run, self._key = run, step_key
        self._tracker = RuleTracker(run, step_key)

    def append(self, entry: Dict) -> None:  # called by the orchestrator's add_status
        super().append(entry)
        self._run.checkpoint()  # pause / end take effect at the next status message
        message = str(entry.get("message", ""))
        self._run.log(self._key, entry.get("level", "info"), message)
        self._tracker.feed(message)


class _Logs(dict):
    def __init__(self, run: Run):
        super().__init__()
        self._run = run

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, _LiveLog(self._run, key))


class BridgePipeline:
    name = "production"

    def __init__(self) -> None:
        self._orch = None
        self._error: Optional[str] = None

    def _load(self):
        if self._orch is None and self._error is None:
            try:
                import ui.orchestrator_runner as orch  # noqa: WPS433
                self._orch = orch
            except Exception as exc:  # missing dependency, bad .env, ...
                self._error = f"{type(exc).__name__}: {exc}"
        return self._orch

    @property
    def steps(self) -> List[Dict[str, Any]]:
        return STEPS

    def available(self) -> Optional[str]:
        """None when the production pipeline can be imported, else the reason."""
        self._load()
        return self._error

    def check_models(self, models: Dict[str, str]) -> List[Dict[str, Any]]:
        orch = self._load()
        results = []
        for role, model in models.items():
            if not model:
                continue
            ok = orch is not None
            detail = ("Listed in ARES_LLM_MODELS. Reachability is confirmed by the first agent call."
                      if ok else f"Pipeline unavailable: {self._error}")
            results.append({"role": role, "model": model, "ok": ok, "detail": detail})
        if orch is not None and not config.mcp_server_url():
            # Without this the orchestrator falls back to its built-in default,
            # the retired OpenShift server (DECISIONS D-004), and would send
            # the uploaded scans there.
            results.append({"role": "MCP server", "model": "", "ok": False,
                            "detail": "MCP_SERVER_URL is not set. Set it in .env to the MCP server "
                                      "this install should use; scans are not sent to a default server."})
        if orch is not None and not orch.AGENT_IDS.get("parser"):
            results.append({"role": "parser agent", "model": "", "ok": False,
                            "detail": "ARES_PARSER_AGENT_ID is not configured"})
        return results

    def run_step(self, index: int, run: Run) -> Any:
        orch = self._load()
        if orch is None:
            raise RuntimeError(f"Production pipeline unavailable: {self._error}")
        key = STEPS[index]["key"]

        state = _State(
            workflow_started=True, workflow_step=index, workflow_complete=False,
            pipeline_error=None, step_durations={}, pipeline_start_time=time.time(),
            all_step_logs=_Logs(run), review_queue=None, uploaded_files=self._uploads(run),
        )
        for step in STEPS:
            state[step["key"]] = run.outputs.get(step["key"])

        primary = run.meta["models"].get("primary")
        original_st, original_executor = orch.st, orch.LocalAgentExecutor

        # A run on a saved target (any platform) gets that target's connection,
        # safety rules and a platform-aware copy of the agent prompt. A run on
        # the default target leaves all of this exactly as it was.
        target = targets.active_for(run.meta.get("target"))

        def executor(*args: Any, **kwargs: Any):
            if primary:
                kwargs["model"] = primary
            if target is not None and kwargs.get("agent_prompt_file"):
                kwargs["agent_prompt_file"] = prompts.write_prompt(
                    kwargs["agent_prompt_file"], target, run.folder / "prompts")
            agent = original_executor(*args, **kwargs)
            if target is not None and hasattr(agent, "_get_tool_definitions"):
                definitions = prompts.adapt_tools(agent._get_tool_definitions(), target)
                agent._get_tool_definitions = lambda: copy.deepcopy(definitions)
            return agent

        # A run that chose imported STIG content serves it through the same
        # get_stig_loader() the orchestrator already calls (one run at a time).
        from genesis_integration import stig_loader as loader_module
        library_loader = stigs.loader_for(run.meta.get("stig"))
        if library_loader is not None:
            loader_module.set_stig_loader_override(library_loader)
            run.log(key, "info", f"STIG content: {run.meta['stig']['title']} "
                                 f"{run.meta['stig']['version']} ({len(library_loader.stig_data)} rules, imported library)")

        if target is not None:
            run.log(key, "info", f"Target: {target['name']} ({target['platform_label']}, {target['backend']})")
        target_context.set_active_target(target)

        orch.st = SimpleNamespace(session_state=state)
        orch.LocalAgentExecutor = executor
        try:
            orch.execute_next_step(use_mock=False)
        finally:
            orch.st, orch.LocalAgentExecutor = original_st, original_executor
            loader_module.set_stig_loader_override(None)
            target_context.set_active_target(None)
            log = state["all_step_logs"].get(key)
            if isinstance(log, _LiveLog):
                log._tracker.finish()
        # The orchestrator adds STIG titles and severity to earlier outputs in
        # place; persist those so they survive a restart.
        for step in STEPS[:index]:
            if state.get(step["key"]) is not None:
                run.save_output(step["key"], state[step["key"]])
        return state[key]

    @staticmethod
    def _uploads(run: Run) -> Dict[str, Any]:
        uploads: Dict[str, Any] = {}
        for item in run.meta["files"]:
            uploads[f"{item['role']}_name"] = item["name"]
            uploads[f"{item['role']}_bytes"] = (run.folder / "uploads" / item["stored_as"]).read_bytes()
        return uploads


def get_pipeline():
    return MockPipeline() if config.use_mock() else BridgePipeline()


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def run_worker(run: Run, pipeline, store: RunStore) -> None:
    """Execute the remaining steps of a run. Runs in its own thread."""
    index = run.meta["step_index"]
    try:
        if not run.meta["model_check"]:
            results = pipeline.check_models(run.meta["models"])
            run.meta["model_check"] = results
            run.save()
            run.emit("model_check", results=results)
            failed = [r for r in results if not r["ok"]]
            if failed:
                raise RuntimeError("Model check failed: " + "; ".join(r["detail"] for r in failed))
        run.checkpoint()
        if run.status == "checking":
            run.set_status("running")

        for index in range(run.meta["step_index"], len(run.meta["steps"])):
            run.checkpoint()
            run.set_step(index, "running")
            started = time.time()
            output = pipeline.run_step(index, run)
            run.save_output(run.meta["steps"][index]["key"], output)
            run.meta["step_index"] = index + 1
            run.set_step(index, "done", time.time() - started)
        run.set_status("completed")
    except RunEnded:
        if index < len(run.meta["steps"]) and run.meta["steps"][index]["state"] == "running":
            run.set_step(index, "pending")
        run.set_status("ended")
    except Exception as exc:  # a real failure: surfaced to the UI as such
        traceback.print_exc()
        if index < len(run.meta["steps"]) and run.meta["steps"][index]["state"] == "running":
            run.set_step(index, "failed")
        run.set_status("failed", error=f"{type(exc).__name__}: {exc}")
