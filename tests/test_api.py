"""
Offline tests for the ARES API. No network, no Genesis, no MCP server:
everything runs against the mock pipeline or synthetic step outputs.

    python -m pytest tests -q
"""

import json
import sys
import time
import types
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient

from ares_api.app import create_app
from ares_api.pipeline import BridgePipeline, mask_upload

CKL = (b"<CHECKLIST><ASSET><HOST_NAME>prod-db-01</HOST_NAME><HOST_IP>10.9.8.7</HOST_IP>"
       b"<HOST_MAC>aa:bb:cc:dd:ee:ff</HOST_MAC></ASSET></CHECKLIST>")
FORM = {"classification": "CUI", "sensitivity": "None",
        "primary_model": "model-a", "secondary_model": ""}


def files():
    return {"tool1": ("scan1.ckl", CKL, "application/xml"),
            "tool2": ("scan2.csv", b"Vuln_ID,Status\nV-1,Open\n", "text/csv")}


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("ARES_USE_MOCK", "true")
    monkeypatch.setenv("ARES_MOCK_STEP_DELAY", "0")
    monkeypatch.setenv("ARES_LLM_MODELS", "model-a,model-b")
    return tmp_path


@pytest.fixture
def client(env):
    return TestClient(create_app(env))


def wait_for(client, run_id, statuses, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in statuses:
            return run
        time.sleep(0.02)
    raise AssertionError(f"run stayed {run['status']}, wanted {statuses}")


def completed_run(client):
    run = client.post("/api/runs", data=FORM, files=files()).json()
    return wait_for(client, run["id"], {"completed"})


def events(client, run_id, headers=None):
    body = client.get(f"/api/runs/{run_id}/events?follow=false", headers=headers or {}).text
    return [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]


# -- service ---------------------------------------------------------------

def test_health_and_schema_start_offline(client):
    health = client.get("/api/health").json()
    assert health["status"] == "ok" and health["pipeline_ready"] and health["mode"] == "mock"
    paths = client.get("/api/openapi.json").json()["paths"]
    assert "/api/runs" in paths and "/api/runs/{run_id}/events" in paths


def test_settings_render_from_api(client):
    settings = client.get("/api/settings").json()
    assert settings["models"] == ["model-a", "model-b"]
    assert settings["editable"] is False and "Classified" in settings["refused_classifications"]


# -- data-handling declaration and model pickers ---------------------------

@pytest.mark.parametrize("change,code", [
    ({"classification": ""}, "classification_required"),
    ({"classification": "Classified"}, "classified_refused"),
    ({"sensitivity": ""}, "sensitivity_required"),
    ({"sensitivity": "None,PII"}, "sensitivity_conflict"),
    ({"primary_model": ""}, "model_not_listed"),
    ({"primary_model": "unlisted"}, "model_not_listed"),
    ({"secondary_model": "unlisted"}, "model_not_listed"),
])
def test_start_is_refused_before_anything_is_stored(client, env, change, code):
    response = client.post("/api/runs", data={**FORM, **change}, files=files())
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == code
    assert list(env.iterdir()) == []
    assert client.get("/api/runs/current").json()["run"] is None


def test_upload_is_masked_before_it_reaches_disk(client, env):
    run = completed_run(client)
    stored = (env / run["id"] / "uploads" / "tool1.ckl").read_bytes()
    assert b"prod-db-01" not in stored and b"10.9.8.7" not in stored
    assert stored.count(b"MASKED") == 3
    assert mask_upload("scan.csv", b"host,10.1.1.1")[1] == 0


# -- lifecycle -------------------------------------------------------------

def test_run_completes_and_reports_results(client):
    run = completed_run(client)
    assert [s["state"] for s in run["steps"]] == ["done"] * 6
    assert run["model_check"] and all(c["ok"] for c in run["model_check"])
    summary = client.get(f"/api/runs/{run['id']}/summary").json()
    assert summary["total"] == 6
    assert summary["by_status"] == {"Open": 3, "NotAFinding": 3,
                                    "Not_Applicable": 0, "Not_Reviewed": 0}
    assert summary["review_required"] == 1 and summary["review_pending"] == 1


def test_run_lock_refuses_a_second_start(client, monkeypatch):
    monkeypatch.setenv("ARES_MOCK_STEP_DELAY", "0.2")
    first = client.post("/api/runs", data=FORM, files=files())
    assert first.status_code == 201
    second = client.post("/api/runs", data=FORM, files=files())
    assert second.status_code == 409
    assert second.json()["detail"]["run_id"] == first.json()["id"]
    client.post(f"/api/runs/{first.json()['id']}/end")
    wait_for(client, first.json()["id"], {"ended"})


def test_pause_resume_end_then_resume_unfinished(client, monkeypatch):
    monkeypatch.setenv("ARES_MOCK_STEP_DELAY", "0.1")
    run_id = client.post("/api/runs", data=FORM, files=files()).json()["id"]
    assert client.post(f"/api/runs/{run_id}/pause").json()["status"] == "paused"
    time.sleep(0.5)
    paused = client.get(f"/api/runs/{run_id}").json()
    assert paused["status"] == "paused" and paused["step_index"] < 6
    frozen = len(events(client, run_id))
    time.sleep(0.3)
    assert len(events(client, run_id)) == frozen  # nothing advances while paused

    assert client.post(f"/api/runs/{run_id}/resume").json()["status"] == "running"
    client.post(f"/api/runs/{run_id}/end")
    ended = wait_for(client, run_id, {"ended"})
    assert ended["resumable"] and not ended["has_results"]
    assert client.get(f"/api/runs/{run_id}/summary").status_code == 409

    monkeypatch.setenv("ARES_MOCK_STEP_DELAY", "0")
    assert client.post(f"/api/runs/{run_id}/resume").status_code == 200
    assert wait_for(client, run_id, {"completed"})["has_results"]
    assert client.post(f"/api/runs/{run_id}/resume").status_code == 409


def test_interrupted_run_survives_restart_and_resumes(client, env, monkeypatch):
    monkeypatch.setenv("ARES_MOCK_STEP_DELAY", "0.2")
    run_id = client.post("/api/runs", data=FORM, files=files()).json()["id"]
    client.post(f"/api/runs/{run_id}/pause")
    restarted = TestClient(create_app(env))  # same data directory, new process state
    run = restarted.get("/api/runs/current").json()["run"]
    assert run["id"] == run_id and run["status"] == "interrupted" and run["resumable"]
    monkeypatch.setenv("ARES_MOCK_STEP_DELAY", "0")
    restarted.post(f"/api/runs/{run_id}/resume")
    wait_for(restarted, run_id, {"completed"})
    client.post(f"/api/runs/{run_id}/end")  # release the first app's parked worker


# -- events ----------------------------------------------------------------

def test_late_joiner_receives_full_history_then_resumes_from_last_id(client):
    run = completed_run(client)
    history = events(client, run["id"])
    assert [e["seq"] for e in history] == list(range(len(history)))
    kinds = {e["type"] for e in history}
    assert {"status", "model_check", "step", "log", "rule"} <= kinds
    assert history[-1] == {**history[-1], "type": "status", "status": "completed"}
    rules = [e for e in history if e["type"] == "rule"]
    assert {e["state"] for e in rules} == {"running", "done"}
    tail = events(client, run["id"], {"Last-Event-ID": str(history[4]["seq"])})
    assert tail == history[5:]


# -- findings --------------------------------------------------------------

def production_outputs(count=366):
    """Step outputs in the production shape (no reconciled_findings in the report)."""
    tool1, tool2, agreements, gaps, disagreements, determinations = [], [], [], [], [], []
    for n in range(count):
        vuln = f"V-{230000 + n}"
        rule = {"vuln_id": vuln, "rule_id": f"SV-{230000 + n}r1_rule",
                "severity": ["CAT I", "CAT II", "CAT III"][n % 3], "rule_title": f"Rule title {n}"}
        if n < 300:
            status = "Open" if n % 4 == 0 else "NotAFinding"
            tool1.append({**rule, "status": status})
            tool2.append({**rule, "status": status})
            agreements.append({**rule, "final_status": status})
        elif n < 340:
            tool1.append({**rule, "status": "Not_Reviewed"})
            tool2.append({**rule, "status": "Open"})
            verdict = "Not_Reviewed" if n >= 335 else "Not a Finding"
            gaps.append({"vuln_id": vuln, "rule_id": rule["rule_id"], "ares_verdict": verdict,
                         "confidence": 0 if n >= 335 else 95, "finding_details": "checked",
                         "commands_executed": ["getenforce"], "command_outputs": ["Enforcing"]})
        else:
            tool1.append({**rule, "status": "Open"})
            tool2.append({**rule, "status": "NotAFinding"})
            disagreements.append({**rule, "tool1_status": "Open", "tool2_status": "NotAFinding",
                                  "conflict_type": "status_mismatch"})
            determinations.append({"vuln_id": vuln, "rule_id": rule["rule_id"],
                                   "ares_verdict": "Open", "confidence": 70 if n % 2 else 96,
                                   "finding_details": "evidence"})
    return {
        "parser_output": {"tool1_findings": tool1, "tool2_findings": tool2},
        "identified_gaps": gaps, "gap_coverage_results": gaps,
        "comparison_output": {"agreements": agreements, "disagreements": disagreements},
        "determination_output": determinations,
        "final_report": {"ckl_file": "x.ckl", "metrics": {}, "human_review_queue": []},
    }


@pytest.fixture
def big_run(client):
    run = completed_run(client)
    stored = client.app.state.store.get(run["id"])
    stored.outputs = production_outputs()
    return run["id"]


def test_all_366_production_rows_page_search_and_sort(client, big_run):
    seen = []
    for page in range(1, 9):
        body = client.get(f"/api/runs/{big_run}/findings?page={page}&page_size=50").json()
        assert body["total"] == 366
        seen += [r["vuln_id"] for r in body["rows"]]
    assert len(seen) == 366 and len(set(seen)) == 366

    rows = client.get(f"/api/runs/{big_run}/findings?page_size=500").json()["rows"]
    unscored = [r["status"] == "Not_Reviewed" for r in rows]
    assert unscored == sorted(unscored) and sum(unscored) == 5  # unscored rows come last
    assert rows[0]["severity"] == "high"

    assert client.get(f"/api/runs/{big_run}/findings?q=V-230365").json()["total"] == 1
    assert client.get(f"/api/runs/{big_run}/findings?q=rule title 12").json()["total"] == 11
    gap_rows = client.get(f"/api/runs/{big_run}/findings?source=gap_coverage_agent").json()
    assert gap_rows["total"] == 40
    by_conf = client.get(f"/api/runs/{big_run}/findings?sort=confidence&dir=desc").json()["rows"]
    assert by_conf[0]["confidence_score"] == 100

    summary = client.get(f"/api/runs/{big_run}/summary").json()
    assert summary["agreements"] == 300 and summary["gaps_validated"] == 40
    assert summary["disagreements_resolved"] == 26
    assert sum(summary["by_status"].values()) == 366

    detail = client.get(f"/api/runs/{big_run}/findings/V-230300").json()
    assert detail["status"] == "NotAFinding" and detail["commands_executed"] == ["getenforce"]
    assert detail["scanner"]["tool2"]["status"] == "Open"


def test_review_queue_is_derived_for_production_runs(client, big_run):
    review = client.get(f"/api/runs/{big_run}/review").json()
    reasons = {c["reason"] for c in review["required"]}
    assert "No verdict was reached" in reasons and "Confidence below 80%" in reasons
    assert review["pending"] == len(review["required"]) == 5 + 13
    assert all(c["source"] != "agreement" for c in review["optional"])


# -- decisions and exports -------------------------------------------------

def ckl_status(client, run_id, vuln_id):
    root = ET.fromstring(client.get(f"/api/runs/{run_id}/export/ckl").content)
    for vuln in root.iter("VULN"):
        if vuln.find("STIG_DATA/ATTRIBUTE_DATA").text == vuln_id:
            return vuln.find("STATUS").text, vuln.find("COMMENTS").text
    raise AssertionError(vuln_id)


def test_override_then_undo_reaches_every_export(client, env):
    run_id = completed_run(client)["id"]
    base = f"/api/runs/{run_id}"
    assert ckl_status(client, run_id, "V-230221")[0] == "Open"

    bad = client.post(f"{base}/decisions/V-230221", json={"action": "override", "status": "Open"})
    assert bad.status_code == 422
    client.post(f"{base}/decisions/V-230221", json={"action": "override", "status": "NotAFinding"})
    status, comment = ckl_status(client, run_id, "V-230221")
    assert status == "NotAFinding" and "overridden:NotAFinding" in comment
    assert "V-230221,SV-230221r627750_rule,high,NotAFinding,Open,NotAFinding,88," in \
        client.get(f"{base}/export/csv").text
    cklb = client.get(f"{base}/export/cklb").json()
    rule = next(r for r in cklb["stigs"][0]["rules"] if r["group_id"] == "V-230221")
    assert rule["status"] == "not_a_finding" and cklb["stigs"][0]["size"] == 6
    exported = client.get(f"{base}/export/json").json()
    assert exported["review_decisions"] == {"V-230221": "overridden:NotAFinding"}
    assert client.get(f"{base}/review").json()["pending"] == 0

    # decisions persist and are shared: a fresh app on the same data sees them
    other_tab = TestClient(create_app(env))
    assert other_tab.get(f"{base}/decisions").json()["decisions"]["V-230221"]["status"] == "NotAFinding"

    client.delete(f"{base}/decisions/V-230221")
    assert ckl_status(client, run_id, "V-230221") == (
        "Open", "ARES reconciled (source: determination_agent, confidence: 88%)")
    assert client.get(f"{base}/review").json()["pending"] == 1
    assert events(client, run_id)[-1]["type"] == "decision"


def test_approve_and_skip(client):
    run_id = completed_run(client)["id"]
    base = f"/api/runs/{run_id}"
    client.post(f"{base}/decisions/V-230221", json={"action": "skip"})
    assert client.get(f"{base}/review").json()["pending"] == 1  # skipped is still pending
    assert "Human decision" not in ckl_status(client, run_id, "V-230221")[1]
    client.post(f"{base}/decisions/V-230221", json={"action": "approve"})
    assert client.get(f"{base}/review").json()["pending"] == 0
    assert "approved:Open" in ckl_status(client, run_id, "V-230221")[1]
    assert client.post(f"{base}/decisions/V-0", json={"action": "approve"}).status_code == 404


# -- past runs -------------------------------------------------------------

def test_past_runs_list_and_keep_pin(client):
    first = completed_run(client)["id"]
    second = completed_run(client)["id"]
    runs = client.get("/api/runs").json()["runs"]
    assert [r["id"] for r in runs] == [second, first]
    assert runs[0]["counts"] == {"total": 6, "open": 3, "review_pending": 1}
    client.put(f"/api/runs/{first}/keep", json={"keep": True})
    assert client.delete(f"/api/runs/{first}").status_code == 409
    assert client.delete(f"/api/runs/{second}").status_code == 204
    assert [r["id"] for r in client.get("/api/runs").json()["runs"]] == [first]


def test_retention_prunes_old_runs_but_not_kept_ones(env, monkeypatch):
    monkeypatch.setenv("ARES_RUN_RETENTION", "2")
    client = TestClient(create_app(env))
    kept = completed_run(client)["id"]
    client.put(f"/api/runs/{kept}/keep", json={"keep": True})
    for _ in range(4):
        completed_run(client)
    ids = [r["id"] for r in client.get("/api/runs").json()["runs"]]
    assert kept in ids and len(ids) <= 4


# -- bridge to the existing orchestrator -----------------------------------

def test_bridge_runs_orchestrator_code_without_streamlit(env, monkeypatch):
    """A stand-in orchestrator that uses st.session_state the way the real one does."""
    orch = types.ModuleType("ui.orchestrator_runner")
    orch.st = None
    orch.AGENT_IDS = {"parser": "agent-1"}
    seen = {}

    class Executor:
        def __init__(self, **kwargs):
            seen.update(kwargs)

    orch.LocalAgentExecutor = Executor

    def execute_next_step(use_mock=True):
        st = orch.st
        step = st.session_state.workflow_step
        key = ["parser_output", "identified_gaps", "gap_coverage_results",
               "comparison_output", "determination_output", "final_report"][step]
        if "all_step_logs" not in st.session_state:
            st.session_state.all_step_logs = {}
        if key not in st.session_state.all_step_logs:
            st.session_state.all_step_logs[key] = []
        log = st.session_state.all_step_logs[key]
        if step == 0:
            uploaded = st.session_state.get("uploaded_files", {})
            assert uploaded["tool1_name"] == "scan1.ckl" and b"MASKED" in uploaded["tool1_bytes"]
            st.session_state.parser_output = production_outputs(6)["parser_output"]
        elif step == 2:
            orch.LocalAgentExecutor(model="hardcoded", max_iterations=25)
            log.append({"level": "header", "message": "\n📋 Gap 1/1: V-230003"})
            log.append({"level": "success", "message": "Result: NotAFinding, Confidence: 95%"})
            st.session_state.gap_coverage_results = [
                {"vuln_id": "V-230003", "ares_verdict": "NotAFinding", "confidence": 95}]
        elif step == 5:
            assert st.session_state.parser_output and st.session_state.gap_coverage_results
            st.session_state.final_report = {"ckl_file": "x.ckl", "metrics": {}}
            st.session_state.workflow_complete = True
        else:
            st.session_state[key] = {"agreements": [], "disagreements": []} if step == 3 else []
        st.session_state.workflow_step = step + 1

    orch.execute_next_step = execute_next_step
    package = types.ModuleType("ui")
    package.orchestrator_runner = orch
    monkeypatch.setitem(sys.modules, "ui", package)
    monkeypatch.setitem(sys.modules, "ui.orchestrator_runner", orch)
    monkeypatch.setenv("ARES_USE_MOCK", "false")
    monkeypatch.setenv("MCP_SERVER_URL", "https://mcp.test.invalid")

    assert BridgePipeline().available() is None
    client = TestClient(create_app(env))
    assert client.get("/api/health").json()["mode"] == "production"
    run = completed_run(client)
    assert seen["model"] == "model-a"  # the picked primary model reaches the executor
    assert orch.st is None  # the orchestrator module is restored after every step
    history = events(client, run["id"])
    rule = [e for e in history if e["type"] == "rule"]
    assert [(e["state"], e["vuln_id"]) for e in rule] == [("running", "V-230003"),
                                                          ("done", "V-230003")]
    assert rule[1]["verdict"] == "NotAFinding" and rule[1]["confidence"] == 95
    assert client.get(f"/api/runs/{run['id']}/summary").json()["gaps_validated"] == 1


def test_production_start_is_refused_when_pipeline_cannot_load(env, monkeypatch):
    monkeypatch.setenv("ARES_USE_MOCK", "false")
    monkeypatch.setitem(sys.modules, "ui.orchestrator_runner", None)  # import fails
    client = TestClient(create_app(env))
    health = client.get("/api/health").json()
    assert health["pipeline_ready"] is False and health["pipeline_error"]
    response = client.post("/api/runs", data=FORM, files=files())
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "pipeline_unavailable"


def test_production_run_stops_at_model_check_without_mcp_server_url(env, monkeypatch):
    """No MCP_SERVER_URL: the run must fail before the orchestrator is called,
    so uploads never go to the orchestrator's built-in default server."""
    called = []
    orch = types.ModuleType("ui.orchestrator_runner")
    orch.st = None
    orch.AGENT_IDS = {"parser": "agent-1"}
    orch.LocalAgentExecutor = object
    orch.execute_next_step = lambda use_mock=False: called.append(1)
    package = types.ModuleType("ui")
    package.orchestrator_runner = orch
    monkeypatch.setitem(sys.modules, "ui", package)
    monkeypatch.setitem(sys.modules, "ui.orchestrator_runner", orch)
    monkeypatch.setenv("ARES_USE_MOCK", "false")
    monkeypatch.delenv("MCP_SERVER_URL", raising=False)

    client = TestClient(create_app(env))
    started = client.post("/api/runs", data=FORM, files=files())
    assert started.status_code == 201
    run_id = started.json()["id"]
    for _ in range(100):
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in ("failed", "completed", "ended"):
            break
        time.sleep(0.05)
    assert run["status"] == "failed"
    assert "MCP_SERVER_URL" in run["error"]
    assert called == []
