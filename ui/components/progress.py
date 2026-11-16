"""
Workflow Progress Page

Displays real-time pipeline execution with:
- Step-by-step status (Pending → Running → Complete)
- CLI terminal output for agents that execute commands
- Duration per step and overall elapsed time
- Summary data at each completed step
"""

import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ui.orchestrator_runner import STEP_DEFINITIONS


def render_progress():
    """Workflow progress visualization and execution trigger."""
    st.header("Workflow Progress")

    if not st.session_state.workflow_started:
        st.info("No workflow running. Start one from the **Upload** tab.")
        return

    # Show pipeline error if one occurred
    pipeline_error = st.session_state.get("pipeline_error")
    if pipeline_error:
        st.error(
            f"**Pipeline failed at Step {pipeline_error['step'] + 1}** "
            f"({pipeline_error['type']}): {pipeline_error['error']}"
        )
        if st.button("Retry Pipeline", key="btn_retry_pipeline"):
            st.session_state.pipeline_error = None
            _execute_pipeline()
            st.rerun()

    # Overall progress bar
    current_step = st.session_state.workflow_step
    total_steps = len(STEP_DEFINITIONS)
    progress_pct = min(current_step / total_steps, 1.0)

    if st.session_state.workflow_complete:
        elapsed = st.session_state.get("pipeline_elapsed", 0)
        st.progress(1.0, text=f"Complete — {total_steps}/{total_steps} steps ({elapsed:.1f}s)")
        st.success("Pipeline finished. Switch to the **Results** tab to review findings.")
    else:
        st.progress(progress_pct, text=f"Step {current_step} of {total_steps}")
        col_run, col_info = st.columns([1, 3])
        with col_run:
            if st.button("Run Pipeline", type="primary", key="btn_run_pipeline"):
                _execute_pipeline()
                st.rerun()
        with col_info:
            st.caption("Runs all 6 pipeline steps using mock agent responses.")

    st.divider()

    # Render each step
    for i, step_def in enumerate(STEP_DEFINITIONS):
        _render_step(i, step_def, current_step)

    # Footer actions (only when complete — mutually exclusive with "Run Pipeline" above)
    if st.session_state.workflow_complete:
        st.divider()
        if st.button("Start New Workflow", key="reset_workflow_progress"):
            _reset_all()
            st.rerun()


def _render_step(index: int, step_def: dict, current_step: int):
    """Render a single pipeline step with status, timing, and output."""
    key = step_def["key"]
    data = st.session_state.get(key)
    duration = st.session_state.get("step_durations", {}).get(key)
    is_complete = index < current_step and data is not None
    is_current = index == current_step and not st.session_state.workflow_complete
    has_cli = step_def.get("has_cli", False)
    step_type = step_def.get("type", "agent")

    # Status badge
    if is_complete:
        icon = "🟢"
        duration_str = f" ({duration:.2f}s)" if duration else ""
        status_label = f"Complete{duration_str}"
    elif is_current:
        icon = "🟠"
        status_label = "Next"
    else:
        icon = "⚪"
        status_label = "Pending"

    # Type badge
    type_badge = "[SCRIPT]" if step_type == "script" else "[AGENT]"

    header = f"{icon} Step {index + 1}: {step_def['name']} {type_badge} — {status_label}"

    with st.expander(header, expanded=is_complete or is_current):
        st.caption(step_def["description"])

        if is_complete and data is not None:
            _render_step_output(key, data, has_cli)
        elif is_current:
            st.caption("Ready to execute. Click **Run Pipeline** above.")


def _render_step_output(key: str, data, has_cli: bool):
    """Render the output summary and CLI terminal for a completed step."""

    if key == "parser_output" and isinstance(data, dict):
        t1 = data.get("tool1_findings", [])
        t2 = data.get("tool2_findings", [])
        meta = data.get("metadata", {})
        tools = meta.get("source_tools", {})

        col1, col2 = st.columns(2)
        with col1:
            tool1_name = tools.get("tool1", {}).get("name", "Tool 1")
            st.metric("Tool 1 Findings", len(t1), help=tool1_name)
        with col2:
            tool2_name = tools.get("tool2", {}).get("name", "Tool 2")
            st.metric("Tool 2 Findings", len(t2), help=tool2_name)

    elif key == "identified_gaps" and isinstance(data, list):
        st.metric("Gaps Identified", len(data))
        if data:
            with st.container():
                for gap in data:
                    reason = gap.get("reason", "")
                    reviewed_by = gap.get("reviewed_by", "unknown")
                    st.markdown(f"- **{gap.get('vuln_id', 'Unknown')}** ({reviewed_by}): {reason}")

    elif key == "gap_coverage_results" and isinstance(data, list):
        st.metric("Gaps Validated", len(data))
        for item in data:
            _render_agent_finding(item)

    elif key == "comparison_output" and isinstance(data, dict):
        summary = data.get("summary", {})
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Compared", summary.get("total_compared", 0))
        with col2:
            st.metric("Agreements", summary.get("agreements", 0))
        with col3:
            st.metric("Disagreements", summary.get("disagreements", 0))

        # Show disagreements detail
        disagreements = data.get("disagreements", [])
        if disagreements:
            st.markdown("**Disagreements found:**")
            for d in disagreements:
                st.markdown(
                    f"- **{d['vuln_id']}** ({d['severity']}): "
                    f"Tool 1 = {d['tool1_status']}, Tool 2 = {d['tool2_status']} "
                    f"[{d.get('conflict_type', '')}]"
                )

    elif key == "determination_output" and isinstance(data, list):
        st.metric("Disagreements Resolved", len(data))
        for item in data:
            _render_agent_finding(item)

    elif key == "final_report" and isinstance(data, dict):
        metrics = data.get("metrics", {})
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Rules", metrics.get("total_rules", 0))
        with col2:
            st.metric("Open", metrics.get("open_count", 0))
        with col3:
            st.metric("Not a Finding", metrics.get("not_a_finding_count", 0))
        with col4:
            st.metric("Needs Review", metrics.get("requires_review", 0))


def _render_agent_finding(item: dict):
    """Render a single agent finding with CLI terminal output."""
    vuln_id = item.get("vuln_id", "Unknown")
    status = item.get("status") or item.get("ares_verdict", "Unknown")
    confidence = item.get("confidence_score", "?")

    with st.container(border=True):
        # Header row
        col1, col2, col3 = st.columns([2, 2, 1])
        with col1:
            st.markdown(f"**{vuln_id}**")
        with col2:
            st.markdown(f"Verdict: **{status}**")
        with col3:
            st.markdown(f"Confidence: **{confidence}%**")

        # Evidence
        evidence = item.get("evidence") or item.get("finding_details", "")
        if evidence:
            st.caption(evidence)

        # CLI terminal output
        commands = item.get("commands_executed", [])
        outputs = item.get("command_outputs", [])

        if commands:
            st.markdown("**CLI Execution:**")
            for j, cmd in enumerate(commands):
                st.code(f"$ {cmd}", language="bash")
                if j < len(outputs) and outputs[j]:
                    st.code(outputs[j], language="text")


def _execute_pipeline():
    """Run the full pipeline via orchestrator runner."""
    import os
    from ui.orchestrator_runner import run_pipeline

    use_mock = os.environ.get("ARES_USE_MOCK", "true").lower() != "false"
    run_pipeline(use_mock=use_mock)


def _reset_all():
    """Reset workflow state."""
    keys_to_clear = [
        "uploaded_files", "workflow_started", "workflow_step", "workflow_complete",
        "parser_output", "identified_gaps", "gap_coverage_results",
        "comparison_output", "determination_output", "final_report",
        "review_queue", "review_decisions", "step_durations", "pipeline_elapsed",
        "pipeline_error",
    ]
    for key in keys_to_clear:
        if key == "workflow_started":
            st.session_state[key] = False
        elif key == "workflow_step":
            st.session_state[key] = 0
        elif key == "workflow_complete":
            st.session_state[key] = False
        elif key in ("review_decisions", "step_durations"):
            st.session_state[key] = {}
        elif key == "pipeline_elapsed":
            st.session_state[key] = 0
        else:
            st.session_state[key] = None
