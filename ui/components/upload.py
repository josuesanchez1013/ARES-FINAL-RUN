"""
File Upload Component

Handles scan file uploads and the "Use Sample Data" shortcut.
Persists file data into st.session_state for downstream pipeline use.
"""

import sys
import json
import streamlit as st
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


SAMPLE_DATA_PATH = Path(__file__).parent.parent.parent / "mcp_server" / "example_parser_output.json"


def render_upload_page():
    """File upload interface for the Upload tab."""
    st.header("Upload Scan Files")
    st.markdown("Upload STIG scan outputs from two tools (CKL or CSV format).")

    # Demo mode: one-click start
    if st.session_state.get("demo_mode") and not st.session_state.workflow_started:
        st.info("**Demo Mode** — Click below to run the full pipeline with sample data.")
        if st.button("Run Demo", type="primary"):
            _load_sample_data()
            st.rerun()
        st.divider()

    # If workflow already started, show status instead of upload
    if st.session_state.workflow_started:
        st.success("Workflow is running. Switch to the **Progress** tab to monitor.")
        if st.button("Reset Workflow", key="reset_workflow_upload"):
            _reset_workflow()
            st.rerun()
        return

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Tool 1 Scan Output")
        tool1_file = st.file_uploader(
            "Upload first scan file (e.g., PreSTIGe .ckl)",
            type=["ckl", "csv"],
            key="tool1_upload",
        )

    with col2:
        st.subheader("Tool 2 Scan Output")
        tool2_file = st.file_uploader(
            "Upload second scan file (e.g., evaluate-STIG .csv)",
            type=["ckl", "csv"],
            key="tool2_upload",
        )

    # Show file details if uploaded
    if tool1_file:
        st.caption(f"Tool 1: {tool1_file.name} ({tool1_file.size:,} bytes)")
    if tool2_file:
        st.caption(f"Tool 2: {tool2_file.name} ({tool2_file.size:,} bytes)")

    st.divider()

    col_start, col_sample = st.columns(2)

    with col_start:
        start_disabled = not (tool1_file and tool2_file)
        if st.button("Start Workflow", disabled=start_disabled, type="primary"):
            st.session_state.uploaded_files = {
                "tool1_name": tool1_file.name,
                "tool1_bytes": tool1_file.getvalue(),
                "tool2_name": tool2_file.name,
                "tool2_bytes": tool2_file.getvalue(),
            }
            _start_workflow()
            st.rerun()

    with col_sample:
        if st.button("Use Sample Data", help="Load example parser output for testing/demo"):
            _load_sample_data()
            st.rerun()

    if start_disabled and not tool1_file and not tool2_file:
        st.info("Upload both scan files to enable the workflow, or use sample data for testing.")


def _load_sample_data():
    """Load example_parser_output.json directly into session state, bypassing Parser Agent."""
    if not SAMPLE_DATA_PATH.exists():
        st.error(f"Sample data not found: {SAMPLE_DATA_PATH}")
        return

    with open(SAMPLE_DATA_PATH) as f:
        sample = json.load(f)

    st.session_state.uploaded_files = {
        "tool1_name": sample["metadata"]["source_tools"]["tool1"]["file"],
        "tool1_bytes": None,
        "tool2_name": sample["metadata"]["source_tools"]["tool2"]["file"],
        "tool2_bytes": None,
    }
    # Skip Parser Agent — load pre-parsed output directly
    st.session_state.parser_output = sample
    _start_workflow(skip_parser=True)

    # In demo mode, run the full pipeline immediately so Progress tab just renders results
    if st.session_state.get("demo_mode"):
        import os
        from ui.orchestrator_runner import run_pipeline
        use_mock = os.environ.get("ARES_USE_MOCK", "true").lower() != "false"
        run_pipeline(use_mock=use_mock)
        if st.session_state.get("pipeline_error"):
            st.error(
                f"Pipeline error: {st.session_state.pipeline_error['error']}"
            )
            return


def _start_workflow(skip_parser=False):
    """Initialize workflow state."""
    st.session_state.workflow_started = True
    st.session_state.workflow_step = 1 if skip_parser else 0
    st.session_state.workflow_complete = False

    # Reset downstream outputs
    if not skip_parser:
        st.session_state.parser_output = None
    st.session_state.identified_gaps = None
    st.session_state.gap_coverage_results = None
    st.session_state.comparison_output = None
    st.session_state.determination_output = None
    st.session_state.final_report = None
    st.session_state.review_queue = None
    st.session_state.review_decisions = {}


def _reset_workflow():
    """Reset all workflow state back to initial."""
    st.session_state.uploaded_files = None
    st.session_state.workflow_started = False
    st.session_state.workflow_step = 0
    st.session_state.workflow_complete = False
    st.session_state.parser_output = None
    st.session_state.identified_gaps = None
    st.session_state.gap_coverage_results = None
    st.session_state.comparison_output = None
    st.session_state.determination_output = None
    st.session_state.final_report = None
    st.session_state.review_queue = None
    st.session_state.review_decisions = {}
