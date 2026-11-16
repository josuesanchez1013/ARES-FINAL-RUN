import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import streamlit as st

# Ensure project root is on path for genesis_integration imports
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from components.workflow import render_workflow_page
from components.results import render_results

def init_session_state():
    """Initialize all session state keys used across the pipeline."""
    defaults = {
        # Upload
        "uploaded_files": None,
        "workflow_started": False,
        "workflow_step": 0,
        "workflow_complete": False,

        # Pipeline outputs
        "parser_output": None,
        "identified_gaps": None,
        "gap_coverage_results": None,
        "comparison_output": None,
        "determination_output": None,
        "final_report": None,

        # Human review
        "review_queue": None,
        "review_decisions": {},

        # Timing
        "step_durations": {},
        "pipeline_elapsed": 0,
        "pipeline_error": None,

        # Demo mode
        "demo_mode": False,
        
        # Execution lock for one-at-a-time usage
        "workflow_lock": None,  # {"session_id": str, "started_at": timestamp, "user_info": str}
        
        # Live terminal logs
        "live_terminal_logs": [],  # List of timestamped log entries
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def render_sidebar():
    """Persistent sidebar with workflow status and demo controls."""
    with st.sidebar:
        st.markdown("# :shield:")
        st.title("ARES")
        st.caption("Automated Reconciliation and Evidence for STIGs")

        st.divider()

        # Mock data mode toggle
        demo = st.toggle("Mock Data Mode", value=st.session_state.demo_mode, key="demo_toggle")
        if demo != st.session_state.demo_mode:
            st.session_state.demo_mode = demo
        if st.session_state.demo_mode:
            st.caption("Using pre-canned mock data for development/testing.")

        st.divider()

        # Workflow status
        st.markdown("**Workflow Status**")
        if not st.session_state.workflow_started:
            st.markdown("Not started")
            st.progress(0, text="0 of 6 steps")
        elif st.session_state.workflow_complete:
            elapsed = st.session_state.get("pipeline_elapsed", 0)
            st.markdown(f"✅ Complete ({elapsed:.1f}s)")
            st.progress(1.0, text="6 of 6 steps")
        else:
            step = st.session_state.workflow_step
            progress_pct = step / 6.0
            st.markdown(f"⏳ Running")
            st.progress(progress_pct, text=f"{step} of 6 steps")

        # Step list
        step_names = [
            "Parser Agent",
            "Gap Identifier",
            "Gap Coverage Agent",
            "Comparison Script",
            "Determination Agent",
            "Reporting Agent",
        ]
        current = st.session_state.workflow_step
        for i, name in enumerate(step_names):
            if i < current:
                st.markdown(f"  🟢 ~~{name}~~")
            elif i == current and st.session_state.workflow_started and not st.session_state.workflow_complete:
                st.markdown(f"  🟠 **{name}**")
            else:
                st.markdown(f"  ⚪ {name}")

        # Quick stats (only when data exists)
        if st.session_state.workflow_complete and st.session_state.final_report:
            st.divider()
            st.markdown("**Quick Stats**")
            metrics = st.session_state.final_report.get("metrics", {})
            st.markdown(f"- Rules: {metrics.get('total_rules', 0)}")
            st.markdown(f"- Disagreements: {metrics.get('disagreements_resolved', 0)}")
            st.markdown(f"- Gaps filled: {metrics.get('gaps_filled', 0)}")
            st.markdown(f"- Needs review: {metrics.get('requires_review', 0)}")

        st.divider()
        st.caption("ARES")


def main():
    st.set_page_config(
        page_title="ARES - STIG Validation",
        page_icon=":shield:",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    init_session_state()
    render_sidebar()

    # Header
    st.title("ARES: Automated Reconciliation and Evidence for STIGs")
    st.caption(
        "Multi-tool STIG reconciliation via Genesis AI agents | "
        "4 Agents + 2 Scripts | RHEL 8 STIG V2R7"
    )

    tab_labels = [":rocket: Workflow", ":bar_chart: Results"]
    tabs = st.tabs(tab_labels)

    with tabs[0]:
        render_workflow_page()

    with tabs[1]:
        render_results()


if __name__ == "__main__":
    main()
