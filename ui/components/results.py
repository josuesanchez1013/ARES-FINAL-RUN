"""
Results Dashboard Page

Displays final reconciled findings with:
- Metrics dashboard (tiles + charts)
- Filterable findings table
- Expandable evidence per finding
- Human review queue for low-confidence items
"""

import streamlit as st
import pandas as pd
from typing import List, Dict

from components.metrics_dashboard import render_metrics_dashboard
from components.review_queue import render_review_queue
from components.export import render_export


def render_results():
    """Results dashboard — metrics, findings table, review queue."""
    st.header("Results")

    if not st.session_state.workflow_complete:
        if st.session_state.workflow_started:
            st.info("Workflow is still running. Results will appear here when complete.")
        else:
            st.info("Start a workflow from the **Upload** tab to see results here.")
        return

    report = st.session_state.final_report
    if not report:
        st.warning("No report data available.")
        return

    # Metrics dashboard
    render_metrics_dashboard(report)

    st.divider()

    # Human review queue (if items need review)
    review_queue = st.session_state.get("review_queue", [])
    if review_queue:
        render_review_queue()
        st.divider()

    # Findings table
    _render_findings_table(report)

    st.divider()

    # Export section
    render_export()


def _render_findings_table(report: Dict):
    """Render the filterable findings table."""
    findings = report.get("reconciled_findings", [])
    if not findings:
        st.info("No findings to display.")
        return

    st.subheader("Reconciled Findings")

    # Filters
    col_f1, col_f2, col_f3 = st.columns(3)

    severity_options = ["All", "high", "medium", "low"]
    status_options = ["All", "Open", "NotAFinding", "Not_Reviewed"]
    source_options = ["All"] + sorted(set(f.get("source", "unknown") for f in findings))

    with col_f1:
        sev_filter = st.selectbox("Severity", severity_options, key="filter_severity")
    with col_f2:
        status_filter = st.selectbox("Status", status_options, key="filter_status")
    with col_f3:
        source_filter = st.selectbox("Source", source_options, key="filter_source")

    # Apply filters
    filtered = findings
    if sev_filter != "All":
        filtered = [f for f in filtered if f.get("severity") == sev_filter]
    if status_filter != "All":
        filtered = [f for f in filtered if f.get("final_status") == status_filter]
    if source_filter != "All":
        filtered = [f for f in filtered if f.get("source") == source_filter]

    st.caption(f"Showing {len(filtered)} of {len(findings)} findings")

    # Apply human review overrides for display
    decisions = st.session_state.get("review_decisions", {})

    # Build dataframe for display
    rows = []
    for f in filtered:
        vuln_id = f.get("vuln_id", "")
        final_status = f.get("final_status", "")

        # Show override if human reviewed
        decision = decisions.get(vuln_id)
        if decision and decision.startswith("overridden:"):
            _, _, override_value = decision.partition(":")
            final_status = override_value + " (overridden)"
        elif decision and decision.startswith("approved:"):
            final_status = final_status + " (approved)"

        rows.append({
            "Vuln ID": vuln_id,
            "Severity": _severity_label(f.get("severity", "")),
            "ARES Verdict": final_status,
            "Tool 1": f.get("tool1_status") or "—",
            "Tool 2": f.get("tool2_status") or "—",
            "Confidence": f.get("confidence_score", 0),
            "Source": f.get("source", "unknown"),
        })

    if rows:
        df = pd.DataFrame(rows)
        st.dataframe(
            df,
            use_container_width=True,
            column_config={
                "Confidence": st.column_config.ProgressColumn(
                    "Confidence",
                    min_value=0,
                    max_value=100,
                    format="%d%%",
                ),
                "Severity": st.column_config.TextColumn("Severity", width="small"),
                "ARES Verdict": st.column_config.TextColumn("ARES Verdict", width="medium"),
            },
            hide_index=True,
        )

    # Expandable details per finding
    st.divider()
    st.subheader("Finding Details")

    for f in filtered:
        vuln_id = f.get("vuln_id", "Unknown")
        final_status = f.get("final_status", "Unknown")
        confidence = f.get("confidence_score", "?")
        severity = _severity_label(f.get("severity", ""))

        with st.expander(f"{vuln_id} — {final_status} ({severity}, {confidence}% confidence)"):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Tool 1 Status:** {f.get('tool1_status') or '—'}")
                st.markdown(f"**Tool 2 Status:** {f.get('tool2_status') or '—'}")
            with col2:
                st.markdown(f"**Source:** {f.get('source', 'unknown')}")
                st.markdown(f"**Confidence:** {confidence}%")

            # Show human decision if exists
            decision = decisions.get(vuln_id)
            if decision:
                st.success(f"Human decision: **{decision}**")


def _severity_label(severity: str) -> str:
    """Convert severity to display label."""
    mapping = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
    return mapping.get(severity, severity)
