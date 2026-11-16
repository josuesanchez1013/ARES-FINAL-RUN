"""
Metrics Dashboard Component

Renders summary metrics (tiles + charts) from the final report data.
Uses Streamlit's built-in charting (no plotly dependency needed).
"""

import streamlit as st
import pandas as pd
from typing import Dict, List

try:
    _ST_SUPPORTS_BAR_COLOR = tuple(
        int(x) for x in st.__version__.split(".")[:2]
    ) >= (1, 30)
except (AttributeError, ValueError):
    _ST_SUPPORTS_BAR_COLOR = False


def render_metrics_dashboard(report: Dict):
    """
    Render the summary metrics dashboard.

    Args:
        report: The final_report dict from session state
    """
    metrics = report.get("metrics", {})
    findings = report.get("reconciled_findings", [])

    # Metric tiles row
    st.subheader("Summary Metrics")
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total Rules", metrics.get("total_rules", 0))
    with col2:
        st.metric("Agreements", metrics.get("agreements", 0))
    with col3:
        st.metric(
            "Disagreements Resolved",
            metrics.get("disagreements_resolved", 0),
        )
    with col4:
        st.metric("Gaps Filled", metrics.get("gaps_filled", 0))
    with col5:
        st.metric(
            "Needs Review",
            metrics.get("requires_review", 0),
            help="Findings with confidence < 80%",
        )

    # Time saved callout — use actual measured time, not the mock's hardcoded value
    elapsed = st.session_state.get("pipeline_elapsed", 0)
    if elapsed:
        st.info(
            f"Pipeline completed in **{elapsed:.1f} seconds**. "
            f"Manual reconciliation takes **3-4 hours** per system."
        )

    st.divider()

    # Charts
    if findings:
        col_chart1, col_chart2 = st.columns(2)

        with col_chart1:
            _render_status_chart(findings)

        with col_chart2:
            _render_severity_chart(findings)

        st.divider()
        _render_tool_accuracy_chart(findings)


def _render_status_chart(findings: List[Dict]):
    """Bar chart showing distribution of final statuses."""
    st.markdown("**Status Distribution**")

    status_counts = {}
    for f in findings:
        status = f.get("final_status", "Unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    df = pd.DataFrame(
        {"Status": list(status_counts.keys()), "Count": list(status_counts.values())}
    )
    df = df.set_index("Status")
    st.bar_chart(df, **{"color": "#4A90D9"} if _ST_SUPPORTS_BAR_COLOR else {})


def _render_severity_chart(findings: List[Dict]):
    """Bar chart showing severity breakdown."""
    st.markdown("**Severity Breakdown**")

    severity_map = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
    severity_counts = {"CAT I": 0, "CAT II": 0, "CAT III": 0}

    for f in findings:
        raw_sev = f.get("severity", "medium")
        category = severity_map.get(raw_sev, raw_sev)
        if category in severity_counts:
            severity_counts[category] += 1

    df = pd.DataFrame(
        {"Severity": list(severity_counts.keys()), "Count": list(severity_counts.values())}
    )
    df = df.set_index("Severity")
    st.bar_chart(df, **{"color": "#E74C3C"} if _ST_SUPPORTS_BAR_COLOR else {})


def _render_tool_accuracy_chart(findings: List[Dict]):
    """Show tool agreement vs disagreement rates."""
    st.markdown("**Finding Sources**")

    source_counts = {}
    for f in findings:
        source = f.get("source", "unknown")
        # Clean up source labels for display
        label = source.replace("_", " ").title()
        source_counts[label] = source_counts.get(label, 0) + 1

    df = pd.DataFrame(
        {"Source": list(source_counts.keys()), "Count": list(source_counts.values())}
    )
    df = df.set_index("Source")
    st.bar_chart(df, **{"color": "#27AE60"} if _ST_SUPPORTS_BAR_COLOR else {})
