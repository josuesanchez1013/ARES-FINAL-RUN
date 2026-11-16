"""
Human Review Queue Component

Displays findings with confidence < 80% (or CAT I < 90%) that require
human approval or override before final export.

Reviewers can:
- Approve the ARES verdict
- Override with a different status
- Skip (leave in queue for later)

Decisions are stored in st.session_state.review_decisions and reflected in exports.
"""

import streamlit as st
from typing import List, Dict


def render_review_queue():
    """
    Render the human review queue.

    Reads from st.session_state.review_queue and writes decisions
    to st.session_state.review_decisions.
    """
    queue = st.session_state.get("review_queue", [])
    decisions = st.session_state.get("review_decisions", {})

    if not queue:
        st.success("No findings require human review. All verdicts are high confidence.")
        return

    # Progress header
    reviewed_count = sum(1 for item in queue if item.get("vuln_id") in decisions)
    total_count = len(queue)

    st.subheader(f"Human Review Queue ({reviewed_count}/{total_count} reviewed)")
    st.progress(reviewed_count / total_count if total_count > 0 else 0)
    st.caption(
        "These findings have confidence below threshold and require human verification. "
        "CAT I findings require > 90% confidence; all others require > 80%."
    )

    st.divider()

    # Render each item in the queue
    for i, item in enumerate(queue):
        _render_review_item(item, i, decisions)


def _render_review_item(item: Dict, index: int, decisions: Dict):
    """Render a single review queue item with action buttons."""
    vuln_id = item.get("vuln_id", "Unknown")
    severity = item.get("severity", "medium")
    ares_verdict = item.get("ares_verdict", "Unknown")
    confidence = item.get("confidence_score", 0)
    tool1_status = item.get("tool1_status", "—")
    tool2_status = item.get("tool2_status", "—")
    evidence = item.get("evidence", "")
    reason = item.get("reason", "")

    # Check if already reviewed
    existing_decision = decisions.get(vuln_id)
    if existing_decision:
        decision_icon = "✅" if existing_decision.startswith("approved:") else "\U0001f504"
        header_suffix = f" — {decision_icon} {existing_decision}"
    else:
        header_suffix = ""

    severity_label = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}.get(severity, severity)

    with st.container(border=True):
        # Header
        col_id, col_sev, col_conf = st.columns([2, 1, 1])
        with col_id:
            st.markdown(f"### {vuln_id}{header_suffix}")
        with col_sev:
            if severity == "high":
                st.error(severity_label)
            elif severity == "medium":
                st.warning(severity_label)
            else:
                st.info(severity_label)
        with col_conf:
            st.metric("Confidence", f"{confidence}%")

        # Verdict comparison
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"**Tool 1:** {tool1_status}")
        with col2:
            st.markdown(f"**Tool 2:** {tool2_status}")
        with col3:
            st.markdown(f"**ARES Verdict:** `{ares_verdict}`")

        # Reason for flagging
        if reason:
            st.caption(f"Flagged because: {reason}")

        # Evidence
        if evidence:
            with st.expander("View Evidence"):
                st.markdown(evidence)

                # Show CLI commands if available
                commands = item.get("commands_executed", [])
                outputs = item.get("command_outputs", [])
                if commands:
                    st.markdown("**Commands Executed:**")
                    for j, cmd in enumerate(commands):
                        st.code(f"$ {cmd}", language="bash")
                        if j < len(outputs) and outputs[j]:
                            st.code(outputs[j], language="text")

        # Action buttons
        if not existing_decision:
            col_approve, col_override, col_skip = st.columns(3)

            with col_approve:
                if st.button(
                    f"Approve ({ares_verdict})",
                    key=f"approve_{vuln_id}_{index}",
                    type="primary",
                ):
                    st.session_state.review_decisions[vuln_id] = f"approved:{ares_verdict}"
                    st.rerun()

            with col_override:
                override_options = ["Open", "NotAFinding", "Not_Applicable"]
                # Remove the current ARES verdict from override options
                override_options = [o for o in override_options if o != ares_verdict]
                override_choice = st.selectbox(
                    "Override to:",
                    override_options,
                    key=f"override_select_{vuln_id}_{index}",
                    label_visibility="collapsed",
                )
                if st.button(
                    f"Override → {override_choice}",
                    key=f"override_{vuln_id}_{index}",
                ):
                    st.session_state.review_decisions[vuln_id] = f"overridden:{override_choice}"
                    st.rerun()

            with col_skip:
                if st.button("Skip", key=f"skip_{vuln_id}_{index}"):
                    st.toast(f"Skipped {vuln_id} — still in queue.")
        else:
            # Show undo option
            if st.button("Undo Decision", key=f"undo_{vuln_id}_{index}"):
                del st.session_state.review_decisions[vuln_id]
                st.rerun()
