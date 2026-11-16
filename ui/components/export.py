"""
Export Component

Generates downloadable files from the final reconciled findings:
- CSV: All findings with ARES verdicts, confidence, evidence
- JSON: Full structured report with all pipeline outputs
- CKL (stretch): STIG Viewer-compatible XML
"""

import csv
import json
import io
from datetime import datetime
from typing import Dict, List

import streamlit as st


def render_export():
    """Render export buttons and generate downloadable files."""
    report = st.session_state.get("final_report")
    if not report:
        return

    st.subheader("Export Results")

    findings = report.get("reconciled_findings", [])
    decisions = st.session_state.get("review_decisions", {})

    col1, col2, col3 = st.columns(3)

    with col1:
        csv_bytes = _generate_csv(findings, decisions)
        st.download_button(
            label="Download CSV",
            data=csv_bytes,
            file_name=f"ares_reconciled_{_timestamp()}.csv",
            mime="text/csv",
            type="primary",
        )
        st.caption("All findings with ARES verdicts and confidence scores")

    with col2:
        json_bytes = _generate_json(report, decisions)
        st.download_button(
            label="Download JSON Report",
            data=json_bytes,
            file_name=f"ares_report_{_timestamp()}.json",
            mime="application/json",
        )
        st.caption("Full structured report with metrics and recommendations")

    with col3:
        ckl_bytes = _generate_ckl(findings, decisions)
        st.download_button(
            label="Download CKL",
            data=ckl_bytes,
            file_name=f"ares_reconciled_{_timestamp()}.ckl",
            mime="application/xml",
        )
        st.caption("STIG Viewer-compatible checklist XML")


def _generate_csv(findings: List[Dict], decisions: Dict) -> bytes:
    """Generate a CSV file from reconciled findings."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Vuln_ID",
        "Rule_ID",
        "Severity",
        "ARES_Verdict",
        "Tool1_Status",
        "Tool2_Status",
        "Confidence",
        "Source",
        "Human_Decision",
    ])

    for f in findings:
        vuln_id = f.get("vuln_id", "")
        decision = decisions.get(vuln_id, "")

        # Apply override to final status
        final_status = f.get("final_status", "")
        if decision.startswith("overridden:"):
            _, _, final_status = decision.partition(":")

        writer.writerow([
            vuln_id,
            f.get("rule_id", ""),
            f.get("severity", ""),
            final_status,
            f.get("tool1_status", ""),
            f.get("tool2_status", ""),
            f.get("confidence_score", ""),
            f.get("source", ""),
            decision,
        ])

    return output.getvalue().encode("utf-8")


def _generate_json(report: Dict, decisions: Dict) -> bytes:
    """Generate full JSON report including human decisions."""
    export = {
        "export_metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool": "ARES - Automated Reconciliation and Evidence for STIGs",
            "version": "1.0.0",
        },
        "metrics": report.get("metrics", {}),
        "reconciled_findings": _apply_decisions(report.get("reconciled_findings", []), decisions),
        "review_decisions": decisions,
        "recommendations": report.get("recommendations", []),
    }
    return json.dumps(export, indent=2).encode("utf-8")


def _generate_ckl(findings: List[Dict], decisions: Dict) -> bytes:
    """Generate a STIG Viewer-compatible CKL XML file."""
    findings_with_decisions = _apply_decisions(findings, decisions)

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<CHECKLIST>",
        "  <ASSET>",
        "    <ROLE>None</ROLE>",
        "    <ASSET_TYPE>Computing</ASSET_TYPE>",
        "    <HOST_NAME>rhel8-stig-lab</HOST_NAME>",
        "    <HOST_IP>10.0.2.15</HOST_IP>",
        "    <MARKING>CUI</MARKING>",
        "  </ASSET>",
        "  <STIGS>",
        "    <iSTIG>",
        "      <STIG_INFO>",
        '        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>RHEL 8 STIG</SID_DATA></SI_DATA>',
        '        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>V2R7</SID_DATA></SI_DATA>',
        f'        <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>ARES Reconciled {_timestamp()}</SID_DATA></SI_DATA>',
        "      </STIG_INFO>",
    ]

    for f in findings_with_decisions:
        vuln_id = f.get("vuln_id", "")
        rule_id = f.get("rule_id", "")
        severity = _ckl_severity(f.get("severity", "medium"))
        status = _ckl_status(f.get("final_status", "Not_Reviewed"))
        confidence = f.get("confidence_score", "")
        source = f.get("source", "")

        comment = f"ARES reconciled (source: {source}, confidence: {confidence}%)"
        decision = decisions.get(vuln_id, "")
        if decision:
            comment += f" | Human decision: {decision}"

        lines.extend([
            "      <VULN>",
            "        <STIG_DATA>",
            "          <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>",
            f"          <ATTRIBUTE_DATA>{_xml_escape(vuln_id)}</ATTRIBUTE_DATA>",
            "        </STIG_DATA>",
            "        <STIG_DATA>",
            "          <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>",
            f"          <ATTRIBUTE_DATA>{_xml_escape(rule_id)}</ATTRIBUTE_DATA>",
            "        </STIG_DATA>",
            "        <STIG_DATA>",
            "          <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>",
            f"          <ATTRIBUTE_DATA>{severity}</ATTRIBUTE_DATA>",
            "        </STIG_DATA>",
            f"        <STATUS>{status}</STATUS>",
            f"        <FINDING_DETAILS>ARES validated via CLI execution</FINDING_DETAILS>",
            f"        <COMMENTS>{_xml_escape(comment)}</COMMENTS>",
            "      </VULN>",
        ])

    lines.extend([
        "    </iSTIG>",
        "  </STIGS>",
        "</CHECKLIST>",
    ])

    return "\n".join(lines).encode("utf-8")


def _apply_decisions(findings: List[Dict], decisions: Dict) -> List[Dict]:
    """Return findings with human override decisions applied."""
    result = []
    for f in findings:
        updated = dict(f)
        vuln_id = f.get("vuln_id", "")
        decision = decisions.get(vuln_id, "")
        if decision.startswith("overridden:"):
            _, _, override_value = decision.partition(":")
            updated["final_status"] = override_value
            updated["human_override"] = True
        elif decision.startswith("approved:"):
            updated["human_override"] = False
        result.append(updated)
    return result


def _ckl_severity(severity: str) -> str:
    """Map severity to CKL format."""
    mapping = {"high": "high", "medium": "medium", "low": "low", "CAT I": "high", "CAT II": "medium", "CAT III": "low"}
    return mapping.get(severity, "medium")


def _ckl_status(status: str) -> str:
    """Map ARES status to CKL STATUS values."""
    mapping = {
        "Open": "Open",
        "NotAFinding": "NotAFinding",
        "Not_Applicable": "Not_Applicable",
        "Not_Reviewed": "Not_Reviewed",
    }
    return mapping.get(status, "Not_Reviewed")


def _xml_escape(text: str) -> str:
    """Escape special XML characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _timestamp() -> str:
    """Generate timestamp for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")
