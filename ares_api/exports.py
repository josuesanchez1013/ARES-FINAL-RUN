"""
Exports, built only when requested.

CSV, JSON and CKL keep the layout of the Streamlit export component
(ui/components/export.py) so downstream consumers see the same files. CKLB is
the STIG Viewer 3 JSON checklist.
"""

import csv
import io
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from xml.sax.saxutils import escape

from . import config
from .findings import effective_status, legacy_decisions

_CKL_STATUS = {"Open": "Open", "NotAFinding": "NotAFinding",
               "Not_Applicable": "Not_Applicable", "Not_Reviewed": "Not_Reviewed"}
_CKLB_STATUS = {"Open": "open", "NotAFinding": "not_a_finding",
                "Not_Applicable": "not_applicable", "Not_Reviewed": "not_reviewed"}

MEDIA_TYPES = {"csv": "text/csv", "json": "application/json",
               "ckl": "application/xml", "cklb": "application/json"}


def _xml(text) -> str:
    return escape(str(text or ""), {'"': "&quot;", "'": "&apos;"})


def _comment(finding: Dict, legacy: Dict[str, str]) -> str:
    comment = (f"ARES reconciled (source: {finding['source']}, "
               f"confidence: {finding['confidence_score']}%)")
    decision = legacy.get(finding["vuln_id"])
    if decision:
        comment += f" | Human decision: {decision}"
    return comment


def _details(finding: Dict) -> str:
    return finding["evidence"] or "No finding details recorded"


def to_csv(findings: List[Dict], decisions: Dict) -> bytes:
    legacy = legacy_decisions(decisions)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Vuln_ID", "Rule_ID", "Severity", "ARES_Verdict", "Tool1_Status",
                     "Tool2_Status", "Confidence", "Source", "Human_Decision"])
    for f in findings:
        writer.writerow([f["vuln_id"], f["rule_id"], f["severity"],
                         effective_status(f, decisions), f["tool1_status"] or "",
                         f["tool2_status"] or "", f["confidence_score"], f["source"],
                         legacy.get(f["vuln_id"], "")])
    return out.getvalue().encode("utf-8")


def to_json(findings: List[Dict], decisions: Dict, summary: Dict, run_meta: Dict) -> bytes:
    legacy = legacy_decisions(decisions)
    rows = []
    for f in findings:
        row = {k: f[k] for k in ("vuln_id", "rule_id", "rule_title", "severity", "source",
                                 "confidence_score", "tool1_status", "tool2_status",
                                 "evidence", "commands_executed", "command_outputs")}
        row["final_status"] = effective_status(f, decisions)
        if f["vuln_id"] in legacy:
            row["human_override"] = legacy[f["vuln_id"]].startswith("overridden:")
        rows.append(row)
    export = {
        "export_metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool": "ARES - Automated Reconciliation and Evidence for STIGs",
            "version": "2.0.0",
            "run_id": run_meta["id"],
            "data_handling": run_meta.get("declaration"),
        },
        "metrics": summary,
        "reconciled_findings": rows,
        "review_decisions": legacy,
    }
    return json.dumps(export, indent=2).encode("utf-8")


def run_stig(run_meta: Optional[Dict] = None) -> Dict[str, str]:
    """The STIG a run was assessed against; the configured one for older runs."""
    chosen = (run_meta or {}).get("stig") or {}
    if chosen.get("entry_ids"):
        return {"title": chosen["title"], "version": chosen["version"],
                "stig_id": chosen.get("stig_id") or chosen["title"].replace(" ", "_")}
    stig = config.stig()
    return {"title": stig["title"], "version": stig["version"],
            "stig_id": stig["title"].replace(" ", "_")}


def run_target(run_meta: Optional[Dict] = None) -> Dict[str, str]:
    """The asset written into exports: the run's saved target, else the configured one."""
    chosen = (run_meta or {}).get("target") or {}
    if chosen.get("id") and chosen["id"] != "default":
        return {"host_name": chosen.get("name", ""), "host_ip": chosen.get("host", "")}
    return config.target()


def to_ckl(findings: List[Dict], decisions: Dict, run_meta: Optional[Dict] = None) -> bytes:
    legacy = legacy_decisions(decisions)
    target, stig = run_target(run_meta), run_stig(run_meta)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>', "<CHECKLIST>", "  <ASSET>",
        "    <ROLE>None</ROLE>", "    <ASSET_TYPE>Computing</ASSET_TYPE>",
        f"    <HOST_NAME>{_xml(target['host_name'])}</HOST_NAME>",
        f"    <HOST_IP>{_xml(target['host_ip'])}</HOST_IP>",
        "    <MARKING>CUI</MARKING>", "  </ASSET>", "  <STIGS>", "    <iSTIG>",
        "      <STIG_INFO>",
        f"        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>{_xml(stig['title'])}</SID_DATA></SI_DATA>",
        f"        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>{_xml(stig['version'])}</SID_DATA></SI_DATA>",
        f"        <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>ARES Reconciled {stamp}</SID_DATA></SI_DATA>",
        "      </STIG_INFO>",
    ]
    for f in findings:
        status = _CKL_STATUS.get(effective_status(f, decisions), "Not_Reviewed")
        lines.extend([
            "      <VULN>",
            "        <STIG_DATA>", "          <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>",
            f"          <ATTRIBUTE_DATA>{_xml(f['vuln_id'])}</ATTRIBUTE_DATA>", "        </STIG_DATA>",
            "        <STIG_DATA>", "          <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>",
            f"          <ATTRIBUTE_DATA>{_xml(f['rule_id'])}</ATTRIBUTE_DATA>", "        </STIG_DATA>",
            "        <STIG_DATA>", "          <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>",
            f"          <ATTRIBUTE_DATA>{_xml(f['severity'])}</ATTRIBUTE_DATA>", "        </STIG_DATA>",
            f"        <STATUS>{status}</STATUS>",
            f"        <FINDING_DETAILS>{_xml(_details(f))}</FINDING_DETAILS>",
            f"        <COMMENTS>{_xml(_comment(f, legacy))}</COMMENTS>",
            "      </VULN>",
        ])
    lines.extend(["    </iSTIG>", "  </STIGS>", "</CHECKLIST>"])
    return "\n".join(lines).encode("utf-8")


def to_cklb(findings: List[Dict], decisions: Dict, run_meta: Dict) -> bytes:
    legacy = legacy_decisions(decisions)
    target, stig = run_target(run_meta), run_stig(run_meta)
    stig_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ares:{run_meta['id']}"))
    rules = []
    for f in findings:
        rules.append({
            "uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ares:{run_meta['id']}:{f['vuln_id']}")),
            "stig_uuid": stig_uuid,
            "group_id": f["vuln_id"],
            "rule_id": f["rule_id"],
            "rule_title": f["rule_title"],
            "severity": f["severity"],
            "status": _CKLB_STATUS.get(effective_status(f, decisions), "not_reviewed"),
            "finding_details": _details(f),
            "comments": _comment(f, legacy),
            "overrides": {},
        })
    checklist = {
        "title": f"ARES reconciled checklist {run_meta['id']}",
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ares:checklist:{run_meta['id']}")),
        "cklb_version": "1.0",
        "active": False,
        "mode": 1,
        "has_path": False,
        "target_data": {"target_type": "Computing", "host_name": target["host_name"],
                        "ip_address": target["host_ip"], "mac_address": "", "fqdn": "",
                        "comments": "", "role": "None", "is_web_database": False,
                        "technology_area": "", "web_db_site": "", "web_db_instance": ""},
        "stigs": [{"stig_name": stig["title"], "display_name": stig["title"],
                   "stig_id": stig["stig_id"],
                   "release_info": f"ARES Reconciled {stig['version']}",
                   "version": stig["version"], "uuid": stig_uuid,
                   "reference_identifier": "", "size": len(rules), "rules": rules}],
    }
    return json.dumps(checklist, indent=2).encode("utf-8")
