"""
Findings: one normalised record per rule, built from the step outputs.

The pipeline produces results in two shapes. Mock mode returns a report that
already holds `reconciled_findings`; production returns CKL metadata only and
the per-rule results live in the earlier step outputs (agreements, gap
results, determinations). Everything the UI and the exports show goes through
`build_findings`, so both shapes behave the same.
"""

import re
from typing import Any, Dict, List, Optional

CAT_I_REVIEW_THRESHOLD = 90
DEFAULT_REVIEW_THRESHOLD = 80

STATUSES = ["Open", "NotAFinding", "Not_Applicable", "Not_Reviewed"]
SEVERITIES = ["high", "medium", "low"]

_STATUS_ALIASES = {"open": "Open", "notafinding": "NotAFinding",
                   "notapplicable": "Not_Applicable", "na": "Not_Applicable",
                   "notreviewed": "Not_Reviewed"}
_SEVERITY_ALIASES = {"high": "high", "cati": "high", "i": "high",
                     "medium": "medium", "catii": "medium", "ii": "medium",
                     "low": "low", "catiii": "low", "iii": "low"}


def _squish(value: Any) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def norm_status(value: Any) -> Optional[str]:
    if value is None or str(value).strip() == "":
        return None
    return _STATUS_ALIASES.get(_squish(value), str(value).strip())


def norm_severity(value: Any) -> str:
    return _SEVERITY_ALIASES.get(_squish(value), "medium")


def _confidence(item: Dict, default: float = 0) -> float:
    for key in ("confidence_score", "confidence"):
        if isinstance(item.get(key), (int, float)):
            return item[key]
    return default


def _vid(item: Dict) -> str:
    return str(item.get("vuln_id") or item.get("group_id") or "")


def _index(items: Any) -> Dict[str, Dict]:
    if not isinstance(items, list):
        return {}
    return {_vid(i): i for i in items if isinstance(i, dict) and _vid(i)}


def _scanner(item: Optional[Dict]) -> Optional[Dict]:
    if not item:
        return None
    return {"status": norm_status(item.get("status")),
            "finding_details": item.get("finding_details") or "",
            "comments": item.get("comments") or ""}


def build_findings(outputs: Dict[str, Any]) -> List[Dict]:
    report = outputs.get("final_report") or {}
    parser = outputs.get("parser_output") or {}
    comparison = outputs.get("comparison_output") or {}
    tool1 = _index(parser.get("tool1_findings"))
    tool2 = _index(parser.get("tool2_findings"))
    gaps = _index(outputs.get("gap_coverage_results"))
    determinations = _index(outputs.get("determination_output"))
    disagreements = _index(comparison.get("disagreements"))
    # The orchestrator enriches gap and disagreement records with STIG data
    # (title, severity) while it works; prefer that over the scanner's copy.
    gap_rules = _index(outputs.get("identified_gaps"))

    def base(vuln_id: str, item: Dict) -> Dict:
        scan = tool1.get(vuln_id) or tool2.get(vuln_id) or {}
        dis = disagreements.get(vuln_id, {})
        stig = dis if dis.get("stig_title") else gap_rules.get(vuln_id, {})
        return {
            "vuln_id": vuln_id,
            "rule_id": item.get("rule_id") or scan.get("rule_id") or "",
            "severity": norm_severity(item.get("severity") or dis.get("severity")
                                      or stig.get("severity") or scan.get("severity")),
            "tool1_status": norm_status(item.get("tool1_status") or dis.get("tool1_status")
                                        or tool1.get(vuln_id, {}).get("status")),
            "tool2_status": norm_status(item.get("tool2_status") or dis.get("tool2_status")
                                        or tool2.get(vuln_id, {}).get("status")),
            "rule_title": item.get("rule_title") or item.get("stig_title")
            or stig.get("stig_title") or scan.get("rule_title") or scan.get("title") or "",
            "evidence": "", "commands_executed": [], "command_outputs": [],
            "requires_human_review": False, "error": "", "secondary_opinion": None,
            "conflict_type": dis.get("conflict_type") or "",
            "scanner": {"tool1": _scanner(tool1.get(vuln_id)),
                        "tool2": _scanner(tool2.get(vuln_id))},
        }

    def agent_detail(item: Dict) -> Dict:
        return {
            "evidence": item.get("evidence") or item.get("finding_details") or "",
            "commands_executed": item.get("commands_executed") or [],
            "command_outputs": item.get("command_outputs") or [],
            "requires_human_review": bool(item.get("requires_human_review")),
            "error": item.get("error") or "",
            "secondary_opinion": item.get("secondary_opinion"),
        }

    by_id: Dict[str, Dict] = {}
    reconciled = report.get("reconciled_findings")
    if isinstance(reconciled, list) and reconciled:
        for item in reconciled:
            vuln_id = _vid(item)
            if not vuln_id:
                continue
            finding = base(vuln_id, item)
            finding["tool1_status"] = norm_status(item.get("tool1_status"))
            finding["tool2_status"] = norm_status(item.get("tool2_status"))
            detail = determinations.get(vuln_id) or gaps.get(vuln_id)
            if detail:
                finding.update(agent_detail(detail))
            finding.update(final_status=norm_status(item.get("final_status")) or "Not_Reviewed",
                           source=item.get("source") or "unknown",
                           confidence_score=_confidence(item, 0))
            by_id[vuln_id] = finding
        return list(by_id.values())

    # Production. Later sources win when a rule appears more than once: a
    # resolved disagreement overrides a gap result, which overrides an agreement.
    for item in comparison.get("agreements") or []:
        vuln_id = _vid(item)
        if not vuln_id:
            continue
        finding = base(vuln_id, item)
        status = norm_status(item.get("final_status") or item.get("status"))
        finding.update(final_status=status or "Not_Reviewed", source="agreement",
                       confidence_score=100,
                       evidence=f"Both tools reported {status}." if status else "")
        by_id[vuln_id] = finding
    for source, items in (("gap_coverage_agent", gaps), ("determination_agent", determinations)):
        for vuln_id, item in items.items():
            finding = base(vuln_id, item)
            finding.update(agent_detail(item))
            finding.update(
                final_status=norm_status(item.get("ares_verdict") or item.get("status"))
                or "Not_Reviewed",
                source=item.get("validation_source") or source,
                confidence_score=_confidence(item, 0))
            by_id[vuln_id] = finding
    return list(by_id.values())


# ---------------------------------------------------------------------------
# Decisions and review
# ---------------------------------------------------------------------------

def effective_status(finding: Dict, decisions: Dict) -> str:
    decision = decisions.get(finding["vuln_id"])
    if decision and decision.get("action") == "overridden":
        return decision["status"]
    return finding["final_status"]


def legacy_decisions(decisions: Dict) -> Dict[str, str]:
    """Decisions in the 'approved:Open' / 'overridden:NotAFinding' form the exports use."""
    return {vuln_id: f"{d['action']}:{d['status']}" for vuln_id, d in decisions.items()
            if d.get("action") in ("approved", "overridden")}


def is_decided(vuln_id: str, decisions: Dict) -> bool:
    return decisions.get(vuln_id, {}).get("action") in ("approved", "overridden")


def review_reason(finding: Dict) -> Optional[str]:
    if finding["source"] == "agreement":
        return None
    confidence = finding["confidence_score"]
    if finding["error"]:
        return "The agent could not validate this rule"
    if finding["final_status"] == "Not_Reviewed":
        return "No verdict was reached"
    if finding["severity"] == "high" and confidence < CAT_I_REVIEW_THRESHOLD:
        return f"CAT I finding with confidence below {CAT_I_REVIEW_THRESHOLD}%"
    if confidence < DEFAULT_REVIEW_THRESHOLD:
        return f"Confidence below {DEFAULT_REVIEW_THRESHOLD}%"
    if finding["requires_human_review"]:
        return "The agent asked for a human check"
    return None


def build_review(findings: List[Dict], outputs: Dict, decisions: Dict) -> Dict[str, Any]:
    """Required items need a decision; optional items are other agent verdicts."""
    report = outputs.get("final_report") or {}
    provided = {_vid(i): i for i in (report.get("review_queue")
                                     or report.get("human_review_queue") or []) if _vid(i)}
    required, optional = [], []
    for finding in findings:
        reason = provided.get(finding["vuln_id"], {}).get("reason") or (
            None if provided else review_reason(finding))
        if finding["vuln_id"] in provided and not reason:
            reason = "Flagged by the reporting step"
        card = dict(finding, reason=reason, decision=decisions.get(finding["vuln_id"]))
        if reason:
            required.append(card)
        elif finding["source"] != "agreement":
            optional.append(card)

    # Undecided first, skipped after untouched, decided last
    def rank(card: Dict) -> int:
        action = (card["decision"] or {}).get("action")
        return {None: 0, "skipped": 1}.get(action, 2)
    required.sort(key=rank)
    pending = sum(1 for c in required if not is_decided(c["vuln_id"], decisions))
    return {"required": required, "optional": optional, "pending": pending}


# ---------------------------------------------------------------------------
# Summary and query
# ---------------------------------------------------------------------------

def build_summary(findings: List[Dict], review: Dict, decisions: Dict) -> Dict[str, Any]:
    statuses = [effective_status(f, decisions) for f in findings]
    by_severity = {sev: {s: 0 for s in STATUSES} for sev in SEVERITIES}
    by_source: Dict[str, int] = {}
    for finding, status in zip(findings, statuses):
        row = by_severity[finding["severity"]]
        row[status if status in row else "Not_Reviewed"] += 1
        by_source[finding["source"]] = by_source.get(finding["source"], 0) + 1
    return {
        "total": len(findings),
        "by_status": {s: statuses.count(s) for s in STATUSES},
        "by_severity": by_severity,
        "by_source": by_source,
        "agreements": by_source.get("agreement", 0),
        "disagreements_resolved": sum(v for k, v in by_source.items() if k.startswith("determination")),
        "gaps_validated": sum(v for k, v in by_source.items() if k.startswith("gap_coverage")),
        "review_required": len(review["required"]),
        "review_pending": review["pending"],
    }


def _natural(text: str) -> List[Any]:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", text)]


_SORT_KEYS = {
    "vuln_id": lambda f: _natural(f["vuln_id"]),
    "severity": lambda f: SEVERITIES.index(f["severity"]),
    "status": lambda f: STATUSES.index(f["status"]) if f["status"] in STATUSES else 99,
    "confidence": lambda f: f["confidence_score"],
    "source": lambda f: f["source"],
}


def query_findings(findings: List[Dict], decisions: Dict, q: str = "", severity: str = "",
                   status: str = "", source: str = "", sort: str = "", direction: str = "asc",
                   page: int = 1, page_size: int = 50) -> Dict[str, Any]:
    rows = []
    for finding in findings:
        decision = decisions.get(finding["vuln_id"])
        rows.append({
            "vuln_id": finding["vuln_id"], "rule_id": finding["rule_id"],
            "rule_title": finding["rule_title"], "severity": finding["severity"],
            "status": effective_status(finding, decisions),
            "ares_status": finding["final_status"],
            "tool1_status": finding["tool1_status"], "tool2_status": finding["tool2_status"],
            "confidence_score": finding["confidence_score"], "source": finding["source"],
            "decision": decision,
        })
    needle = q.strip().lower()
    if needle:
        rows = [r for r in rows if needle in r["vuln_id"].lower()
                or needle in r["rule_id"].lower() or needle in r["rule_title"].lower()]
    if severity:
        rows = [r for r in rows if r["severity"] == severity]
    if status:
        rows = [r for r in rows if r["status"] == status]
    if source:
        rows = [r for r in rows if r["source"] == source]

    if sort in _SORT_KEYS:
        rows.sort(key=_SORT_KEYS["vuln_id"])
        rows.sort(key=_SORT_KEYS[sort], reverse=direction == "desc")
    else:
        # Default: scored rows first, unscored (Not reviewed) after; then
        # severity, then rule number.
        rows.sort(key=lambda r: (r["status"] == "Not_Reviewed",
                                 SEVERITIES.index(r["severity"]), _natural(r["vuln_id"])))
    total = len(rows)
    page_size = max(1, min(page_size, 500))
    page = max(1, page)
    start = (page - 1) * page_size
    return {"total": total, "page": page, "page_size": page_size,
            "rows": rows[start:start + page_size]}
