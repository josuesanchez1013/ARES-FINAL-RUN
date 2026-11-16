"""
Comparison Script - ARES STIG Reconciliation

Deterministic status comparison script that categorizes findings from:
- Tool 1 findings (from parser)
- Tool 2 findings (from parser)
- Gap Coverage validated findings

Outputs:
- Agreements: All sources agree on status
- Disagreements: Any source contradicts another

This is a PYTHON SCRIPT, not a Genesis agent. Logic is deterministic and fast.

Usage:
    from genesis_integration.comparison_script import compare_findings

    result = compare_findings(
        tool1_findings=parser_output['tool1_findings'],
        tool2_findings=parser_output['tool2_findings'],
        gap_coverage_findings=gap_coverage_output
    )
"""

from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

SEVERITY_PRIORITY = {"high": 1, "CAT I": 1, "medium": 2, "CAT II": 2, "low": 3, "CAT III": 3}

CANONICAL_STATUSES = {
    "open": "Open",
    "notafinding": "NotAFinding",
    "not_a_finding": "NotAFinding",
    "notapplicable": "Not_Applicable",
    "not_applicable": "Not_Applicable",
    "notreviewed": "Not_Reviewed",
    "not_reviewed": "Not_Reviewed",
}


def normalize_status(status: str) -> str:
    """
    Normalize status strings to consistent format for comparison.

    Handles variations like:
    - "Not_Reviewed" vs "NotReviewed" vs "Not Reviewed" vs "not_reviewed"
    - "Open" vs "open" vs "OPEN"
    - "NotAFinding" vs "Not_A_Finding" vs "notafinding"
    """
    if not status:
        return "Not_Reviewed"

    cleaned = status.strip().lower().replace(" ", "_").replace("-", "_")

    if cleaned in CANONICAL_STATUSES:
        return CANONICAL_STATUSES[cleaned]

    # Remove all separators for fuzzy match
    squished = cleaned.replace("_", "")
    for key, canonical in CANONICAL_STATUSES.items():
        if key.replace("_", "") == squished:
            return canonical

    # If nothing matches, return original with first letter capitalized
    return status.strip().capitalize()


def compare_findings(
    tool1_findings: List[Dict[str, Any]],
    tool2_findings: List[Dict[str, Any]],
    gap_coverage_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Compare findings from multiple sources and categorize into agreements/disagreements.

    Handles all disagreement types per architecture:
    - Tool1 vs Tool2
    - Tool1 vs Gap Coverage
    - Tool2 vs Gap Coverage
    - 3-way conflicts

    Args:
        tool1_findings: Normalized findings from Tool 1 (e.g., PreSTIGe)
        tool2_findings: Normalized findings from Tool 2 (e.g., evaluate-STIG)
        gap_coverage_findings: Validated findings from Gap Coverage Agent (optional)

    Returns:
        {
            "agreements": List[Dict],
            "disagreements": List[Dict],
            "summary": {
                "total_compared": int,
                "agreements": int,
                "disagreements": int,
                "gap_coverage_applied": int
            }
        }
    """
    logger.info("Starting comparison of findings...")

    tool1_map = {f["vuln_id"]: f for f in tool1_findings if "vuln_id" in f}
    tool2_map = {f["vuln_id"]: f for f in tool2_findings if "vuln_id" in f}

    # Build gap coverage map
    gap_map: Dict[str, Dict] = {}
    if gap_coverage_findings:
        for f in gap_coverage_findings:
            if "vuln_id" in f:
                gap_map[f["vuln_id"]] = f

    # All vuln_ids across all sources
    all_ids = set(tool1_map.keys()) | set(tool2_map.keys()) | set(gap_map.keys())
    # Only compare where at least two sources have a non-Not_Reviewed verdict
    common_ids = set(tool1_map.keys()) & set(tool2_map.keys())

    agreements = []
    disagreements = []

    for vuln_id in sorted(common_ids):
        tool1_finding = tool1_map[vuln_id]
        tool2_finding = tool2_map[vuln_id]
        gap_finding = gap_map.get(vuln_id)

        tool1_status = normalize_status(tool1_finding.get("status", ""))
        tool2_status = normalize_status(tool2_finding.get("status", ""))

        # Skip items where both are Not_Reviewed (gaps, not comparisons)
        if tool1_status == "Not_Reviewed" and tool2_status == "Not_Reviewed":
            continue

        severity = tool1_finding.get("severity", tool2_finding.get("severity", "medium"))

        # Collect all verdicts for this rule
        verdicts = {"tool1": tool1_status, "tool2": tool2_status}
        if gap_finding:
            gap_status = normalize_status(gap_finding.get("status", ""))
            if gap_status != "Not_Reviewed":
                verdicts["gap_coverage"] = gap_status

        # Determine agreement vs disagreement
        active_verdicts = {
            k: v for k, v in verdicts.items() if v != "Not_Reviewed"
        }
        unique_statuses = set(active_verdicts.values())

        if len(unique_statuses) <= 1:
            agreements.append({
                "vuln_id": vuln_id,
                "rule_id": tool1_finding.get("rule_id", tool2_finding.get("rule_id")),
                "severity": severity,
                "status": unique_statuses.pop() if unique_statuses else tool1_status,
                "source": _agreement_source(active_verdicts),
                "tool1_status": tool1_status,
                "tool2_status": tool2_status,
                "gap_coverage_status": verdicts.get("gap_coverage"),
            })
        else:
            disagreements.append({
                "vuln_id": vuln_id,
                "rule_id": tool1_finding.get("rule_id", tool2_finding.get("rule_id")),
                "severity": severity,
                "tool1_status": tool1_status,
                "tool2_status": tool2_status,
                "gap_coverage_status": verdicts.get("gap_coverage"),
                "conflict_type": _classify_conflict(verdicts),
                "tool1_finding": tool1_finding,
                "tool2_finding": tool2_finding,
                "gap_finding": gap_finding,
            })

    # Sort disagreements by severity (CAT I first)
    disagreements = sort_by_severity(disagreements)

    summary = {
        "total_compared": len(agreements) + len(disagreements),
        "agreements": len(agreements),
        "disagreements": len(disagreements),
        "gap_coverage_applied": len(gap_map),
    }

    logger.info(f"Comparison complete: {summary}")

    return {
        "agreements": agreements,
        "disagreements": disagreements,
        "summary": summary,
    }


def _agreement_source(active_verdicts: Dict[str, str]) -> str:
    """Describe which sources agreed."""
    sources = sorted(active_verdicts.keys())
    if len(sources) >= 3:
        return "all_sources_agree"
    elif len(sources) == 2:
        return f"{sources[0]}_and_{sources[1]}_agree"
    elif len(sources) == 1:
        return f"{sources[0]}_only"
    return "unknown"


def _classify_conflict(verdicts: Dict[str, str]) -> str:
    """Classify the type of disagreement."""
    active = {k: v for k, v in verdicts.items() if v != "Not_Reviewed"}
    sources = sorted(active.keys())
    unique = set(active.values())

    if len(unique) >= 3:
        return "three_way_conflict"
    if "gap_coverage" in sources:
        non_gap = [k for k in sources if k != "gap_coverage"]
        # Check which tools disagree with gap coverage
        gap_status = active.get("gap_coverage")
        disagreeing = [k for k in non_gap if active[k] != gap_status]
        if len(disagreeing) == 2:
            return "both_tools_vs_gap_coverage"
        elif disagreeing:
            return f"{disagreeing[0]}_vs_gap_coverage"
    return "tool1_vs_tool2"


def merge_gap_coverage_findings(
    tool1_findings: List[Dict],
    tool2_findings: List[Dict],
    gap_coverage_findings: List[Dict],
) -> Dict[str, Any]:
    """
    Merge gap coverage validated findings into tool findings.

    For rules where a tool had "Not_Reviewed", replace with the gap coverage
    agent's validated status.

    Returns:
        {
            "tool1_findings_updated": List[Dict],
            "tool2_findings_updated": List[Dict],
            "gap_coverage_applied": int
        }
    """
    gap_map = {f["vuln_id"]: f for f in gap_coverage_findings}
    applied = 0

    tool1_updated = []
    for finding in tool1_findings:
        updated = dict(finding)
        if normalize_status(finding.get("status", "")) == "Not_Reviewed":
            gap = gap_map.get(finding["vuln_id"])
            if gap:
                updated["status"] = gap["status"]
                updated["validated_by"] = "gap_coverage_agent"
                updated["confidence_score"] = gap.get("confidence_score")
                applied += 1
        tool1_updated.append(updated)

    tool2_updated = []
    for finding in tool2_findings:
        updated = dict(finding)
        if normalize_status(finding.get("status", "")) == "Not_Reviewed":
            gap = gap_map.get(finding["vuln_id"])
            if gap:
                updated["status"] = gap["status"]
                updated["validated_by"] = "gap_coverage_agent"
                updated["confidence_score"] = gap.get("confidence_score")
                applied += 1
        tool2_updated.append(updated)

    return {
        "tool1_findings_updated": tool1_updated,
        "tool2_findings_updated": tool2_updated,
        "gap_coverage_applied": applied,
    }


def sort_by_severity(findings: List[Dict]) -> List[Dict]:
    """Sort findings by severity: CAT I / high > CAT II / medium > CAT III / low."""
    def _key(f):
        sev = f.get("severity", "medium")
        priority = SEVERITY_PRIORITY.get(sev, 99)
        return (priority, f.get("vuln_id", ""))

    return sorted(findings, key=_key)


def categorize_findings_by_severity(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Group findings by severity level for reporting."""
    result: Dict[str, List[Dict]] = {"CAT I": [], "CAT II": [], "CAT III": []}

    severity_map = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}

    for finding in findings:
        raw = finding.get("severity", "medium")
        category = severity_map.get(raw, raw)
        if category in result:
            result[category].append(finding)
        else:
            result.setdefault(category, []).append(finding)

    return result


if __name__ == "__main__":
    import json
    from pathlib import Path

    example_path = Path(__file__).parent.parent / "mcp_server" / "example_parser_output.json"

    if example_path.exists():
        with open(example_path) as f:
            parser_output = json.load(f)

        result = compare_findings(
            tool1_findings=parser_output["tool1_findings"],
            tool2_findings=parser_output["tool2_findings"],
        )

        print(json.dumps(result, indent=2))
    else:
        print(f"Example file not found: {example_path}")
