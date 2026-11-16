"""
Comparison Script - ARES STIG Reconciliation (ENHANCED)

Uses data from session state and performs comprehensive comparison:
- Tool 1 findings (from parser_output in session state)
- Tool 2 findings (from parser_output in session state)  
- Gap Coverage validated findings (from gap_coverage_results in session state)

Outputs agreements and disagreements with full STIG context for determination agent.

Usage:
    from genesis_integration.comparison_script_enhanced import run_comparison
    
    result = run_comparison(parser_output, gap_coverage_results)
"""

from typing import List, Dict, Any, Optional, Tuple
import logging
import json
import os
import requests
import urllib3
from pathlib import Path

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# MCP Server Configuration
MCP_SERVER_URL = os.environ.get(
    'MCP_SERVER_URL',
    'https://mcp.example.internal'
)

# Project root for file paths
PROJECT_ROOT = Path(__file__).parent.parent

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


def load_parsed_findings_from_local() -> Tuple[List[Dict], List[Dict]]:
    """
    Load parsed findings from local data/output directory.
    These files were downloaded by the parser agent.
    
    Returns:
        (tool1_findings, tool2_findings)
    """
    output_dir = PROJECT_ROOT / "data" / "output"
    
    try:
        print(f"\n[LOAD] Loading parsed files from: {output_dir}")
        
        # Find the two most recent parsed JSON files
        parsed_files = list(output_dir.glob("*_parsed.json"))
        
        if len(parsed_files) < 2:
            raise ValueError(f"Expected 2 parsed files in {output_dir}, found {len(parsed_files)}")
        
        # Sort by modification time, take 2 most recent
        parsed_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        file1, file2 = parsed_files[0], parsed_files[1]
        
        print(f"[LOAD] Reading {file1.name}...")
        with open(file1, 'r') as f:
            data1 = json.load(f)
        
        print(f"[LOAD] Reading {file2.name}...")
        with open(file2, 'r') as f:
            data2 = json.load(f)
        
        # Extract findings from the parsed data structure
        tool1_findings = data1.get('findings', [])
        tool2_findings = data2.get('findings', [])
        
        print(f"[LOAD] ✅ Loaded {len(tool1_findings)} findings from {file1.name}")
        print(f"[LOAD] ✅ Loaded {len(tool2_findings)} findings from {file2.name}")
        
        logger.info(f"Loaded {len(tool1_findings)} findings from {file1.name}")
        logger.info(f"Loaded {len(tool2_findings)} findings from {file2.name}")
        
        return tool1_findings, tool2_findings
        
    except Exception as e:
        logger.error(f"Failed to load parsed files from local directory: {e}")
        print(f"\n[ERROR] Failed to load from local directory: {e}")
        print(f"[ERROR] Make sure parsed files exist in: {output_dir}")
        raise


def load_gap_coverage_results() -> List[Dict]:
    """
    Load gap coverage results from local JSON file.
    
    Returns:
        List of gap coverage validated findings
    """
    gap_file = PROJECT_ROOT / "data" / "output" / "gap_coverage_results.json"
    
    print(f"\n[LOAD] Loading gap coverage results from: {gap_file}")
    
    if not gap_file.exists():
        logger.warning(f"Gap coverage file not found: {gap_file}")
        print(f"[WARNING] Gap coverage file not found: {gap_file}")
        return []
    
    try:
        with open(gap_file, 'r') as f:
            gap_findings = json.load(f)
        
        print(f"[LOAD] ✅ Loaded {len(gap_findings)} gap coverage findings")
        logger.info(f"Loaded {len(gap_findings)} gap coverage findings from {gap_file.name}")
        return gap_findings
        
    except Exception as e:
        logger.error(f"Failed to load gap coverage results: {e}")
        print(f"[ERROR] Failed to load gap coverage results: {e}")
        return []


def load_stig_data() -> Dict[str, Dict]:
    """
    Load STIG data (Check Text, Discussion, etc.) for context.
    
    Returns:
        Dict mapping vuln_id to STIG data
    """
    from genesis_integration.stig_loader import get_stig_loader
    
    print(f"\n[LOAD] Loading STIG data for context...")
    
    try:
        stig_loader = get_stig_loader()
        all_vuln_ids = stig_loader.get_all_vuln_ids()
        
        stig_map = {}
        for vuln_id in all_vuln_ids:
            stig_data = stig_loader.get_rule_data(vuln_id)
            if stig_data:
                stig_map[vuln_id] = stig_data
        
        print(f"[LOAD] ✅ Loaded STIG data for {len(stig_map)} rules")
        logger.info(f"Loaded STIG data for {len(stig_map)} rules")
        return stig_map
        
    except Exception as e:
        logger.error(f"Failed to load STIG data: {e}")
        print(f"[ERROR] Failed to load STIG data: {e}")
        return {}


def normalize_status(status: str) -> str:
    """
    Normalize status strings to consistent format for comparison.
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


def run_comparison(parser_output: Dict[str, Any], gap_coverage_results: List[Dict]) -> Dict[str, Any]:
    """
    Main entry point: Use data from session state and run comparison.
    
    Args:
        parser_output: Parser agent output with tool1_findings and tool2_findings
        gap_coverage_results: List of gap coverage validated findings
    
    Returns comprehensive comparison with full context for determination agent.
    """
    print("\n" + "="*80)
    print("ARES COMPARISON SCRIPT")
    print("="*80)
    
    logger.info("Starting ARES Comparison workflow...")
    
    # Extract data from parameters (already in memory)
    tool1_findings = parser_output.get('tool1_findings', [])
    tool2_findings = parser_output.get('tool2_findings', [])
    gap_coverage_findings = gap_coverage_results
    
    print(f"[LOAD] ✅ Using {len(tool1_findings)} findings from Tool 1 (session state)")
    print(f"[LOAD] ✅ Using {len(tool2_findings)} findings from Tool 2 (session state)")
    print(f"[LOAD] ✅ Using {len(gap_coverage_findings)} gap coverage findings (session state)")
    
    # Load STIG data for context
    stig_map = load_stig_data()
    
    # Run comparison
    print(f"\n[COMPARE] Analyzing {len(tool1_findings)} vs {len(tool2_findings)} findings...")
    result = compare_findings(
        tool1_findings=tool1_findings,
        tool2_findings=tool2_findings,
        gap_coverage_findings=gap_coverage_findings,
        stig_map=stig_map
    )
    
    # Save results
    output_file = PROJECT_ROOT / "data" / "output" / "comparison_output.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"\n[SAVE] ✅ Comparison results saved to: {output_file}")
    logger.info(f"Comparison results saved to: {output_file}")
    
    return result


def compare_findings(
    tool1_findings: List[Dict[str, Any]],
    tool2_findings: List[Dict[str, Any]],
    gap_coverage_findings: Optional[List[Dict[str, Any]]] = None,
    stig_map: Optional[Dict[str, Dict]] = None,
) -> Dict[str, Any]:
    """
    Compare findings from multiple sources and categorize into agreements/disagreements.
    
    Returns comprehensive data for determination agent.
    """
    logger.info("Starting comparison of findings...")

    # Helper to get ID field (try group_id first, then vuln_id for backward compatibility)
    def get_id(finding: Dict) -> str:
        return finding.get('group_id') or finding.get('vuln_id') or ''

    tool1_map = {get_id(f): f for f in tool1_findings if get_id(f)}
    tool2_map = {get_id(f): f for f in tool2_findings if get_id(f)}

    # Build gap coverage map (gap coverage always uses vuln_id)
    gap_map: Dict[str, Dict] = {}
    if gap_coverage_findings:
        for f in gap_coverage_findings:
            vuln_id = f.get("vuln_id")
            if vuln_id:
                gap_map[vuln_id] = f
    
    # STIG context map
    if stig_map is None:
        stig_map = {}

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
            gap_status = normalize_status(gap_finding.get("ares_verdict", gap_finding.get("status", "")))
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
            # Build comprehensive disagreement record for determination agent
            disagreement = {
                "vuln_id": vuln_id,
                "rule_id": tool1_finding.get("rule_id", tool2_finding.get("rule_id")),
                "severity": severity,
                "tool1_status": tool1_status,
                "tool2_status": tool2_status,
                "gap_coverage_status": verdicts.get("gap_coverage"),
                "conflict_type": _classify_conflict(verdicts),
                
                # Full finding data from all sources
                "tool1_finding": tool1_finding,
                "tool2_finding": tool2_finding,
                "gap_finding": gap_finding,
                
                # STIG context for determination agent
                "stig_data": stig_map.get(vuln_id, {}),
                
                # Summary for determination agent
                "summary": {
                    "tool1_details": tool1_finding.get("finding_details", "No details"),
                    "tool2_details": tool2_finding.get("finding_details", "No details"),
                    "gap_details": gap_finding.get("finding_details") if gap_finding else None,
                    "gap_confidence": gap_finding.get("confidence") if gap_finding else None,
                    "gap_evidence": gap_finding.get("evidence") if gap_finding else None,
                },
            }
            disagreements.append(disagreement)

    # Sort disagreements by severity (CAT I first)
    disagreements = sort_by_severity(disagreements)

    summary = {
        "total_compared": len(agreements) + len(disagreements),
        "agreements": len(agreements),
        "disagreements": len(disagreements),
        "gap_coverage_applied": len(gap_map),
        "by_conflict_type": _count_by_conflict_type(disagreements),
        "by_severity": _count_by_severity(disagreements),
    }

    logger.info(f"Comparison complete: {summary}")
    
    print(f"\n[RESULTS]")
    print(f"  Agreements: {summary['agreements']}")
    print(f"  Disagreements: {summary['disagreements']}")
    print(f"  Gap Coverage Applied: {summary['gap_coverage_applied']}")

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


def _count_by_conflict_type(disagreements: List[Dict]) -> Dict[str, int]:
    """Count disagreements by conflict type."""
    counts = {}
    for d in disagreements:
        conflict_type = d.get("conflict_type", "unknown")
        counts[conflict_type] = counts.get(conflict_type, 0) + 1
    return counts


def _count_by_severity(disagreements: List[Dict]) -> Dict[str, int]:
    """Count disagreements by severity."""
    counts = {"CAT I": 0, "CAT II": 0, "CAT III": 0}
    for d in disagreements:
        sev = d.get("severity", "CAT II")
        if sev in counts:
            counts[sev] += 1
        else:
            counts[sev] = 1
    return counts


def sort_by_severity(findings: List[Dict]) -> List[Dict]:
    """Sort findings by severity: CAT I / high > CAT II / medium > CAT III / low."""
    def _key(f):
        sev = f.get("severity", "medium")
        priority = SEVERITY_PRIORITY.get(sev, 99)
        return (priority, f.get("vuln_id", ""))

    return sorted(findings, key=_key)


if __name__ == "__main__":
    # Test the comparison workflow
    logging.basicConfig(level=logging.INFO)
    
    try:
        result = run_comparison()
        
        print("\n" + "="*80)
        print("COMPARISON COMPLETE")
        print("="*80)
        print(f"\nAgreements: {result['summary']['agreements']}")
        print(f"Disagreements: {result['summary']['disagreements']}")
        print(f"Gap Coverage Applied: {result['summary']['gap_coverage_applied']}")
        print(f"\nResults saved to: data/output/comparison_output.json")
        
        # Show conflict type breakdown
        if result['summary'].get('by_conflict_type'):
            print(f"\nDisagreements by Type:")
            for conflict_type, count in result['summary']['by_conflict_type'].items():
                print(f"  • {conflict_type}: {count}")
        
        # Show first few disagreements
        if result['disagreements']:
            print(f"\nFirst 3 Disagreements:")
            for i, d in enumerate(result['disagreements'][:3], 1):
                print(f"  {i}. {d['vuln_id']} ({d['severity']}): {d['conflict_type']}")
                print(f"     Tool1={d['tool1_status']}, Tool2={d['tool2_status']}, Gap={d.get('gap_coverage_status', 'N/A')}")
        
    except Exception as e:
        logger.error(f"Comparison failed: {e}", exc_info=True)
        print(f"\nERROR: {e}")
        print("\nMake sure:")
        print("  1. MCP server has parsed files available")
        print("  2. gap_coverage_results.json exists in data/output/")
        print("  3. RHEL_8_STIG_V2R7.md exists in data/input/")
