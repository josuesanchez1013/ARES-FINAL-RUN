"""
Gap Identifier - Deterministic script to identify findings reviewed by only one tool.

This is NOT an AI agent - it's pure Python logic for deterministic gap detection.
The Gap Coverage Agent (Genesis) will then validate these gaps via CLI.

UPDATED for v1.3.0 File-Based Architecture:
- Accepts file paths to parsed JSON files
- Loads findings from files written by MCP tools
- Works with both direct data and file paths
"""

from typing import List, Dict, Set, Union
import json
from pathlib import Path


def load_findings_from_file(filepath: Union[str, Path]) -> List[Dict]:
    """
    Load findings from a JSON file written by MCP parser tools.
    
    Args:
        filepath: Path to parsed JSON file (e.g., 'rhel8-prestige-auto_parsed.json')
    
    Returns:
        List of finding dictionaries
        
    File format:
        {
            "source_file": "rhel8-prestige-auto.ckl",
            "parsed_at": "2026-07-13T20:00:00",
            "parser_version": "1.3.0",
            "count": 366,
            "findings": [...]
        }
    """
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    # Extract findings array from MCP tool output format
    if 'findings' in data:
        return data['findings']
    else:
        raise ValueError(f"Invalid file format: missing 'findings' key in {filepath}")


def identify_gaps_from_files(tool1_file: Union[str, Path], tool2_file: Union[str, Path]) -> Dict:
    """
    Identify gaps by loading findings from files (v1.3.0 architecture).
    
    This is the recommended entry point for Streamlit and other orchestrators.
    
    Args:
        tool1_file: Path to Tool 1 parsed JSON (e.g., '/data/output/tool1_parsed.json')
        tool2_file: Path to Tool 2 parsed JSON (e.g., '/data/output/tool2_parsed.json')
    
    Returns:
        Dict with gaps list and statistics
        
    Example:
        >>> result = identify_gaps_from_files(
        ...     '/data/output/prestige_parsed.json',
        ...     '/data/output/evaluatestig_parsed.json'
        ... )
        >>> print(f"Found {len(result['gaps'])} gaps")
        >>> print(f"Statistics: {result['statistics']}")
    """
    # Load findings from files
    tool1_findings = load_findings_from_file(tool1_file)
    tool2_findings = load_findings_from_file(tool2_file)
    
    # Use existing gap detection logic
    gaps = identify_gaps(tool1_findings, tool2_findings)
    stats = categorize_findings(tool1_findings, tool2_findings, gaps)
    
    return {
        'gaps': gaps,
        'statistics': stats,
        'tool1_file': str(tool1_file),
        'tool2_file': str(tool2_file),
        'tool1_count': len(tool1_findings),
        'tool2_count': len(tool2_findings)
    }


def identify_gaps(tool1_findings: List[Dict], tool2_findings: List[Dict]) -> List[Dict]:
    """
    Identify findings reviewed by only one tool (gaps).
    
    Args:
        tool1_findings: List of normalized findings from Tool 1 (e.g., PreSTIGe)
        tool2_findings: List of normalized findings from Tool 2 (e.g., evaluate-STIG)
    
    Returns:
        List of gap findings with metadata about which tool reviewed them
        
    Example:
        >>> tool1 = [{"group_id": "V-230221", "status": "Open"}, {"group_id": "V-230222", "status": "NotAFinding"}]
        >>> tool2 = [{"group_id": "V-230221", "status": "NotAFinding"}]
        >>> gaps = identify_gaps(tool1, tool2)
        >>> print(gaps)
        [{"group_id": "V-230222", "reviewed_by": "tool1_only", "tool1_finding": {...}}]
    """
    # Helper to get ID field (try group_id first, then vuln_id for backward compatibility)
    def get_id(finding: Dict) -> str:
        return finding.get('group_id') or finding.get('vuln_id')
    
    tool1_ids: Set[str] = {get_id(f) for f in tool1_findings if get_id(f)}
    tool2_ids: Set[str] = {get_id(f) for f in tool2_findings if get_id(f)}
    
    tool1_map = {get_id(f): f for f in tool1_findings if get_id(f)}
    tool2_map = {get_id(f): f for f in tool2_findings if get_id(f)}
    
    gaps = []
    
    # Findings reviewed by Tool 1 but not Tool 2
    tool1_only_ids = tool1_ids - tool2_ids
    for vuln_id in tool1_only_ids:
        finding = tool1_map[vuln_id]
        gaps.append({
            'vuln_id': vuln_id,
            'rule_id': finding.get('rule_id'),
            'reviewed_by': 'tool1_only',
            'tool1_finding': finding,
            'requires_validation': True,
            'reason': 'Tool 2 did not review this check'
        })
    
    # Findings reviewed by Tool 2 but not Tool 1
    tool2_only_ids = tool2_ids - tool1_ids
    for vuln_id in tool2_only_ids:
        finding = tool2_map[vuln_id]
        gaps.append({
            'vuln_id': vuln_id,
            'rule_id': finding.get('rule_id'),
            'reviewed_by': 'tool2_only',
            'tool2_finding': finding,
            'requires_validation': True,
            'reason': 'Tool 1 did not review this check'
        })
    
    # Also check for "Not_Reviewed" status in findings that appear in both tools
    common_ids = tool1_ids & tool2_ids
    for vuln_id in common_ids:
        tool1_finding = tool1_map[vuln_id]
        tool2_finding = tool2_map[vuln_id]
        
        # If one tool has "Not_Reviewed" status, treat as gap
        if tool1_finding.get('status') == 'Not_Reviewed' and tool2_finding.get('status') != 'Not_Reviewed':
            gaps.append({
                'vuln_id': vuln_id,
                'rule_id': tool1_finding.get('rule_id'),
                'reviewed_by': 'tool2_only',
                'tool2_finding': tool2_finding,
                'requires_validation': False,  # Tool 2 already has a verdict
                'reason': 'Tool 1 marked as Not_Reviewed, Tool 2 has verdict'
            })
        elif tool2_finding.get('status') == 'Not_Reviewed' and tool1_finding.get('status') != 'Not_Reviewed':
            gaps.append({
                'vuln_id': vuln_id,
                'rule_id': tool2_finding.get('rule_id'),
                'reviewed_by': 'tool1_only',
                'tool1_finding': tool1_finding,
                'requires_validation': False,  # Tool 1 already has a verdict
                'reason': 'Tool 2 marked as Not_Reviewed, Tool 1 has verdict'
            })
        elif tool1_finding.get('status') == 'Not_Reviewed' and tool2_finding.get('status') == 'Not_Reviewed':
            gaps.append({
                'vuln_id': vuln_id,
                'rule_id': tool1_finding.get('rule_id'),
                'reviewed_by': 'neither',
                'requires_validation': True,
                'reason': 'Both tools marked as Not_Reviewed - needs CLI validation'
            })
    
    return gaps


def categorize_findings(tool1_findings: List[Dict], tool2_findings: List[Dict], gaps: List[Dict]) -> Dict:
    """
    Categorize all findings for summary statistics.
    
    This gives a quick overview without doing full comparison logic.
    The Comparison Agent will do the detailed analysis.
    
    Returns:
        Summary statistics about gaps and coverage
    """
    # Helper to get ID field (try group_id first, then vuln_id for backward compatibility)
    def get_id(finding: Dict) -> str:
        return finding.get('group_id') or finding.get('vuln_id')
    
    tool1_ids = {get_id(f) for f in tool1_findings if get_id(f)}
    tool2_ids = {get_id(f) for f in tool2_findings if get_id(f)}
    
    total_rules = len(tool1_ids | tool2_ids)  # Union of all reviewed rules
    both_reviewed = len(tool1_ids & tool2_ids)  # Intersection
    gaps_count = len(gaps)
    
    return {
        'total_rules_reviewed': total_rules,
        'both_tools_reviewed': both_reviewed,
        'gaps_identified': gaps_count,
        'tool1_only_count': len([g for g in gaps if g['reviewed_by'] == 'tool1_only']),
        'tool2_only_count': len([g for g in gaps if g['reviewed_by'] == 'tool2_only']),
        'neither_reviewed_count': len([g for g in gaps if g['reviewed_by'] == 'neither'])
    }


if __name__ == '__main__':
    # Example usage for testing
    tool1 = [
        {'vuln_id': 'V-230221', 'rule_id': 'SV-230221r627750_rule', 'status': 'Open', 'severity': 'high'},
        {'vuln_id': 'V-230222', 'rule_id': 'SV-230222r627750_rule', 'status': 'NotAFinding', 'severity': 'medium'},
        {'vuln_id': 'V-230225', 'rule_id': 'SV-230225r627750_rule', 'status': 'Not_Reviewed', 'severity': 'high'},
    ]
    
    tool2 = [
        {'vuln_id': 'V-230221', 'rule_id': 'SV-230221r627750_rule', 'status': 'NotAFinding', 'severity': 'high'},
        {'vuln_id': 'V-230222', 'rule_id': 'SV-230222r627750_rule', 'status': 'NotAFinding', 'severity': 'medium'},
        {'vuln_id': 'V-230226', 'rule_id': 'SV-230226r627750_rule', 'status': 'Open', 'severity': 'medium'},
    ]
    
    gaps = identify_gaps(tool1, tool2)
    stats = categorize_findings(tool1, tool2, gaps)
    
    print("=== Gap Detection Example ===")
    print(f"\nIdentified {len(gaps)} gaps:")
    for gap in gaps:
        print(f"  - {gap['vuln_id']}: {gap['reason']}")
    
    print(f"\nSummary Statistics:")
    print(f"  Total rules reviewed: {stats['total_rules_reviewed']}")
    print(f"  Both tools reviewed: {stats['both_tools_reviewed']}")
    print(f"  Gaps identified: {stats['gaps_identified']}")
    print(f"  Tool 1 only: {stats['tool1_only_count']}")
    print(f"  Tool 2 only: {stats['tool2_only_count']}")
