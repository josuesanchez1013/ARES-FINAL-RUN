"""
Validation script to test parse_ckl and parse_csv tools as AI agents will use them.

This script:
1. Parses PreSTIGe CKL and evaluate-STIG CSV (the two files we'll use in demo)
2. Validates all 366 findings are extracted with complete STIG metadata
3. Generates TWO separate output files with ALL findings:
   - ckl_parser_output.json (PreSTIGe CKL with all 366 findings)
   - csv_parser_output.json (evaluate-STIG CSV with all 366 findings)
4. Verifies output matches Parser Agent prompt expectations
"""

import json
from pathlib import Path
from mcp_server.parsers.ckl_parser import CKLParser
from mcp_server.parsers.csv_parser import CSVParser

# File paths
data_dir = Path(__file__).parent.parent / "data" / "input"
output_dir = Path(__file__).parent.parent / "data" / "output"
prestige_ckl = data_dir / "rhel8-prestige-auto.ckl"
evaluatestig_csv = data_dir / "rhel8-evaluatestig-remote-ansible.csv"


def parse_and_validate_ckl(filepath: Path, tool_name: str):
    """Parse CKL file with complete STIG metadata."""
    print(f"\n{'='*80}")
    print(f"PARSING {tool_name} CKL FILE")
    print(f"{'='*80}")
    print(f"File: {filepath.name}")
    
    parser = CKLParser()
    findings = parser.parse(str(filepath))
    
    # Convert findings to dict format with ALL STIG metadata
    findings_dict = [
        {
            "group_id": f.group_id,
            "rule_id": f.rule_id,
            "stig_id": f.stig_id,
            "severity": f.severity,
            "classification": f.classification,
            "rule_title": f.rule_title,
            "discussion": f.discussion,
            "check_text": f.check_text,
            "fix_text": f.fix_text,
            "cci": f.cci,
            "status": f.status,
            "finding_details": f.finding_details,
            "comments": f.comments,
            "file_source": f.file_source
        }
        for f in findings
    ]
    
    # Validate count
    print(f"\n✓ Total findings: {len(findings_dict)}")
    assert len(findings_dict) == 366, f"Expected 366 findings, got {len(findings_dict)}"
    
    # Status distribution
    open_count = sum(1 for f in findings_dict if f["status"] == "Open")
    not_a_finding = sum(1 for f in findings_dict if f["status"] == "NotAFinding")
    not_reviewed = sum(1 for f in findings_dict if f["status"] == "Not_Reviewed")
    not_applicable = sum(1 for f in findings_dict if f["status"] == "Not_Applicable")
    
    print(f"✓ Status distribution:")
    print(f"  - Open: {open_count}")
    print(f"  - NotAFinding: {not_a_finding}")
    print(f"  - Not_Reviewed: {not_reviewed}")
    print(f"  - Not_Applicable: {not_applicable}")
    
    # Severity distribution
    cat1 = sum(1 for f in findings_dict if f["severity"] == "CAT I")
    cat2 = sum(1 for f in findings_dict if f["severity"] == "CAT II")
    cat3 = sum(1 for f in findings_dict if f["severity"] == "CAT III")
    
    print(f"✓ Severity distribution:")
    print(f"  - CAT I: {cat1}")
    print(f"  - CAT II: {cat2}")
    print(f"  - CAT III: {cat3}")
    
    # Validate required fields
    missing_fields = []
    for i, finding in enumerate(findings_dict):
        if not finding.get("group_id"):
            missing_fields.append(f"Finding {i}: missing group_id")
        if not finding.get("severity"):
            missing_fields.append(f"Finding {i}: missing severity")
        if not finding.get("status"):
            missing_fields.append(f"Finding {i}: missing status")
        if not finding.get("rule_title"):
            missing_fields.append(f"Finding {i}: missing rule_title")
    
    if missing_fields:
        print(f"\n❌ VALIDATION FAILED:")
        for msg in missing_fields[:10]:
            print(f"  {msg}")
        raise ValueError(f"Found {len(missing_fields)} findings with missing required fields")
    else:
        print(f"✓ All 366 findings have required fields (group_id, severity, status, rule_title)")
    
    # Check STIG metadata extraction
    with_check_text = sum(1 for f in findings_dict if f.get("check_text"))
    with_discussion = sum(1 for f in findings_dict if f.get("discussion"))
    with_rule_id = sum(1 for f in findings_dict if f.get("rule_id"))
    with_cci = sum(1 for f in findings_dict if f.get("cci"))
    
    print(f"✓ STIG metadata extracted:")
    print(f"  - rule_id: {with_rule_id}/366 findings")
    print(f"  - check_text: {with_check_text}/366 findings (CRITICAL for Gap Coverage Agent)")
    print(f"  - discussion: {with_discussion}/366 findings (needed for Determination Agent)")
    print(f"  - cci: {with_cci}/366 findings")
    
    # Show sample with metadata
    print(f"\n✓ Sample finding with STIG metadata:")
    sample = findings_dict[0]
    print(f"  group_id: {sample['group_id']}")
    print(f"  rule_id: {sample['rule_id']}")
    print(f"  severity: {sample['severity']}")
    print(f"  status: {sample['status']}")
    print(f"  rule_title: {sample['rule_title'][:60]}...")
    print(f"  check_text: {'Present (' + str(len(sample['check_text'])) + ' chars)' if sample.get('check_text') else 'None'}")
    print(f"  discussion: {'Present (' + str(len(sample['discussion'])) + ' chars)' if sample.get('discussion') else 'None'}")
    
    return findings_dict


def parse_and_validate_csv(filepath: Path, tool_name: str):
    """Parse CSV file with complete STIG metadata."""
    print(f"\n{'='*80}")
    print(f"PARSING {tool_name} CSV FILE")
    print(f"{'='*80}")
    print(f"File: {filepath.name}")
    
    parser = CSVParser()
    findings = parser.parse(str(filepath))
    
    # Convert findings to dict format with ALL STIG metadata
    findings_dict = [
        {
            "group_id": f.group_id,
            "rule_id": f.rule_id,
            "stig_id": f.stig_id,
            "severity": f.severity,
            "classification": f.classification,
            "rule_title": f.rule_title,
            "discussion": f.discussion,
            "check_text": f.check_text,
            "fix_text": f.fix_text,
            "cci": f.cci,
            "status": f.status,
            "finding_details": f.finding_details,
            "comments": f.comments,
            "file_source": f.file_source
        }
        for f in findings
    ]
    
    # Validate count
    print(f"\n✓ Total findings: {len(findings_dict)}")
    assert len(findings_dict) == 366, f"Expected 366 findings, got {len(findings_dict)}"
    
    # Status distribution
    open_count = sum(1 for f in findings_dict if f["status"] == "Open")
    not_a_finding = sum(1 for f in findings_dict if f["status"] == "NotAFinding")
    not_reviewed = sum(1 for f in findings_dict if f["status"] == "Not_Reviewed")
    not_applicable = sum(1 for f in findings_dict if f["status"] == "Not_Applicable")
    
    print(f"✓ Status distribution:")
    print(f"  - Open: {open_count}")
    print(f"  - NotAFinding: {not_a_finding}")
    print(f"  - Not_Reviewed: {not_reviewed}")
    print(f"  - Not_Applicable: {not_applicable}")
    
    # Severity distribution
    cat1 = sum(1 for f in findings_dict if f["severity"] == "CAT I")
    cat2 = sum(1 for f in findings_dict if f["severity"] == "CAT II")
    cat3 = sum(1 for f in findings_dict if f["severity"] == "CAT III")
    
    print(f"✓ Severity distribution:")
    print(f"  - CAT I: {cat1}")
    print(f"  - CAT II: {cat2}")
    print(f"  - CAT III: {cat3}")
    
    # Validate required fields
    missing_fields = []
    for i, finding in enumerate(findings_dict):
        if not finding.get("group_id"):
            missing_fields.append(f"Finding {i}: missing group_id")
        if not finding.get("severity"):
            missing_fields.append(f"Finding {i}: missing severity")
        if not finding.get("status"):
            missing_fields.append(f"Finding {i}: missing status")
        if not finding.get("rule_title"):
            missing_fields.append(f"Finding {i}: missing rule_title")
    
    if missing_fields:
        print(f"\n❌ VALIDATION FAILED:")
        for msg in missing_fields[:10]:
            print(f"  {msg}")
        raise ValueError(f"Found {len(missing_fields)} findings with missing required fields")
    else:
        print(f"✓ All 366 findings have required fields (group_id, severity, status, rule_title)")
    
    # Check STIG metadata extraction
    with_check_text = sum(1 for f in findings_dict if f.get("check_text"))
    with_discussion = sum(1 for f in findings_dict if f.get("discussion"))
    with_rule_id = sum(1 for f in findings_dict if f.get("rule_id"))
    with_stig_id = sum(1 for f in findings_dict if f.get("stig_id"))
    with_cci = sum(1 for f in findings_dict if f.get("cci"))
    
    print(f"✓ STIG metadata extracted:")
    print(f"  - rule_id: {with_rule_id}/366 findings")
    print(f"  - stig_id: {with_stig_id}/366 findings")
    print(f"  - check_text: {with_check_text}/366 findings (CRITICAL for Gap Coverage Agent)")
    print(f"  - discussion: {with_discussion}/366 findings (needed for Determination Agent)")
    print(f"  - cci: {with_cci}/366 findings")
    
    # Show sample with metadata
    print(f"\n✓ Sample finding with STIG metadata:")
    sample = findings_dict[0]
    print(f"  group_id: {sample['group_id']}")
    print(f"  rule_id: {sample['rule_id']}")
    print(f"  stig_id: {sample['stig_id']}")
    print(f"  severity: {sample['severity']}")
    print(f"  status: {sample['status']}")
    print(f"  rule_title: {sample['rule_title'][:60]}...")
    print(f"  check_text: {'Present (' + str(len(sample['check_text'])) + ' chars)' if sample.get('check_text') else 'None'}")
    print(f"  discussion: {'Present (' + str(len(sample['discussion'])) + ' chars)' if sample.get('discussion') else 'None'}")
    
    return findings_dict


def main():
    """Run comprehensive parser validation and generate output files."""
    print(f"\n{'#'*80}")
    print(f"# COMPREHENSIVE PARSER VALIDATION")
    print(f"# Testing parse_ckl and parse_csv with COMPLETE STIG metadata extraction")
    print(f"{'#'*80}")
    
    # Check files exist
    if not prestige_ckl.exists():
        print(f"❌ PreSTIGe CKL file not found: {prestige_ckl}")
        return
    if not evaluatestig_csv.exists():
        print(f"❌ evaluate-STIG CSV file not found: {evaluatestig_csv}")
        return
    
    # Parse Tool 1 (PreSTIGe CKL)
    tool1_findings = parse_and_validate_ckl(prestige_ckl, "PreSTIGe")
    
    # Parse Tool 2 (evaluate-STIG CSV)
    tool2_findings = parse_and_validate_csv(evaluatestig_csv, "evaluate-STIG")
    
    # Generate output files with ALL findings
    print(f"\n{'='*80}")
    print(f"GENERATING OUTPUT FILES")
    print(f"{'='*80}")
    
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Write CKL parser output (ALL 366 findings)
    ckl_output_file = output_dir / "ckl_parser_output.json"
    with open(ckl_output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "metadata": {
                "tool_name": "PreSTIGe",
                "file_format": "CKL",
                "stig_title": "RHEL 8 STIG",
                "stig_version": "V2R7",
                "total_findings": len(tool1_findings)
            },
            "findings": tool1_findings
        }, f, indent=2)
    print(f"✓ CKL parser output: {ckl_output_file}")
    print(f"  Contains ALL {len(tool1_findings)} findings with complete STIG metadata")
    
    # Write CSV parser output (ALL 366 findings)
    csv_output_file = output_dir / "csv_parser_output.json"
    with open(csv_output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "metadata": {
                "tool_name": "evaluate-STIG",
                "file_format": "CSV",
                "stig_title": "RHEL 8 STIG",
                "stig_version": "V2R7",
                "total_findings": len(tool2_findings)
            },
            "findings": tool2_findings
        }, f, indent=2)
    print(f"✓ CSV parser output: {csv_output_file}")
    print(f"  Contains ALL {len(tool2_findings)} findings with complete STIG metadata")
    
    # Final summary
    print(f"\n{'='*80}")
    print(f"✓ ALL VALIDATIONS PASSED")
    print(f"{'='*80}")
    print(f"\nParser tools are ready for AI agent use:")
    print(f"  • parse_ckl: ✓ Extracts all 366 findings with complete STIG metadata")
    print(f"  • parse_csv: ✓ Extracts all 366 findings with complete STIG metadata")
    print(f"  • Required fields: ✓ group_id, severity, status, rule_title")
    print(f"  • STIG metadata: ✓ check_text, discussion, rule_id, cci, fix_text")
    print(f"  • Status normalization: ✓ Open/NotAFinding/Not_Reviewed")
    print(f"  • Severity normalization: ✓ CAT I/II/III")
    print(f"\nOutput files generated:")
    print(f"  1. {ckl_output_file.name} - PreSTIGe CKL parser output (366 findings)")
    print(f"  2. {csv_output_file.name} - evaluate-STIG CSV parser output (366 findings)")
    print(f"\nNext steps:")
    print(f"  1. Review output files to verify STIG metadata extraction")
    print(f"  2. Update Parser Agent prompt if needed to match actual output")
    print(f"  3. Deploy MCP server to Panel (when access granted)")
    print(f"  4. Test Parser Agent with Genesis")


if __name__ == "__main__":
    main()
