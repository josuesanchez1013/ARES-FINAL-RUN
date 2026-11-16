"""
Test parsers with opposite file types: PreSTIGe CSV + evaluate-STIG CKL
to ensure parsers work consistently regardless of which tool generated the file.
"""

import pytest
from pathlib import Path
from mcp_server.parsers.ckl_parser import CKLParser
from mcp_server.parsers.csv_parser import CSVParser


def test_prestige_csv():
    """Test PreSTIGe CSV file - ensure CSV parser works regardless of tool."""
    csv_file = Path(__file__).parent.parent / "data" / "input" / "rhel8-prestige-auto.csv"
    
    if not csv_file.exists():
        pytest.skip(f"PreSTIGe CSV file not found: {csv_file}")
    
    parser = CSVParser()
    findings = parser.parse(str(csv_file))
    
    print(f"\n=== PreSTIGe CSV Parse Results ===")
    print(f"Total findings: {len(findings)}")
    
    # Must have exactly 366 findings
    assert len(findings) == 366, f"Expected 366 findings, got {len(findings)}"
    
    # Check status distribution
    open_count = sum(1 for f in findings if f.status == "Open")
    not_a_finding = sum(1 for f in findings if f.status == "NotAFinding")
    not_reviewed = sum(1 for f in findings if f.status == "Not_Reviewed")
    not_applicable = sum(1 for f in findings if f.status == "Not_Applicable")
    
    print(f"Status: Open={open_count}, NotAFinding={not_a_finding}, Not_Reviewed={not_reviewed}, Not_Applicable={not_applicable}")
    
    # Verify all 4 status types are properly detected
    assert open_count + not_a_finding + not_reviewed + not_applicable == 366, "Status counts don't add up"
    
    # Check file_source is set correctly
    assert all(f.file_source == "rhel8-prestige-auto.csv" for f in findings), "file_source should be filename"
    
    # Verify STIG metadata
    with_check_text = sum(1 for f in findings if f.check_text)
    with_discussion = sum(1 for f in findings if f.discussion)
    with_cci = sum(1 for f in findings if f.cci)
    
    print(f"STIG metadata: check_text={with_check_text}, discussion={with_discussion}, cci={with_cci}")
    assert with_check_text == 366, "All findings should have check_text"
    assert with_discussion == 366, "All findings should have discussion"


def test_evaluatestig_ckl():
    """Test evaluate-STIG CKL file - ensure CKL parser works regardless of tool."""
    ckl_file = Path(__file__).parent.parent / "data" / "input" / "rhel8-evaluatestig-remote-ansible.ckl"
    
    if not ckl_file.exists():
        pytest.skip(f"evaluate-STIG CKL file not found: {ckl_file}")
    
    parser = CKLParser()
    findings = parser.parse(str(ckl_file))
    
    print(f"\n=== evaluate-STIG CKL Parse Results ===")
    print(f"Total findings: {len(findings)}")
    
    # Must have exactly 366 findings
    assert len(findings) == 366, f"Expected 366 findings, got {len(findings)}"
    
    # Check status distribution
    open_count = sum(1 for f in findings if f.status == "Open")
    not_a_finding = sum(1 for f in findings if f.status == "NotAFinding")
    not_reviewed = sum(1 for f in findings if f.status == "Not_Reviewed")
    not_applicable = sum(1 for f in findings if f.status == "Not_Applicable")
    
    print(f"Status: Open={open_count}, NotAFinding={not_a_finding}, Not_Reviewed={not_reviewed}, Not_Applicable={not_applicable}")
    
    # Verify all 4 status types are properly detected
    assert open_count + not_a_finding + not_reviewed + not_applicable == 366, "Status counts don't add up"
    
    # Check file_source is set correctly
    assert all(f.file_source == "rhel8-evaluatestig-remote-ansible.ckl" for f in findings), "file_source should be filename"
    
    # Verify STIG metadata
    with_check_text = sum(1 for f in findings if f.check_text)
    with_discussion = sum(1 for f in findings if f.discussion)
    with_cci = sum(1 for f in findings if f.cci)
    
    print(f"STIG metadata: check_text={with_check_text}, discussion={with_discussion}, cci={with_cci}")
    assert with_check_text == 366, "All findings should have check_text"
    assert with_discussion == 366, "All findings should have discussion"
    assert with_cci == 366, "All findings should have CCI"


def test_consistent_output_structure():
    """Verify both parsers produce the same standardized output structure."""
    csv_file = Path(__file__).parent.parent / "data" / "input" / "rhel8-prestige-auto.csv"
    ckl_file = Path(__file__).parent.parent / "data" / "input" / "rhel8-evaluatestig-remote-ansible.ckl"
    
    if not csv_file.exists() or not ckl_file.exists():
        pytest.skip("Test files not found")
    
    csv_parser = CSVParser()
    ckl_parser = CKLParser()
    
    csv_findings = csv_parser.parse(str(csv_file))
    ckl_findings = ckl_parser.parse(str(ckl_file))
    
    # Both should have same number of findings
    assert len(csv_findings) == len(ckl_findings) == 366
    
    # Check V-230221 exists in both and has same structure
    csv_v230221 = next((f for f in csv_findings if f.group_id == "V-230221"), None)
    ckl_v230221 = next((f for f in ckl_findings if f.group_id == "V-230221"), None)
    
    assert csv_v230221 is not None, "V-230221 not found in CSV"
    assert ckl_v230221 is not None, "V-230221 not found in CKL"
    
    # Both should have all required fields
    required_fields = ["group_id", "rule_id", "severity", "status", "rule_title", "file_source"]
    for field in required_fields:
        assert hasattr(csv_v230221, field), f"CSV missing field: {field}"
        assert hasattr(ckl_v230221, field), f"CKL missing field: {field}"
        assert getattr(csv_v230221, field) is not None, f"CSV {field} is None"
        assert getattr(ckl_v230221, field) is not None, f"CKL {field} is None"
    
    # Both should have STIG metadata
    stig_metadata = ["check_text", "discussion", "cci"]
    for field in stig_metadata:
        csv_val = getattr(csv_v230221, field)
        ckl_val = getattr(ckl_v230221, field)
        # At least one should have the field populated (may differ by tool)
        assert csv_val or ckl_val, f"Both parsers missing {field} for V-230221"
    
    print("\n=== Standardization Check ===")
    print("✓ Both parsers produce consistent structure")
    print("✓ All required fields present")
    print("✓ STIG metadata extracted")
