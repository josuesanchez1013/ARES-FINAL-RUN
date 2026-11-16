"""
Tests for CKL parser (Checklist XML format).

Note: CKL files are XML format. CKLB files are JSON format and require a separate parser.
"""

import pytest
from mcp_server.parsers.ckl_parser import CKLParser
from mcp_server.schemas.finding_schema import Finding


class TestCKLParser:
    """Test suite for CKL (XML) parser."""
    
    def test_parse_prestige_ckl(self, prestige_ckl_file):
        """Test parsing real PreSTIGe CKL file (366 findings) - COMPREHENSIVE TEST.
        
        This test mirrors how the Parser Agent will use parse_ckl tool:
        1. Parse the file
        2. Validate ALL 366 findings are present
        3. Verify all required fields exist for EVERY finding
        4. Check output structure matches Parser Agent prompt expectations
        """
        if not prestige_ckl_file.exists():
            pytest.skip("Real PreSTIGe CKL file not available")
        
        parser = CKLParser()
        findings = parser.parse(str(prestige_ckl_file))
        
        # CRITICAL: Must have exactly 366 findings (all RHEL 8 STIG rules)
        assert len(findings) == 366, f"Expected 366 findings, got {len(findings)}"
        assert all(isinstance(f, Finding) for f in findings)
        
        # CRITICAL: Every finding must have required fields (Parser Agent expects these)
        for i, finding in enumerate(findings):
            assert finding.group_id, f"Finding {i} missing group_id"
            assert finding.group_id.startswith("V-"), f"Finding {i} invalid group_id format: {finding.group_id}"
            assert finding.severity in ["CAT I", "CAT II", "CAT III"], f"Finding {i} invalid severity: {finding.severity}"
            assert finding.status in ["Open", "NotAFinding", "Not_Reviewed", "Not_Applicable"], f"Finding {i} invalid status: {finding.status}"
            assert finding.rule_title, f"Finding {i} missing rule_title"
            assert finding.file_source, f"Finding {i} missing file_source"
            # All findings should have STIG metadata extracted
            # check_text, discussion are CRITICAL for downstream agents
        
        # Verify severity distribution (known from RHEL 8 STIG V2R7)
        cat1 = sum(1 for f in findings if f.severity == "CAT I")
        cat2 = sum(1 for f in findings if f.severity == "CAT II")
        cat3 = sum(1 for f in findings if f.severity == "CAT III")
        
        assert cat1 == 29, f"Expected 29 CAT I findings, got {cat1}"
        assert cat2 == 311, f"Expected 311 CAT II findings, got {cat2}"
        assert cat3 == 26, f"Expected 26 CAT III findings, got {cat3}"
        
        # Verify status distribution (all findings should have valid status)
        open_count = sum(1 for f in findings if f.status == "Open")
        not_a_finding = sum(1 for f in findings if f.status == "NotAFinding")
        not_reviewed = sum(1 for f in findings if f.status == "Not_Reviewed")
        
        print(f"\n=== PreSTIGe CKL Parse Results ===")
        print(f"Total findings: {len(findings)}")
        print(f"Open: {open_count}")
        print(f"NotAFinding: {not_a_finding}")
        print(f"Not_Reviewed: {not_reviewed}")
        print(f"CAT I: {cat1}, CAT II: {cat2}, CAT III: {cat3}")
        
        # Verify ALL findings have unique group_ids (no duplicates)
        group_ids = [f.group_id for f in findings]
        assert len(group_ids) == len(set(group_ids)), "Duplicate group_ids found"
        
        # Spot check: Verify a known finding exists with STIG metadata
        v230221 = next((f for f in findings if f.group_id == "V-230221"), None)
        assert v230221 is not None, "V-230221 not found in findings"
        assert v230221.severity in ["CAT I", "CAT II", "CAT III"]
        assert v230221.rule_id is not None, "V-230221 missing rule_id"
        assert v230221.check_text is not None, "V-230221 missing check_text (needed by Gap Coverage Agent)"
    
    def test_parse_evaluatestig_ckl(self, evaluatestig_ckl_file):
        """Test parsing real evaluate-STIG CKL file (366 findings) - COMPREHENSIVE TEST.
        
        This test mirrors how the Parser Agent will use parse_ckl tool:
        1. Parse the file
        2. Validate ALL 366 findings are present
        3. Verify all required fields exist for EVERY finding
        4. Check output structure matches Parser Agent prompt expectations
        """
        if not evaluatestig_ckl_file.exists():
            pytest.skip("Real evaluate-STIG CKL file not available")
        
        parser = CKLParser()
        findings = parser.parse(str(evaluatestig_ckl_file))
        
        # CRITICAL: Must have exactly 366 findings (all RHEL 8 STIG rules)
        assert len(findings) == 366, f"Expected 366 findings, got {len(findings)}"
        assert all(isinstance(f, Finding) for f in findings)
        
        # CRITICAL: Every finding must have required fields (Parser Agent expects these)
        for i, finding in enumerate(findings):
            assert finding.group_id, f"Finding {i} missing group_id"
            assert finding.group_id.startswith("V-"), f"Finding {i} invalid group_id format: {finding.group_id}"
            assert finding.severity in ["CAT I", "CAT II", "CAT III"], f"Finding {i} invalid severity: {finding.severity}"
            assert finding.status in ["Open", "NotAFinding", "Not_Reviewed", "Not_Applicable"], f"Finding {i} invalid status: {finding.status}"
            assert finding.rule_title, f"Finding {i} missing rule_title"
            assert finding.file_source, f"Finding {i} missing file_source"
        
        # Verify severity distribution (known from RHEL 8 STIG V2R7)
        cat1 = sum(1 for f in findings if f.severity == "CAT I")
        cat2 = sum(1 for f in findings if f.severity == "CAT II")
        cat3 = sum(1 for f in findings if f.severity == "CAT III")
        
        assert cat1 == 29, f"Expected 29 CAT I findings, got {cat1}"
        assert cat2 == 311, f"Expected 311 CAT II findings, got {cat2}"
        assert cat3 == 26, f"Expected 26 CAT III findings, got {cat3}"
        
        # Verify status distribution
        open_count = sum(1 for f in findings if f.status == "Open")
        not_a_finding = sum(1 for f in findings if f.status == "NotAFinding")
        not_reviewed = sum(1 for f in findings if f.status == "Not_Reviewed")
        
        print(f"\n=== evaluate-STIG CKL Parse Results ===")
        print(f"Total findings: {len(findings)}")
        print(f"Open: {open_count}")
        print(f"NotAFinding: {not_a_finding}")
        print(f"Not_Reviewed: {not_reviewed}")
        print(f"CAT I: {cat1}, CAT II: {cat2}, CAT III: {cat3}")
        
        # Verify ALL findings have unique group_ids (no duplicates)
        group_ids = [f.group_id for f in findings]
        assert len(group_ids) == len(set(group_ids)), "Duplicate group_ids found"
    
    def test_parse_missing_file(self):
        """Test error handling for missing file."""
        parser = CKLParser()
        with pytest.raises(FileNotFoundError):
            parser.parse("nonexistent.ckl")
    
    def test_normalize_severity(self):
        """Test severity normalization."""
        parser = CKLParser()
        
        # Test all severity variations
        assert parser._normalize_severity("high") == "CAT I"
        assert parser._normalize_severity("medium") == "CAT II"
        assert parser._normalize_severity("low") == "CAT III"
        assert parser._normalize_severity("CAT I") == "CAT I"
        assert parser._normalize_severity("CAT II") == "CAT II"
        assert parser._normalize_severity("CAT III") == "CAT III"
    
    def test_normalize_status(self):
        """Test status normalization."""
        parser = CKLParser()
        
        # Test all status variations
        assert parser._normalize_status("Open") == "Open"
        assert parser._normalize_status("NotAFinding") == "NotAFinding"
        assert parser._normalize_status("Not_Reviewed") == "Not_Reviewed"
        assert parser._normalize_status("Not Applicable") == "Not_Applicable"
        assert parser._normalize_status("NA") == "Not_Applicable"
    
    def test_parse_invalid_xml(self, tmp_path):
        """Test error handling for invalid XML."""
        invalid_file = tmp_path / "invalid.ckl"
        invalid_file.write_text("This is not XML")
        
        parser = CKLParser()
        with pytest.raises(ValueError, match="Invalid XML format"):
            parser.parse(str(invalid_file))
