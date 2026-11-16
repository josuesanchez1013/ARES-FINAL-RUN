"""
Tests for CSV parser.

Handles CSV files with classification banners and various column name formats.
"""

import pytest
from mcp_server.parsers.csv_parser import CSVParser
from mcp_server.schemas.finding_schema import Finding


class TestCSVParser:
    """Test suite for CSV parser."""
    
    def test_parse_prestige_csv(self, prestige_csv_file):
        """Test parsing real PreSTIGe CSV file with classification banner (366 findings) - COMPREHENSIVE TEST.
        
        This test mirrors how the Parser Agent will use parse_csv tool:
        1. Parse the file (handles classification banners)
        2. Validate ALL 366 findings are present
        3. Verify all required fields exist for EVERY finding
        4. Check output structure matches Parser Agent prompt expectations
        """
        if not prestige_csv_file.exists():
            pytest.skip("Real PreSTIGe CSV file not available")
        
        parser = CSVParser()
        findings = parser.parse(str(prestige_csv_file))
        
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
        
        print(f"\n=== PreSTIGe CSV Parse Results ===")
        print(f"Total findings: {len(findings)}")
        print(f"Open: {open_count}")
        print(f"NotAFinding: {not_a_finding}")
        print(f"Not_Reviewed: {not_reviewed}")
        print(f"CAT I: {cat1}, CAT II: {cat2}, CAT III: {cat3}")
        
        # Verify ALL findings have unique group_ids (no duplicates)
        group_ids = [f.group_id for f in findings]
        assert len(group_ids) == len(set(group_ids)), "Duplicate group_ids found"
    
    def test_parse_evaluatestig_csv(self, evaluatestig_csv_file):
        """Test parsing real evaluate-STIG CSV file with classification banner (366 findings) - COMPREHENSIVE TEST.
        
        This test mirrors how the Parser Agent will use parse_csv tool:
        1. Parse the file (handles classification banners)
        2. Validate ALL 366 findings are present
        3. Verify all required fields exist for EVERY finding
        4. Check output structure matches Parser Agent prompt expectations
        """
        if not evaluatestig_csv_file.exists():
            pytest.skip("Real evaluate-STIG CSV file not available")
        
        parser = CSVParser()
        findings = parser.parse(str(evaluatestig_csv_file))
        
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
        
        print(f"\n=== evaluate-STIG CSV Parse Results ===")
        print(f"Total findings: {len(findings)}")
        print(f"Open: {open_count}")
        print(f"NotAFinding: {not_a_finding}")
        print(f"Not_Reviewed: {not_reviewed}")
        print(f"CAT I: {cat1}, CAT II: {cat2}, CAT III: {cat3}")
        
        # Verify ALL findings have unique group_ids (no duplicates)
        group_ids = [f.group_id for f in findings]
        assert len(group_ids) == len(set(group_ids)), "Duplicate group_ids found"
        
        # Spot check: Verify classification banner was properly handled (no banner data in findings)
        assert all("~" not in f.group_id for f in findings), "Classification banner not properly filtered"
    
    def test_detect_columns(self):
        """Test column detection for various CSV formats."""
        parser = CSVParser()
        
        # Test with standard column names
        columns1 = ["Group ID", "Rule ID", "Severity", "Status", "Rule Title", "Finding Details"]
        col_map1 = parser._detect_columns(columns1)
        assert "group_id" in col_map1
        assert "rule_id" in col_map1
        assert "severity" in col_map1
        assert "status" in col_map1
        
        # Test with alternative column names
        columns2 = ["Vuln ID", "Cat", "Result", "Description", "Evidence"]
        col_map2 = parser._detect_columns(columns2)
        assert "group_id" in col_map2  # Vuln ID maps to group_id
        assert "severity" in col_map2  # Cat maps to severity
        assert "status" in col_map2  # Result maps to status
    
    def test_parse_missing_file(self):
        """Test error handling for missing file."""
        parser = CSVParser()
        with pytest.raises(FileNotFoundError):
            parser.parse("nonexistent.csv")
    
    def test_parse_missing_required_column(self, tmp_path):
        """Test error handling for missing required columns."""
        csv_file = tmp_path / "missing_column.csv"
        csv_file.write_text("SomeColumn,AnotherColumn\nvalue1,value2\n")
        
        parser = CSVParser()
        with pytest.raises(Exception, match="CSV missing required"):
            parser.parse(str(csv_file))
    
    def test_normalize_severity(self):
        """Test severity normalization."""
        parser = CSVParser()
        
        # Test all severity variations
        assert parser._normalize_severity("high") == "CAT I"
        assert parser._normalize_severity("medium") == "CAT II"
        assert parser._normalize_severity("low") == "CAT III"
        assert parser._normalize_severity("CAT I") == "CAT I"
        assert parser._normalize_severity("CAT II") == "CAT II"
        assert parser._normalize_severity("CAT III") == "CAT III"
    
    def test_normalize_status(self):
        """Test status normalization."""
        parser = CSVParser()
        
        # Test all status variations
        assert parser._normalize_status("Open") == "Open"
        assert parser._normalize_status("NotAFinding") == "NotAFinding"
        assert parser._normalize_status("Not_Reviewed") == "Not_Reviewed"
        assert parser._normalize_status("pass") == "NotAFinding"
        assert parser._normalize_status("fail") == "Open"
    
    def test_classification_banner_handling(self, tmp_path):
        """Test that classification banners are properly skipped."""
        csv_file = tmp_path / "with_banner.csv"
        csv_file.write_text(
            "~~~~~~~ Unclassified ~~~~~~\n"
            "Group ID,Severity,Status,Rule Title\n"
            "V-12345,high,Open,Test finding\n"
        )
        
        parser = CSVParser()
        findings = parser.parse(str(csv_file))
        
        assert len(findings) == 1
        assert findings[0].group_id == "V-12345"
