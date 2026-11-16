"""
Parser for STIG CSV output.

Works with CSV output from any STIG tool:
- PreSTIGe
- evaluate-STIG  
- Any tool that exports CSV with Rule ID, Severity, Status columns

CSV format may vary slightly by tool/version, parser auto-detects columns.
"""

import csv
from typing import List
from .base_parser import BaseParser
from ..schemas.finding_schema import Finding


class CSVParser(BaseParser):
    """Parse evaluate-STIG CSV files."""
    
    # Common column name variations
    # NOTE: Order matters! Earlier in list = higher priority
    # GROUP_ID is the primary identifier (V-230221 format)
    GROUP_ID_COLS = ["Group ID", "Vuln ID", "Vuln_Num"]
    RULE_ID_COLS = ["Rule ID", "SRG ID"]
    STIG_ID_COLS = ["STIG ID"]
    SEVERITY_COLS = ["Severity", "Cat", "Category"]
    CLASSIFICATION_COLS = ["Classification", "Class"]
    TITLE_COLS = ["Rule Title", "Title", "Description"]
    DISCUSSION_COLS = ["Discussion", "Vuln_Discuss", "Vulnerability Discussion"]
    CHECK_TEXT_COLS = ["Check Content", "Check Text", "Check_Content"]
    FIX_TEXT_COLS = ["Fix Text", "Fix_Text", "Mitigation"]
    CCI_COLS = ["CCIs", "CCI", "CCI_REF", "IA Controls"]
    STATUS_COLS = ["Status", "Result", "Finding Status"]
    DETAILS_COLS = ["Finding Details", "Details", "Evidence"]
    COMMENTS_COLS = ["Comments", "Comment"]
    
    def parse(self, filepath: str) -> List[Finding]:
        """Parse CSV file to normalized findings."""
        path = self._validate_file_exists(filepath)
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                # Skip classification banner lines (lines starting with ~)
                lines = []
                for line in f:
                    if not line.strip().startswith('~'):
                        lines.append(line)
                
                # Parse CSV from remaining lines
                import io
                csv_text = ''.join(lines)
                reader = csv.DictReader(io.StringIO(csv_text))
                
                # Detect column names
                col_map = self._detect_columns(reader.fieldnames)
                
                # Use filename as file_source (no tool detection)
                file_source = path.name
                
                findings = []
                for row in reader:
                    finding = self._parse_row(row, col_map, file_source)
                    if finding:
                        findings.append(finding)
                
                return findings
        
        except Exception as e:
            raise Exception(f"Error parsing CSV file: {e}")
    
    def _detect_columns(self, fieldnames: List[str]) -> dict:
        """Detect which columns map to which fields.
        
        Prioritizes columns based on list order (earlier = higher priority).
        This ensures we use Group ID (V-230221) over STIG ID (RHEL-08-010000).
        """
        col_map = {}
        
        # Clean all fieldnames
        fieldnames_clean = [f.strip() for f in fieldnames]
        
        # Match columns in priority order (earlier in list = higher priority)
        def find_best_match(candidates, available_fields):
            """Find the first candidate that exists in available_fields."""
            for candidate in candidates:
                if candidate in available_fields:
                    return candidate
            return None
        
        # Match each field type with highest priority column available
        col_map["group_id"] = find_best_match(self.GROUP_ID_COLS, fieldnames_clean)
        col_map["rule_id"] = find_best_match(self.RULE_ID_COLS, fieldnames_clean)
        col_map["stig_id"] = find_best_match(self.STIG_ID_COLS, fieldnames_clean)
        col_map["severity"] = find_best_match(self.SEVERITY_COLS, fieldnames_clean)
        col_map["classification"] = find_best_match(self.CLASSIFICATION_COLS, fieldnames_clean)
        col_map["title"] = find_best_match(self.TITLE_COLS, fieldnames_clean)
        col_map["discussion"] = find_best_match(self.DISCUSSION_COLS, fieldnames_clean)
        col_map["check_text"] = find_best_match(self.CHECK_TEXT_COLS, fieldnames_clean)
        col_map["fix_text"] = find_best_match(self.FIX_TEXT_COLS, fieldnames_clean)
        col_map["cci"] = find_best_match(self.CCI_COLS, fieldnames_clean)
        col_map["status"] = find_best_match(self.STATUS_COLS, fieldnames_clean)
        col_map["details"] = find_best_match(self.DETAILS_COLS, fieldnames_clean)
        col_map["comments"] = find_best_match(self.COMMENTS_COLS, fieldnames_clean)
        
        # Validate required columns exist
        if not col_map.get("group_id"):
            raise ValueError(f"CSV missing required Group ID column. Available columns: {fieldnames}")
        if not col_map.get("status"):
            raise ValueError(f"CSV missing required Status column. Available columns: {fieldnames}")
        
        return col_map
    
    def _parse_row(self, row: dict, col_map: dict, file_source: str) -> Finding:
        """Parse single CSV row to Finding with complete STIG metadata."""
        # Extract Group ID (PRIMARY IDENTIFIER)
        group_id = row.get(col_map.get("group_id", ""), "").strip()
        if not group_id:
            return None  # Skip rows without Group ID
        
        # Extract Rule ID (e.g., SV-230221r627750_rule)
        rule_id = row.get(col_map.get("rule_id", ""), "").strip() or None
        
        # Extract STIG ID (e.g., RHEL-08-010000)
        stig_id = row.get(col_map.get("stig_id", ""), "").strip() or None
        
        # Extract Severity
        severity_raw = row.get(col_map.get("severity", ""), "CAT III")
        severity = self._normalize_severity(severity_raw)
        
        # Extract Classification
        classification = row.get(col_map.get("classification", ""), "").strip() or None
        
        # Extract Rule Title
        rule_title = row.get(col_map.get("title", ""), "No title").strip()
        
        # Extract Discussion
        discussion = row.get(col_map.get("discussion", ""), "").strip() or None
        
        # Extract Check Text
        check_text = row.get(col_map.get("check_text", ""), "").strip() or None
        
        # Extract Fix Text
        fix_text = row.get(col_map.get("fix_text", ""), "").strip() or None
        
        # Extract CCI
        cci = row.get(col_map.get("cci", ""), "").strip() or None
        
        # Extract Status (scan result)
        status_raw = row.get(col_map.get("status", ""), "Not_Reviewed")
        status = self._normalize_status(status_raw)
        
        # Extract Finding Details (evidence from scan tool)
        finding_details = row.get(col_map.get("details", ""), "").strip() or None
        
        # Extract Comments
        comments = row.get(col_map.get("comments", ""), "").strip() or None
        
        return Finding(
            group_id=group_id,
            rule_id=rule_id,
            stig_id=stig_id,
            severity=severity,
            classification=classification,
            rule_title=rule_title,
            discussion=discussion,
            check_text=check_text,
            fix_text=fix_text,
            cci=cci,
            status=status,
            finding_details=finding_details,
            comments=comments,
            file_source=file_source,
            raw_data={
                "original_severity": severity_raw,
                "original_status": status_raw,
                "csv_row": row
            }
        )
    
    def _normalize_severity(self, severity_raw: str) -> str:
        """Normalize severity to CAT I/II/III."""
        # Same logic as CKL parser
        if not severity_raw:
            return "CAT III"
        
        severity_lower = severity_raw.lower()
        if severity_lower in ["high", "cat i", "cat1", "category i", "i"]:
            return "CAT I"
        elif severity_lower in ["medium", "cat ii", "cat2", "category ii", "ii"]:
            return "CAT II"
        elif severity_lower in ["low", "cat iii", "cat3", "category iii", "iii"]:
            return "CAT III"
        else:
            return "CAT III"
    
    def _normalize_status(self, status_raw: str) -> str:
        """Normalize status to Open/NotAFinding/Not_Reviewed/Not_Applicable."""
        # Same logic as CKL parser
        if not status_raw:
            return "Not_Reviewed"
        
        status_lower = status_raw.lower().replace("_", "").replace(" ", "")
        if status_lower in ["open", "finding", "fail", "failed"]:
            return "Open"
        elif status_lower in ["notafinding", "pass", "passed"]:
            return "NotAFinding"
        elif status_lower in ["notapplicable", "na"]:
            return "Not_Applicable"
        else:
            return "Not_Reviewed"
