"""
Parser for CKL files (Checklist XML format).

IMPORTANT: This parser handles CKL files which use XML structure.
CKLB files (introduced in STIG Viewer 3+) use JSON format and require a separate parser.

Works with CKL (XML) output from any STIG tool:
- PreSTIGe
- evaluate-STIG
- SCC (SCAP Compliance Checker)
- STIG Viewer (versions 1-2)
- Any tool that exports standard CKL XML format

All use the same XML structure with <CHECKLIST>, <VULN>, and <STIG_DATA> elements.
"""

import xml.etree.ElementTree as ET
from typing import List
from .base_parser import BaseParser
from ..schemas.finding_schema import Finding


class CKLParser(BaseParser):
    """Parse CKL (Checklist XML) files from any STIG tool."""
    
    def parse(self, filepath: str) -> List[Finding]:
        """Parse CKL (XML) file to normalized findings.
        
        Note: CKLB (JSON) files are not supported by this parser.
        """
        path = self._validate_file_exists(filepath)
        
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            
            # Use filename as file_source (no tool detection)
            file_source = path.name
            
            findings = []
            
            # Navigate XML structure: CHECKLIST → STIGS → iSTIG → VULN
            for vuln in root.findall(".//VULN"):
                finding = self._parse_vuln(vuln, file_source)
                if finding:
                    findings.append(finding)
            
            return findings
        
        except ET.ParseError as e:
            raise ValueError(f"Invalid XML format: {e}")
        except Exception as e:
            raise Exception(f"Error parsing CKL file: {e}")
    
    def _parse_vuln(self, vuln_elem: ET.Element, file_source: str) -> Finding:
        """Parse single VULN element to Finding with complete STIG metadata."""
        # Extract Group ID (Vuln_Num) - PRIMARY IDENTIFIER
        group_id = self._get_stig_data(vuln_elem, "Vuln_Num")
        if not group_id:
            return None  # Skip if no Group ID
        
        # Extract Rule ID (e.g., SV-230221r627750_rule)
        rule_id = self._get_stig_data(vuln_elem, "Rule_ID")
        
        # Extract STIG ID (e.g., RHEL-08-010000)
        stig_id = self._get_stig_data(vuln_elem, "STIG_UUID") or self._get_stig_data(vuln_elem, "IA_Controls")
        
        # Extract Severity
        severity_raw = self._get_stig_data(vuln_elem, "Severity")
        severity = self._normalize_severity(severity_raw)
        
        # Extract Classification
        classification = self._get_stig_data(vuln_elem, "Class") or self._get_stig_data(vuln_elem, "Classification")
        
        # Extract Rule Title
        rule_title = self._get_stig_data(vuln_elem, "Rule_Title") or "No title"
        
        # Extract Discussion (vulnerability description/background)
        discussion = self._get_stig_data(vuln_elem, "Vuln_Discuss")
        
        # Extract Check Text (how to verify compliance)
        check_text = self._get_stig_data(vuln_elem, "Check_Content")
        
        # Extract Fix Text (how to remediate)
        fix_text = self._get_stig_data(vuln_elem, "Fix_Text")
        
        # Extract CCI (Control Correlation Identifier)
        cci = self._get_stig_data(vuln_elem, "CCI_REF")
        
        # Extract Status (scan result)
        status_elem = vuln_elem.find("STATUS")
        status_raw = status_elem.text if status_elem is not None else "Not_Reviewed"
        status = self._normalize_status(status_raw)
        
        # Extract Finding Details (evidence from scan tool)
        finding_details_elem = vuln_elem.find("FINDING_DETAILS")
        finding_details = finding_details_elem.text if finding_details_elem is not None else None
        
        # Extract Comments
        comments_elem = vuln_elem.find("COMMENTS")
        comments = comments_elem.text if comments_elem is not None else None
        
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
                "original_status": status_raw
            }
        )
    
    def _get_stig_data(self, vuln_elem: ET.Element, attribute: str) -> str:
        """Extract STIG_DATA by VULN_ATTRIBUTE name."""
        for stig_data in vuln_elem.findall("STIG_DATA"):
            vuln_attr = stig_data.find("VULN_ATTRIBUTE")
            if vuln_attr is not None and vuln_attr.text == attribute:
                attr_data = stig_data.find("ATTRIBUTE_DATA")
                if attr_data is not None:
                    return attr_data.text
        return None
    
    def _normalize_severity(self, severity_raw: str) -> str:
        """Normalize severity to CAT I/II/III."""
        if not severity_raw:
            return "CAT III"  # Default to lowest
        
        severity_lower = severity_raw.lower()
        if severity_lower in ["high", "cat i", "cat1", "category i"]:
            return "CAT I"
        elif severity_lower in ["medium", "cat ii", "cat2", "category ii"]:
            return "CAT II"
        elif severity_lower in ["low", "cat iii", "cat3", "category iii"]:
            return "CAT III"
        else:
            return "CAT III"  # Default
    
    def _normalize_status(self, status_raw: str) -> str:
        """Normalize status to Open/NotAFinding/Not_Reviewed/Not_Applicable."""
        if not status_raw:
            return "Not_Reviewed"
        
        status_lower = status_raw.lower().replace("_", "").replace(" ", "")
        if status_lower in ["open", "finding", "fail"]:
            return "Open"
        elif status_lower in ["notafinding", "pass"]:
            return "NotAFinding"
        elif status_lower in ["notapplicable", "na"]:
            return "Not_Applicable"
        else:
            return "Not_Reviewed"
