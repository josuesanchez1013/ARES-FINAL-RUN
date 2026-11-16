"""
CKL Generator for ARES.

Generates STIG Viewer-compatible CKL XML files from reconciled findings.
Used by both the generate_ckl MCP tool (Reporting Agent) and the Streamlit UI export.
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class CKLGenerator:
    """Generate STIG Viewer-compatible CKL XML from reconciled findings."""

    DEFAULT_ASSET = {
        "role": "None",
        "asset_type": "Computing",
        "host_name": "",
        "host_ip": "",
        "host_mac": "",
        "host_fqdn": "",
        "tech_area": "",
        "target_key": "",
        "marking": "CUI",
        "web_or_database": "false",
        "web_db_site": "",
        "web_db_instance": "",
        "target_comment": "",
    }

    DEFAULT_STIG_INFO = {
        "title": "Red Hat Enterprise Linux 8 Security Technical Implementation Guide",
        "version": "2",
        "releaseinfo": "Release: 7",
        "stigid": "RHEL_8_STIG",
        "classification": "UNCLASSIFIED",
        "customname": "",
        "description": "",
        "filename": "",
        "uuid": "",
        "notice": "terms-of-use",
        "source": "STIG.DOD.MIL",
    }

    VULN_ATTRIBUTES = [
        "Vuln_Num",
        "Severity",
        "Group_Title",
        "Rule_ID",
        "Rule_Ver",
        "Rule_Title",
        "Vuln_Discuss",
        "IA_Controls",
        "Check_Content",
        "Fix_Text",
        "False_Positives",
        "False_Negatives",
        "Documentable",
        "Mitigations",
        "Potential_Impact",
        "Third_Party_Tools",
        "Mitigation_Control",
        "Responsibility",
        "Security_Override_Guidance",
        "Check_Content_Ref",
        "Weight",
        "Class",
        "STIGRef",
        "TargetKey",
        "STIG_UUID",
        "CCI_REF",
    ]

    SEVERITY_TO_CKL = {
        "CAT I": "high",
        "CAT II": "medium",
        "CAT III": "low",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }

    VALID_STATUSES = {"Open", "NotAFinding", "Not_Reviewed", "Not_Applicable"}

    def generate(
        self,
        findings: List[Dict],
        metadata: Optional[Dict] = None,
        asset_info: Optional[Dict] = None,
    ) -> str:
        """Generate CKL XML string from reconciled findings."""
        metadata = metadata or {}
        asset_info = asset_info or {}

        root = ET.Element("CHECKLIST")
        self._build_asset(root, asset_info)
        stigs = ET.SubElement(root, "STIGS")
        istig = ET.SubElement(stigs, "iSTIG")
        self._build_stig_info(istig, metadata)

        for finding in findings:
            self._build_vuln(istig, finding, metadata)

        ET.indent(root, space="  ")
        xml_str = ET.tostring(root, encoding="unicode", xml_declaration=True)
        return xml_str

    def generate_to_file(
        self,
        findings: List[Dict],
        metadata: Optional[Dict] = None,
        asset_info: Optional[Dict] = None,
        output_dir: str = "/data/output",
    ) -> Path:
        """Generate CKL and write to file. Returns output path."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"reconciled_{timestamp}.ckl"
        filepath = output_path / filename

        xml_content = self.generate(findings, metadata, asset_info)
        filepath.write_text(xml_content, encoding="utf-8")

        return filepath

    def _build_asset(self, root: ET.Element, asset_info: Dict) -> None:
        asset_elem = ET.SubElement(root, "ASSET")

        merged = {**self.DEFAULT_ASSET, **asset_info}

        field_map = [
            ("role", "ROLE"),
            ("asset_type", "ASSET_TYPE"),
            ("marking", "MARKING"),
            ("host_name", "HOST_NAME"),
            ("host_ip", "HOST_IP"),
            ("host_mac", "HOST_MAC"),
            ("host_fqdn", "HOST_FQDN"),
            ("target_comment", "TARGET_COMMENT"),
            ("tech_area", "TECH_AREA"),
            ("target_key", "TARGET_KEY"),
            ("web_or_database", "WEB_OR_DATABASE"),
            ("web_db_site", "WEB_DB_SITE"),
            ("web_db_instance", "WEB_DB_INSTANCE"),
        ]

        for key, tag in field_map:
            elem = ET.SubElement(asset_elem, tag)
            elem.text = str(merged.get(key, ""))

    def _build_stig_info(self, istig: ET.Element, metadata: Dict) -> None:
        stig_info = ET.SubElement(istig, "STIG_INFO")

        merged = {**self.DEFAULT_STIG_INFO, **metadata}

        si_fields = [
            "version",
            "classification",
            "customname",
            "stigid",
            "description",
            "filename",
            "releaseinfo",
            "title",
            "uuid",
            "notice",
            "source",
        ]

        # Map metadata keys to SI_DATA names
        key_map = {
            "stig_title": "title",
            "release": "releaseinfo",
            "hostname": None,  # goes in ASSET, not here
            "reconciliation_date": None,
        }

        for field in si_fields:
            si_data = ET.SubElement(stig_info, "SI_DATA")
            sid_name = ET.SubElement(si_data, "SID_NAME")
            sid_name.text = field
            sid_data = ET.SubElement(si_data, "SID_DATA")

            # Check direct field match first, then mapped keys
            value = merged.get(field, "")
            if not value:
                for src_key, target in key_map.items():
                    if target == field and src_key in merged:
                        value = merged[src_key]
                        break
            sid_data.text = str(value) if value else ""

    def _build_vuln(self, istig: ET.Element, finding: Dict, metadata: Dict) -> None:
        vuln_elem = ET.SubElement(istig, "VULN")
        raw_data = finding.get("raw_data") or {}

        attr_values = self._extract_vuln_attributes(finding, raw_data, metadata)

        for attr_name in self.VULN_ATTRIBUTES:
            stig_data = ET.SubElement(vuln_elem, "STIG_DATA")
            vuln_attr = ET.SubElement(stig_data, "VULN_ATTRIBUTE")
            vuln_attr.text = attr_name
            attr_data = ET.SubElement(stig_data, "ATTRIBUTE_DATA")
            attr_data.text = attr_values.get(attr_name, "")

        # STATUS
        status_elem = ET.SubElement(vuln_elem, "STATUS")
        status = finding.get("final_status") or finding.get("status", "Not_Reviewed")
        status_elem.text = status if status in self.VALID_STATUSES else "Not_Reviewed"

        # FINDING_DETAILS
        details_elem = ET.SubElement(vuln_elem, "FINDING_DETAILS")
        details_elem.text = finding.get("finding_details", "") or ""

        # COMMENTS
        comments_elem = ET.SubElement(vuln_elem, "COMMENTS")
        comments_elem.text = self._build_comments(finding)

    def _extract_vuln_attributes(
        self, finding: Dict, raw_data: Dict, metadata: Dict
    ) -> Dict[str, str]:
        vuln_id = finding.get("vuln_id") or finding.get("group_id", "")
        severity = self.SEVERITY_TO_CKL.get(finding.get("severity", ""), "medium")

        stig_title = metadata.get("stig_title") or metadata.get("title", "")
        version = metadata.get("version", "")
        release = metadata.get("releaseinfo") or metadata.get("release", "")
        stig_ref = f"{stig_title} :: Version {version}, {release}" if stig_title else ""

        return {
            "Vuln_Num": vuln_id,
            "Severity": severity,
            "Group_Title": raw_data.get("group_title", ""),
            "Rule_ID": finding.get("rule_id", "") or "",
            "Rule_Ver": finding.get("stig_id", "") or raw_data.get("rule_ver", ""),
            "Rule_Title": finding.get("rule_title") or finding.get("title", "") or "",
            "Vuln_Discuss": finding.get("discussion", "") or "",
            "IA_Controls": raw_data.get("ia_controls", ""),
            "Check_Content": finding.get("check_text", "") or "",
            "Fix_Text": finding.get("fix_text", "") or "",
            "False_Positives": raw_data.get("false_positives", ""),
            "False_Negatives": raw_data.get("false_negatives", ""),
            "Documentable": raw_data.get("documentable", "false"),
            "Mitigations": raw_data.get("mitigations", ""),
            "Potential_Impact": raw_data.get("potential_impact", ""),
            "Third_Party_Tools": raw_data.get("third_party_tools", ""),
            "Mitigation_Control": raw_data.get("mitigation_control", ""),
            "Responsibility": raw_data.get("responsibility", ""),
            "Security_Override_Guidance": raw_data.get("security_override_guidance", ""),
            "Check_Content_Ref": raw_data.get("check_content_ref", "M"),
            "Weight": raw_data.get("weight", "10.0"),
            "Class": finding.get("classification", "") or raw_data.get("class", "Unclass"),
            "STIGRef": stig_ref,
            "TargetKey": raw_data.get("target_key", ""),
            "STIG_UUID": raw_data.get("stig_uuid", ""),
            "CCI_REF": finding.get("cci", "") or "",
        }

    def _build_comments(self, finding: Dict) -> str:
        parts = []

        confidence = finding.get("ares_confidence") or finding.get("confidence_score")
        source = finding.get("validation_source") or finding.get("source")

        if confidence is not None or source:
            ares_info = "ARES reconciled"
            if source:
                ares_info += f" (source: {source}"
                if confidence is not None:
                    ares_info += f", confidence: {confidence}%"
                ares_info += ")"
            elif confidence is not None:
                ares_info += f" (confidence: {confidence}%)"
            parts.append(ares_info)

        original_comments = finding.get("comments")
        if original_comments:
            parts.append(original_comments)

        file_source = finding.get("file_source")
        if file_source:
            parts.append(f"Source file: {file_source}")

        return " | ".join(parts) if parts else ""
