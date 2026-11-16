"""Tests for the CKL Generator."""

import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_server.generators.ckl_generator import CKLGenerator
from mcp_server.parsers.ckl_parser import CKLParser


@pytest.fixture
def generator():
    return CKLGenerator()


@pytest.fixture
def sample_metadata():
    return {
        "stig_title": "Red Hat Enterprise Linux 8 Security Technical Implementation Guide",
        "version": "2",
        "releaseinfo": "Release: 7 Benchmark Date: 01 Apr 2026",
        "stigid": "RHEL_8_STIG",
    }


@pytest.fixture
def sample_asset():
    return {
        "host_name": "rhel8-stig-lab",
        "host_ip": "192.168.56.102",
        "host_mac": "08:00:27:9b:9a:08",
        "host_fqdn": "rhel8-stig-lab",
        "tech_area": "UNIX",
        "target_key": "5446",
    }


@pytest.fixture
def minimal_findings():
    return [
        {"vuln_id": "V-230221", "status": "Open", "severity": "CAT I"},
        {"vuln_id": "V-230222", "status": "NotAFinding", "severity": "CAT II"},
        {"vuln_id": "V-230223", "status": "Not_Reviewed", "severity": "CAT III"},
    ]


@pytest.fixture
def full_findings():
    return [
        {
            "vuln_id": "V-230221",
            "group_id": "V-230221",
            "rule_id": "SV-230221r1017040_rule",
            "stig_id": "RHEL-08-010000",
            "severity": "CAT I",
            "classification": "Unclass",
            "rule_title": "RHEL 8 must be a vendor-supported release.",
            "discussion": "An operating system release is considered supported if the vendor continues to provide security patches.",
            "check_text": "Verify the version of the operating system is vendor supported.",
            "fix_text": "Upgrade to a supported version of RHEL 8.",
            "cci": "CCI-000366",
            "status": "NotAFinding",
            "final_status": "NotAFinding",
            "finding_details": "Red Hat Enterprise Linux release 8.10 (Ootpa)",
            "comments": "Validated via cat /etc/redhat-release",
            "ares_confidence": 95,
            "validation_source": "determination_agent",
            "file_source": "rhel8-prestige-auto.ckl",
            "raw_data": {"original_severity": "high", "original_status": "NotAFinding"},
        }
    ]


class TestCKLGeneratorBasic:
    def test_produces_valid_xml(self, generator, minimal_findings):
        xml_str = generator.generate(minimal_findings)
        root = ET.fromstring(xml_str)
        assert root.tag == "CHECKLIST"

    def test_correct_vuln_count(self, generator, minimal_findings):
        xml_str = generator.generate(minimal_findings)
        root = ET.fromstring(xml_str)
        vulns = root.findall(".//VULN")
        assert len(vulns) == 3

    def test_xml_declaration_present(self, generator, minimal_findings):
        xml_str = generator.generate(minimal_findings)
        assert xml_str.startswith("<?xml")

    def test_empty_findings_produces_valid_xml(self, generator):
        xml_str = generator.generate([])
        root = ET.fromstring(xml_str)
        vulns = root.findall(".//VULN")
        assert len(vulns) == 0


class TestAssetSection:
    def test_default_asset_fields(self, generator, minimal_findings):
        xml_str = generator.generate(minimal_findings)
        root = ET.fromstring(xml_str)
        asset = root.find("ASSET")
        assert asset is not None
        assert asset.find("ROLE").text == "None"
        assert asset.find("ASSET_TYPE").text == "Computing"
        assert asset.find("MARKING").text == "CUI"

    def test_custom_asset_info(self, generator, minimal_findings, sample_asset):
        xml_str = generator.generate(minimal_findings, asset_info=sample_asset)
        root = ET.fromstring(xml_str)
        asset = root.find("ASSET")
        assert asset.find("HOST_NAME").text == "rhel8-stig-lab"
        assert asset.find("HOST_IP").text == "192.168.56.102"
        assert asset.find("HOST_MAC").text == "08:00:27:9b:9a:08"
        assert asset.find("TECH_AREA").text == "UNIX"
        assert asset.find("TARGET_KEY").text == "5446"

    def test_all_asset_fields_present(self, generator, minimal_findings):
        xml_str = generator.generate(minimal_findings)
        root = ET.fromstring(xml_str)
        asset = root.find("ASSET")
        expected_tags = [
            "ROLE", "ASSET_TYPE", "MARKING", "HOST_NAME", "HOST_IP",
            "HOST_MAC", "HOST_FQDN", "TARGET_COMMENT", "TECH_AREA",
            "TARGET_KEY", "WEB_OR_DATABASE", "WEB_DB_SITE", "WEB_DB_INSTANCE",
        ]
        for tag in expected_tags:
            assert asset.find(tag) is not None, f"Missing ASSET field: {tag}"


class TestStigInfoSection:
    def test_stig_info_present(self, generator, minimal_findings, sample_metadata):
        xml_str = generator.generate(minimal_findings, sample_metadata)
        root = ET.fromstring(xml_str)
        stig_info = root.find(".//STIG_INFO")
        assert stig_info is not None

    def test_all_si_data_entries(self, generator, minimal_findings, sample_metadata):
        xml_str = generator.generate(minimal_findings, sample_metadata)
        root = ET.fromstring(xml_str)
        stig_info = root.find(".//STIG_INFO")
        si_data_entries = stig_info.findall("SI_DATA")
        expected_fields = [
            "version", "classification", "customname", "stigid",
            "description", "filename", "releaseinfo", "title", "uuid",
            "notice", "source",
        ]
        assert len(si_data_entries) == len(expected_fields)

    def test_metadata_values_populated(self, generator, minimal_findings, sample_metadata):
        xml_str = generator.generate(minimal_findings, sample_metadata)
        root = ET.fromstring(xml_str)
        stig_info = root.find(".//STIG_INFO")

        for si_data in stig_info.findall("SI_DATA"):
            sid_name = si_data.find("SID_NAME").text
            sid_data = si_data.find("SID_DATA").text or ""
            if sid_name == "stigid":
                assert sid_data == "RHEL_8_STIG"
            elif sid_name == "version":
                assert sid_data == "2"


class TestVulnElements:
    def test_26_stig_data_per_vuln(self, generator, minimal_findings):
        xml_str = generator.generate(minimal_findings)
        root = ET.fromstring(xml_str)
        for vuln in root.findall(".//VULN"):
            stig_data_count = len(vuln.findall("STIG_DATA"))
            assert stig_data_count == 26

    def test_vuln_num_from_vuln_id(self, generator, minimal_findings):
        xml_str = generator.generate(minimal_findings)
        root = ET.fromstring(xml_str)
        vuln = root.findall(".//VULN")[0]
        first_attr = vuln.find("STIG_DATA")
        assert first_attr.find("VULN_ATTRIBUTE").text == "Vuln_Num"
        assert first_attr.find("ATTRIBUTE_DATA").text == "V-230221"

    def test_vuln_num_from_group_id_fallback(self, generator):
        findings = [{"group_id": "V-999999", "status": "Open", "severity": "CAT II"}]
        xml_str = generator.generate(findings)
        root = ET.fromstring(xml_str)
        vuln = root.find(".//VULN")
        first_attr = vuln.find("STIG_DATA")
        assert first_attr.find("ATTRIBUTE_DATA").text == "V-999999"

    def test_full_metadata_in_vuln(self, generator, full_findings, sample_metadata):
        xml_str = generator.generate(full_findings, sample_metadata)
        root = ET.fromstring(xml_str)
        vuln = root.find(".//VULN")

        attrs = {}
        for sd in vuln.findall("STIG_DATA"):
            key = sd.find("VULN_ATTRIBUTE").text
            val = sd.find("ATTRIBUTE_DATA").text or ""
            attrs[key] = val

        assert attrs["Rule_ID"] == "SV-230221r1017040_rule"
        assert attrs["Rule_Ver"] == "RHEL-08-010000"
        assert attrs["Rule_Title"] == "RHEL 8 must be a vendor-supported release."
        assert "vendor" in attrs["Vuln_Discuss"]
        assert "Verify" in attrs["Check_Content"]
        assert "Upgrade" in attrs["Fix_Text"]
        assert attrs["CCI_REF"] == "CCI-000366"


class TestStatusMapping:
    @pytest.mark.parametrize("status", ["Open", "NotAFinding", "Not_Reviewed", "Not_Applicable"])
    def test_valid_statuses(self, generator, status):
        findings = [{"vuln_id": "V-000001", "status": status, "severity": "CAT II"}]
        xml_str = generator.generate(findings)
        root = ET.fromstring(xml_str)
        status_elem = root.find(".//VULN/STATUS")
        assert status_elem.text == status

    def test_final_status_takes_priority(self, generator):
        findings = [{
            "vuln_id": "V-000001",
            "status": "Not_Reviewed",
            "final_status": "Open",
            "severity": "CAT II",
        }]
        xml_str = generator.generate(findings)
        root = ET.fromstring(xml_str)
        assert root.find(".//VULN/STATUS").text == "Open"

    def test_invalid_status_defaults_to_not_reviewed(self, generator):
        findings = [{"vuln_id": "V-000001", "status": "InvalidStatus", "severity": "CAT II"}]
        xml_str = generator.generate(findings)
        root = ET.fromstring(xml_str)
        assert root.find(".//VULN/STATUS").text == "Not_Reviewed"


class TestSeverityMapping:
    @pytest.mark.parametrize("severity,expected", [
        ("CAT I", "high"),
        ("CAT II", "medium"),
        ("CAT III", "low"),
    ])
    def test_severity_mapping(self, generator, severity, expected):
        findings = [{"vuln_id": "V-000001", "status": "Open", "severity": severity}]
        xml_str = generator.generate(findings)
        root = ET.fromstring(xml_str)
        vuln = root.find(".//VULN")
        for sd in vuln.findall("STIG_DATA"):
            if sd.find("VULN_ATTRIBUTE").text == "Severity":
                assert sd.find("ATTRIBUTE_DATA").text == expected


class TestComments:
    def test_ares_confidence_in_comments(self, generator, full_findings):
        xml_str = generator.generate(full_findings)
        root = ET.fromstring(xml_str)
        comments = root.find(".//VULN/COMMENTS").text
        assert "95%" in comments
        assert "determination_agent" in comments

    def test_original_comments_preserved(self, generator, full_findings):
        xml_str = generator.generate(full_findings)
        root = ET.fromstring(xml_str)
        comments = root.find(".//VULN/COMMENTS").text
        assert "cat /etc/redhat-release" in comments

    def test_file_source_in_comments(self, generator, full_findings):
        xml_str = generator.generate(full_findings)
        root = ET.fromstring(xml_str)
        comments = root.find(".//VULN/COMMENTS").text
        assert "rhel8-prestige-auto.ckl" in comments

    def test_empty_comments_when_no_metadata(self, generator, minimal_findings):
        xml_str = generator.generate(minimal_findings)
        root = ET.fromstring(xml_str)
        comments = root.find(".//VULN/COMMENTS").text or ""
        assert comments == ""


class TestXMLEscaping:
    def test_special_chars_in_finding_details(self, generator):
        findings = [{
            "vuln_id": "V-000001",
            "status": "Open",
            "severity": "CAT II",
            "finding_details": 'Config <bad> & "unsafe" value',
        }]
        xml_str = generator.generate(findings)
        # Should not throw — ElementTree handles escaping
        root = ET.fromstring(xml_str)
        details = root.find(".//VULN/FINDING_DETAILS").text
        assert "<bad>" in details
        assert '"unsafe"' in details

    def test_special_chars_in_rule_title(self, generator):
        findings = [{
            "vuln_id": "V-000001",
            "status": "Open",
            "severity": "CAT II",
            "rule_title": "Rule with <angle> & 'quotes'",
        }]
        xml_str = generator.generate(findings)
        root = ET.fromstring(xml_str)
        vuln = root.find(".//VULN")
        for sd in vuln.findall("STIG_DATA"):
            if sd.find("VULN_ATTRIBUTE").text == "Rule_Title":
                assert "<angle>" in sd.find("ATTRIBUTE_DATA").text


class TestPerformance:
    def test_366_findings_under_2_seconds(self, generator, sample_metadata, sample_asset):
        findings = [
            {"vuln_id": f"V-{230221 + i}", "status": "Open", "severity": "CAT II",
             "rule_title": f"Rule {i}", "finding_details": f"Details for finding {i}"}
            for i in range(366)
        ]
        start = time.time()
        xml_str = generator.generate(findings, sample_metadata, sample_asset)
        elapsed = time.time() - start
        assert elapsed < 2.0, f"Generation took {elapsed:.2f}s (max 2s)"
        root = ET.fromstring(xml_str)
        assert len(root.findall(".//VULN")) == 366


class TestRoundtrip:
    def test_roundtrip_with_real_data(self, generator, sample_metadata, sample_asset):
        parser = CKLParser()
        ckl_path = Path(__file__).parent.parent / "data" / "input" / "rhel8-prestige-auto.ckl"
        original = parser.parse(str(ckl_path))
        finding_dicts = [f.model_dump() for f in original]
        for d in finding_dicts:
            d["vuln_id"] = d["group_id"]

        xml_str = generator.generate(finding_dicts, sample_metadata, sample_asset)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ckl", delete=False, encoding="utf-8"
        ) as f:
            f.write(xml_str)
            tmp_path = f.name

        try:
            reparsed = parser.parse(tmp_path)
            assert len(reparsed) == len(original)

            for orig, reparse in zip(original, reparsed):
                assert orig.group_id == reparse.group_id
                assert orig.status == reparse.status
                assert orig.severity == reparse.severity
        finally:
            Path(tmp_path).unlink()

    def test_roundtrip_with_minimal_data(self, generator):
        findings = [
            {"vuln_id": "V-230221", "status": "Open", "severity": "CAT I"},
            {"vuln_id": "V-230222", "status": "NotAFinding", "severity": "CAT II"},
        ]
        xml_str = generator.generate(findings)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ckl", delete=False, encoding="utf-8"
        ) as f:
            f.write(xml_str)
            tmp_path = f.name

        try:
            parser = CKLParser()
            reparsed = parser.parse(tmp_path)
            assert len(reparsed) == 2
            assert reparsed[0].group_id == "V-230221"
            assert reparsed[0].status == "Open"
            assert reparsed[1].group_id == "V-230222"
            assert reparsed[1].status == "NotAFinding"
        finally:
            Path(tmp_path).unlink()


class TestGenerateToFile:
    def test_writes_file(self, generator, minimal_findings, sample_metadata):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generator.generate_to_file(
                minimal_findings, sample_metadata, output_dir=tmpdir
            )
            assert path.exists()
            assert path.suffix == ".ckl"
            content = path.read_text(encoding="utf-8")
            assert content.startswith("<?xml")

    def test_filename_contains_timestamp(self, generator, minimal_findings):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = generator.generate_to_file(minimal_findings, output_dir=tmpdir)
            assert "reconciled_" in path.name


class TestHumanOverrides:
    def test_override_applied_via_final_status(self, generator):
        findings = [{
            "vuln_id": "V-000001",
            "status": "Not_Reviewed",
            "final_status": "NotAFinding",
            "severity": "CAT II",
        }]
        xml_str = generator.generate(findings)
        root = ET.fromstring(xml_str)
        assert root.find(".//VULN/STATUS").text == "NotAFinding"
