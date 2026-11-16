"""
pytest configuration and fixtures for ARES tests.
"""

import pytest
from pathlib import Path


@pytest.fixture
def test_data_dir():
    """Path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_ckl_file(test_data_dir):
    """Path to sample CKL (XML) file for testing."""
    return test_data_dir / "sample-tool1.ckl"


@pytest.fixture
def sample_csv_file(test_data_dir):
    """Path to sample CSV file."""
    return test_data_dir / "sample-tool2.csv"


@pytest.fixture
def real_data_dir():
    """Path to real RHEL 8 scan files."""
    return Path(__file__).parent.parent / "data" / "input"


@pytest.fixture
def prestige_ckl_file(real_data_dir):
    """Path to real PreSTIGe CKL file."""
    return real_data_dir / "rhel8-prestige-auto.ckl"


@pytest.fixture
def prestige_csv_file(real_data_dir):
    """Path to real PreSTIGe CSV file."""
    return real_data_dir / "rhel8-prestige-auto.csv"


@pytest.fixture
def evaluatestig_ckl_file(real_data_dir):
    """Path to real evaluate-STIG CKL file."""
    return real_data_dir / "rhel8-evaluatestig-remote-ansible.ckl"


@pytest.fixture
def evaluatestig_csv_file(real_data_dir):
    """Path to real evaluate-STIG CSV file."""
    return real_data_dir / "rhel8-evaluatestig-remote-ansible.csv"


@pytest.fixture
def sample_findings():
    """Sample normalized findings for testing."""
    from mcp_server.schemas.finding_schema import Finding
    
    return [
        Finding(
            group_id="V-230221",
            rule_id="SV-230221r627750_rule",
            stig_id="RHEL-08-010000",
            severity="CAT I",
            classification="Unclassified",
            rule_title="RHEL 8 must prevent direct root login",
            discussion="Allowing direct root login is a security risk...",
            check_text="Verify root login is disabled: grep PermitRootLogin /etc/ssh/sshd_config",
            fix_text="Edit /etc/ssh/sshd_config and set PermitRootLogin no",
            cci="CCI-000366",
            status="Open",
            finding_details="PermitRootLogin is set to yes",
            comments=None,
            file_source="test.ckl",
            raw_data={}
        ),
        Finding(
            group_id="V-230222",
            rule_id="SV-230222r627750_rule",
            stig_id="RHEL-08-010010",
            severity="CAT II",
            classification="Unclassified",
            rule_title="RHEL 8 must enforce password complexity",
            discussion="Password complexity reduces brute force risk...",
            check_text="Verify password complexity: grep -E 'minlen|dcredit|ucredit' /etc/security/pwquality.conf",
            fix_text="Configure password complexity in /etc/security/pwquality.conf",
            cci="CCI-000192",
            status="NotAFinding",
            finding_details="Password complexity is configured",
            comments=None,
            file_source="test.ckl",
            raw_data={}
        ),
        Finding(
            group_id="V-230223",
            rule_id="SV-230223r627750_rule",
            stig_id="RHEL-08-010020",
            severity="CAT III",
            classification="Unclassified",
            rule_title="RHEL 8 must configure session timeout",
            discussion="Session timeouts prevent unauthorized access...",
            check_text="Verify timeout is set: grep TMOUT /etc/profile",
            fix_text="Add TMOUT=600 to /etc/profile",
            cci="CCI-000057",
            status="Not_Reviewed",
            finding_details=None,
            comments=None,
            file_source="test.ckl",
            raw_data={}
        )
    ]
