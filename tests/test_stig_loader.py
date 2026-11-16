"""Offline tests for the STIG loader (markdown-based STIG content).

Converted from the ad-hoc root-level test_stig_loader.py script into a real,
collectible pytest module. Runs offline (reads the local RHEL 8 STIG markdown).
"""

import pytest

from genesis_integration.stig_loader import get_stig_loader


@pytest.fixture(scope="module")
def loader():
    return get_stig_loader()


def test_loader_loads_rules(loader):
    """The loader should parse a non-trivial number of RHEL 8 STIG rules."""
    vuln_ids = loader.get_all_vuln_ids()
    assert isinstance(vuln_ids, list)
    assert len(vuln_ids) > 100  # RHEL 8 STIG has hundreds of rules


def test_get_rule_data_shape(loader):
    """Any known rule should return the normalized fields agents rely on."""
    vuln_ids = loader.get_all_vuln_ids()
    if not vuln_ids:
        pytest.skip("No STIG rules loaded in this environment")
    rule = loader.get_rule_data(vuln_ids[0])
    assert rule is not None
    # Fields downstream agents depend on (may be empty string but must exist as keys)
    for key in ("rule_title", "severity", "rule_id", "check_text"):
        assert key in rule


def test_unknown_rule_returns_none(loader):
    assert loader.get_rule_data("V-000000-does-not-exist") is None
