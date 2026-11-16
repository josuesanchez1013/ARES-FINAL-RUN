"""
Mock Agent Responses for ARES UI Development

Provides realistic pre-canned data that mimics what Genesis agents would return.
Used when use_mock=True in the orchestrator runner (before MCP/agents are live).

Data is based on the sample parser output (5 findings per tool) and produces
realistic pipeline results for UI development and demo mode.
"""


MOCK_GAP_COVERAGE_OUTPUT = [
    {
        "vuln_id": "V-230225",
        "rule_id": "SV-230225r627750_rule",
        "severity": "high",
        "status": "NotAFinding",
        "finding_details": "Symlink protection enabled. fs.protected_symlinks = 1",
        "confidence_score": 92,
        "validation_source": "gap_coverage_agent",
        "commands_executed": [
            "sysctl fs.protected_symlinks",
            "cat /proc/sys/fs/protected_symlinks",
        ],
        "command_outputs": [
            "fs.protected_symlinks = 1",
            "1",
        ],
    },
    {
        "vuln_id": "V-230226",
        "rule_id": "SV-230226r627750_rule",
        "severity": "medium",
        "status": "Open",
        "finding_details": "SELinux is in permissive mode. STIG requires enforcing mode.",
        "confidence_score": 97,
        "validation_source": "gap_coverage_agent",
        "commands_executed": [
            "getenforce",
            "grep ^SELINUX= /etc/selinux/config",
        ],
        "command_outputs": [
            "Permissive",
            "SELINUX=permissive",
        ],
    },
]


MOCK_DETERMINATION_OUTPUT = [
    {
        "vuln_id": "V-230221",
        "rule_id": "SV-230221r627750_rule",
        "severity": "high",
        "tool1_status": "Open",
        "tool2_status": "NotAFinding",
        "ares_verdict": "Open",
        "confidence_score": 88,
        "evidence": "yum check-update shows 3 security patches pending. Last update was 45 days ago per rpm -qa --last.",  # noqa: E501
        "tool1_correct": True,
        "tool2_correct": False,
        "tool2_error_type": "false_negative",
        "validation_source": "determination_agent",
        "commands_executed": [
            "yum check-update --security",
            "rpm -qa --last | head -5",
        ],
        "command_outputs": [
            "kernel-4.18.0-553.el8_10.x86_64   updates\nbind-utils-9.11.36-16.el8_10.1.x86_64   updates\nopenssl-1.1.1k-14.el8_10.x86_64   updates",  # noqa: E501
            "gpg-pubkey-fd431d51-4ae0493b   Wed 22 May 2026\nkernel-4.18.0-513.el8.x86_64   Mon 25 May 2026",
        ],
    },
]


MOCK_REPORTING_OUTPUT = {
    "reconciled_findings": [
        {
            "vuln_id": "V-230221",
            "rule_id": "SV-230221r627750_rule",
            "severity": "high",
            "final_status": "Open",
            "source": "determination_agent",
            "confidence_score": 88,
            "tool1_status": "Open",
            "tool2_status": "NotAFinding",
        },
        {
            "vuln_id": "V-230222",
            "rule_id": "SV-230222r627750_rule",
            "severity": "medium",
            "final_status": "NotAFinding",
            "source": "agreement",
            "confidence_score": 100,
            "tool1_status": "NotAFinding",
            "tool2_status": "NotAFinding",
        },
        {
            "vuln_id": "V-230223",
            "rule_id": "SV-230223r627750_rule",
            "severity": "medium",
            "final_status": "Open",
            "source": "agreement",
            "confidence_score": 100,
            "tool1_status": "Open",
            "tool2_status": "Open",
        },
        {
            "vuln_id": "V-230224",
            "rule_id": "SV-230224r627750_rule",
            "severity": "low",
            "final_status": "NotAFinding",
            "source": "agreement",
            "confidence_score": 100,
            "tool1_status": "NotAFinding",
            "tool2_status": "NotAFinding",
        },
        {
            "vuln_id": "V-230225",
            "rule_id": "SV-230225r627750_rule",
            "severity": "high",
            "final_status": "NotAFinding",
            "source": "gap_coverage_agent",
            "confidence_score": 92,
            "tool1_status": "Not_Reviewed",
            "tool2_status": None,
        },
        {
            "vuln_id": "V-230226",
            "rule_id": "SV-230226r627750_rule",
            "severity": "medium",
            "final_status": "Open",
            "source": "gap_coverage_agent",
            "confidence_score": 97,
            "tool1_status": None,
            "tool2_status": "Open",
        },
    ],
    "metrics": {
        "total_rules": 6,
        "agreements": 3,
        "disagreements_resolved": 1,
        "gaps_filled": 2,
        "open_count": 3,
        "not_a_finding_count": 3,
        "requires_review": 1,
        "avg_confidence": 93.2,
        "time_elapsed_seconds": 18.4,
    },
    "review_queue": [
        {
            "vuln_id": "V-230221",
            "rule_id": "SV-230221r627750_rule",
            "severity": "high",
            "ares_verdict": "Open",
            "confidence_score": 88,
            "tool1_status": "Open",
            "tool2_status": "NotAFinding",
            "evidence": "yum check-update shows 3 security patches pending. Last update was 45 days ago per rpm -qa --last.",  # noqa: E501
            "reason": "CAT I finding with confidence < 90% requires human review",
        },
    ],
    "recommendations": [
        {
            "vuln_id": "V-230221",
            "severity": "high",
            "recommendation": "Apply pending security patches: yum update --security",
            "effort": "Low",
        },
        {
            "vuln_id": "V-230223",
            "severity": "medium",
            "recommendation": "Set minimum password length to 15: authconfig --passminlen=15 --update",
            "effort": "Low",
        },
        {
            "vuln_id": "V-230226",
            "severity": "medium",
            "recommendation": "Set SELinux to enforcing: setenforce 1 && sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config",  # noqa: E501
            "effort": "Medium",
        },
    ],
}
