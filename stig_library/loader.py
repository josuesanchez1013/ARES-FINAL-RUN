"""
Adapter that serves imported library content through the same interface as
genesis_integration.stig_loader.STIGLoader, so the pipeline needs no changes.
"""

from typing import Any, Dict, List, Optional


class LibraryStigLoader:
    def __init__(self, entries: List[Dict[str, Any]]):
        self.entries = entries
        self.stig_data: Dict[str, Dict[str, Any]] = {}
        for entry in entries:
            for rule in entry["rules"]:
                self.stig_data.setdefault(rule["vuln_id"], {
                    "vuln_id": rule["vuln_id"],
                    "rule_id": rule["rule_id"],
                    "stig_id": rule["stig_id"],
                    "severity": rule["severity"],
                    "rule_title": rule["rule_title"],
                    "discussion": rule["discussion"],
                    "check_text": rule["check_text"],
                    "fix_text": rule["fix_text"],
                    "cci": ", ".join(rule.get("cci") or []),
                    "stig_title": entry["title"],
                    "stig_version": entry["version_label"],
                })

    def get_check_text(self, vuln_id: str) -> Optional[str]:
        rule = self.stig_data.get(vuln_id)
        return rule.get("check_text") if rule else None

    def get_rule_data(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        return self.stig_data.get(vuln_id)

    def get_all_vuln_ids(self) -> list:
        return list(self.stig_data.keys())
