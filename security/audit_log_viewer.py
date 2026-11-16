"""
Audit Log Viewer for ARES.

Read and analyze audit logs.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
import csv
import datetime

logger = logging.getLogger(__name__)


def load_audit_log(log_file: str) -> List[Dict]:
    """
    Load audit log from JSONL file.
    
    Args:
        log_file: Path to audit log file
        
    Returns:
        List of log entries
    """
    # Logs are loading
    entries = []
    with open(log_file, 'r') as f:
        for line in f:
            entries.append(json.loads(line))
    return entries
    
    
log_audit = load_audit_log("/home/vagrant/Projects/ares-ai-intern-challenge/data/logs/audit_20260706_230520.jsonl")

print(log_audit)

def filter_by_rule(logs: List[Dict], rule_id: str) -> List[Dict]:
    """
    Filter log entries by STIG Rule ID.
    
    Args:
        logs: List of log entries
        rule_id: Rule ID to filter by
        
    Returns:
        Filtered log entries
    """
    # TODO: Implement filtering
    return [entry for entry in logs if entry.get("rule_id") == rule_id]
    

filtered_logs = filter_by_rule(log_audit,"V-230221")
print("filtered log test")
print(filtered_logs)


def filter_by_agent(logs: List[Dict], agent: str) -> List[Dict]:
    """
    Filter log entries by agent name.
    
    Args:
        logs: List of log entries
        agent: Agent name to filter by
        
    Returns:
        Filtered log entries
    """
    # TODO: Implement filtering
    return [entry for entry in logs if entry.get("agent") == agent]

filtered_logs_by_agent = filter_by_agent(log_audit,"CLI_Executor")
print("filtered log by AGENT")
print(filtered_logs_by_agent)


def export_audit_report(
    logs: List[Dict],
    output_dir: str = "reports",
    prefix: str = "audit",
    timestamp: bool = True,
    suffix: str = ".csv",
) -> Path:
   
   
    out_dir = Path(output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

   
    if timestamp:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{ts}{suffix}"
    else:
        
        filename = f"{prefix}{suffix}"

    out_file = out_dir / filename

   
    if not logs:
        # Still create an *empty* file with a header (optional)
        
        with out_file.open("w", newline="", encoding="utf-8") as f:
            pass
        return out_file

    # Write the CSV
    with out_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)

    return out_file

csv_path = export_audit_report(log_audit)   
print(f"CSV written to: {csv_path}")

def get_summary_stats(logs: List[Dict]) -> Dict:
    """
    Get summary statistics from audit log.
    
    Args:
        logs: List of log entries
        
    Returns:
        Summary statistics dict
    """
    # TODO: Implement statistics
    return {
        "total_commands": len(logs),
        "unique_rules": len(set(entry["rule_id"] for entry in logs)),
        "agents": list(set(entry["agent"] for entry in logs)),
        "success_rate": sum(1 for entry in logs if entry["exit_code"] == 0) / len(logs)
    }
    

summary = get_summary_stats(log_audit)
print(summary)
