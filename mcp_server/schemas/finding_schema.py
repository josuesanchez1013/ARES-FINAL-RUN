"""
Normalized Finding schema for ARES.

All parsers must output findings in this format.
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Literal
from datetime import datetime


class Finding(BaseModel):
    """Normalized STIG finding across all tools.
    
    Contains comprehensive STIG metadata to support downstream agents:
    - Gap Coverage Agent needs check_text to understand how to validate via CLI
    - Determination Agent needs discussion for context on disagreements
    - Reporting Agent needs all fields for comprehensive output
    """
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "group_id": "V-230221",
                "rule_id": "SV-230221r627750_rule",
                "stig_id": "RHEL-08-010000",
                "severity": "CAT I",
                "classification": "Unclassified",
                "rule_title": "RHEL 8 must prevent direct root login",
                "discussion": "Allowing direct root login is a security risk...",
                "check_text": "Verify root login is disabled by running: grep PermitRootLogin /etc/ssh/sshd_config",
                "fix_text": "Edit /etc/ssh/sshd_config and set PermitRootLogin no",
                "cci": "CCI-000366",
                "status": "Open",
                "finding_details": "PermitRootLogin is set to yes",
                "comments": None,
                "tool_source": "PreSTIGe",
                "raw_data": {}
            }
        }
    )
    
    # STIG Metadata (from STIG XML/CSV)
    group_id: str = Field(..., description="STIG Group/Vuln ID (e.g., V-230221)")
    rule_id: Optional[str] = Field(None, description="STIG Rule ID (e.g., SV-230221r627750_rule)")
    stig_id: Optional[str] = Field(None, description="STIG-specific ID (e.g., RHEL-08-010000)")
    severity: Literal["CAT I", "CAT II", "CAT III"] = Field(..., description="Finding severity")
    classification: Optional[str] = Field(None, description="Classification level")
    rule_title: str = Field(..., description="Short description of requirement")
    discussion: Optional[str] = Field(None, description="Background/context for requirement")
    check_text: Optional[str] = Field(None, description="Instructions for verifying compliance")
    fix_text: Optional[str] = Field(None, description="Instructions for remediation (not used by agents)")
    cci: Optional[str] = Field(None, description="Control Correlation Identifier")
    
    # Scan Results (from tool output)
    status: Literal["Open", "NotAFinding", "Not_Reviewed", "Not_Applicable"] = Field(..., description="Finding status")
    finding_details: Optional[str] = Field(None, description="Evidence/explanation from tool")
    comments: Optional[str] = Field(None, description="Additional comments")
    
    # Metadata
    file_source: str = Field(..., description="Source filename (e.g., 'rhel8-prestige-auto.ckl')")
    raw_data: Optional[dict] = Field(None, description="Original data from tool for debugging")
