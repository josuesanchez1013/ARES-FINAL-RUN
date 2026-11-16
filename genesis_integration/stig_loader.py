"""
STIG Loader - Parse RHEL_8_STIG_V2R7.md and extract Check Text.

This bypasses Genesis RAG and loads Check Text directly from the markdown file.
"""

import re
from pathlib import Path
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class STIGLoader:
    """Loads STIG Check Text from markdown file."""
    
    def __init__(self, stig_md_path: str):
        """
        Initialize STIG loader.
        
        Args:
            stig_md_path: Path to RHEL_8_STIG_V2R7.md
        """
        self.stig_md_path = Path(stig_md_path)
        self.stig_data: Dict[str, Dict] = {}
        self._load_stig_data()
    
    def _load_stig_data(self):
        """Parse markdown file and extract Check Text for each vuln_id."""
        if not self.stig_md_path.exists():
            logger.error(f"STIG markdown file not found: {self.stig_md_path}")
            return
        
        logger.info(f"Loading STIG data from {self.stig_md_path}")
        
        content = self.stig_md_path.read_text(encoding='utf-8')
        
        # Split by rule sections (## V-XXXXXX)
        rule_pattern = r'^## (V-\d+)$'
        sections = re.split(rule_pattern, content, flags=re.MULTILINE)
        
        # sections = ['header', 'V-230221', 'rule1 content', 'V-230222', 'rule2 content', ...]
        # Skip first element (document header)
        for i in range(1, len(sections), 2):
            if i + 1 >= len(sections):
                break
            
            vuln_id = sections[i].strip()
            rule_content = sections[i + 1]
            
            # Extract metadata
            rule_data = self._parse_rule_section(vuln_id, rule_content)
            if rule_data:
                self.stig_data[vuln_id] = rule_data
        
        logger.info(f"Loaded {len(self.stig_data)} STIG rules from markdown")
    
    def _parse_rule_section(self, vuln_id: str, content: str) -> Optional[Dict]:
        """Parse a single rule section and extract metadata."""
        try:
            # Extract Rule ID
            rule_id_match = re.search(r'\*\*Rule ID:\*\*\s+(.+?)$', content, re.MULTILINE)
            rule_id = rule_id_match.group(1).strip() if rule_id_match else 'Unknown'
            
            # Extract STIG ID
            stig_id_match = re.search(r'\*\*STIG ID:\*\*\s+(.+?)$', content, re.MULTILINE)
            stig_id = stig_id_match.group(1).strip() if stig_id_match else 'Unknown'
            
            # Extract Severity
            severity_match = re.search(r'\*\*Severity:\*\*\s+(.+?)$', content, re.MULTILINE)
            severity = severity_match.group(1).strip() if severity_match else 'Unknown'
            
            # Extract Rule Title
            title_match = re.search(r'\*\*Rule Title:\*\*\s+(.+?)$', content, re.MULTILINE)
            title = title_match.group(1).strip() if title_match else 'Unknown rule'
            
            # Extract Discussion
            discussion_match = re.search(
                r'\*\*Discussion:\*\*\n(.*?)\n\*\*Check Text:\*\*',
                content,
                re.DOTALL
            )
            discussion = discussion_match.group(1).strip() if discussion_match else ''
            
            # Extract Check Text (between **Check Text:** and **Fix Text:**)
            check_text_match = re.search(
                r'\*\*Check Text:\*\*\n```\n(.*?)\n```',
                content,
                re.DOTALL
            )
            check_text = check_text_match.group(1).strip() if check_text_match else ''
            
            # Extract Fix Text
            fix_text_match = re.search(
                r'\*\*Fix Text:\*\*\n```\n(.*?)\n```',
                content,
                re.DOTALL
            )
            fix_text = fix_text_match.group(1).strip() if fix_text_match else ''
            
            return {
                'vuln_id': vuln_id,
                'rule_id': rule_id,
                'stig_id': stig_id,
                'severity': severity,
                'rule_title': title,
                'discussion': discussion,
                'check_text': check_text,
                'fix_text': fix_text,
            }
        
        except Exception as e:
            logger.error(f"Failed to parse rule {vuln_id}: {e}")
            return None
    
    def get_check_text(self, vuln_id: str) -> Optional[str]:
        """
        Get Check Text for a specific vuln_id.
        
        Args:
            vuln_id: Vulnerability ID (e.g., 'V-230221')
        
        Returns:
            Check Text string or None if not found
        """
        rule = self.stig_data.get(vuln_id)
        if rule:
            return rule.get('check_text')
        return None
    
    def get_rule_data(self, vuln_id: str) -> Optional[Dict]:
        """
        Get complete rule data for a specific vuln_id.
        
        Args:
            vuln_id: Vulnerability ID (e.g., 'V-230221')
        
        Returns:
            Dict with all rule metadata or None if not found
        """
        return self.stig_data.get(vuln_id)
    
    def get_all_vuln_ids(self) -> list:
        """Get list of all vulnerability IDs in the STIG."""
        return list(self.stig_data.keys())


# Singleton instance for easy access
_stig_loader_instance = None

# Set by the ARES API for the length of one run step when the run uses STIG
# content imported into the STIG library (see stig_library/). Anything with
# get_rule_data / get_check_text / get_all_vuln_ids works.
_stig_loader_override = None


def set_stig_loader_override(loader) -> None:
    """Serve `loader` from get_stig_loader() until cleared with None."""
    global _stig_loader_override
    _stig_loader_override = loader


def get_stig_loader(stig_md_path: Optional[str] = None) -> STIGLoader:
    """
    Get singleton STIGLoader instance.
    
    Args:
        stig_md_path: Path to STIG markdown file (only needed for first call)
    
    Returns:
        STIGLoader instance
    """
    global _stig_loader_instance

    if _stig_loader_override is not None:
        return _stig_loader_override

    if _stig_loader_instance is None:
        if stig_md_path is None:
            # Default path
            project_root = Path(__file__).parent.parent
            stig_md_path = project_root / "data" / "input" / "RHEL_8_STIG_V2R7.md"
        
        _stig_loader_instance = STIGLoader(str(stig_md_path))
    
    return _stig_loader_instance
