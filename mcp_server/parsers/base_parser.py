"""
Base parser interface.

All parsers must inherit from this and implement parse().
"""

from abc import ABC, abstractmethod
from typing import List
from pathlib import Path
from ..schemas.finding_schema import Finding


class BaseParser(ABC):
    """Abstract base class for all scan output parsers."""
    
    @abstractmethod
    def parse(self, filepath: str) -> List[Finding]:
        """
        Parse scan output file and return list of normalized findings.
        
        Args:
            filepath: Absolute path to scan output file
            
        Returns:
            List of Finding objects in normalized schema
            
        Raises:
            FileNotFoundError: If filepath doesn't exist
            ValueError: If file format is invalid
            Exception: For other parsing errors
        """
        pass
    
    def _validate_file_exists(self, filepath: str) -> Path:
        """Validate file exists and is readable."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        if not path.is_file():
            raise ValueError(f"Path is not a file: {filepath}")
        return path
