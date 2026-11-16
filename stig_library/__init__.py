"""
STIG library: import DISA STIG content (XCCDF benchmarks and SCAP data
streams) from DoD Cyber Exchange downloads and serve it to the pipeline.

- xccdf.py    parse one XCCDF benchmark or SCAP data stream into plain dicts
- archive.py  walk an uploaded zip (including zips nested inside it) safely
- library.py  versioned on-disk store, change reports, scan matching
- loader.py   adapter with the same interface as genesis_integration.stig_loader
"""

from .library import StigLibrary, ImportError_ as StigImportError  # noqa: F401
from .loader import LibraryStigLoader  # noqa: F401
