"""Runtime configuration, read from environment variables on each call."""

import os
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_MODEL = "nemotron-3-ultra-550b-a55b"
CLASSIFICATIONS = ["Unclassified", "CUI", "Classified"]
REFUSED_CLASSIFICATIONS = {"Classified"}
DEFAULT_SENSITIVITY = ["PII", "Proprietary", "Export controlled", "Other"]
SENSITIVITY_NONE = "None"


def _csv(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(name, "")
    values = [v.strip() for v in raw.split(",") if v.strip()]
    return values or list(default)


def use_mock() -> bool:
    return os.environ.get("ARES_USE_MOCK", "false").lower() == "true"


def data_dir() -> Path:
    return Path(os.environ.get("ARES_DATA_DIR", str(PROJECT_ROOT / "data" / "runs")))


def stig_library_dir() -> Path:
    return Path(os.environ.get("ARES_STIG_LIBRARY_DIR",
                               str(PROJECT_ROOT / "data" / "stig_library")))


def targets_dir() -> Path:
    return Path(os.environ.get("ARES_TARGETS_DIR", str(PROJECT_ROOT / "data" / "targets")))


def scap_dir() -> Path:
    return Path(os.environ.get("ARES_SCAP_DIR", str(PROJECT_ROOT / "data" / "scap_scans")))


def stig_import_max_bytes() -> int:
    """Largest STIG upload accepted (the full DISA library zip is a few hundred MB)."""
    try:
        return max(1, int(os.environ.get("ARES_STIG_IMPORT_MAX_MB", "2048"))) * 1024 * 1024
    except ValueError:
        return 2048 * 1024 * 1024


def models() -> List[str]:
    return _csv("ARES_LLM_MODELS", [DEFAULT_MODEL])


def sensitivity_categories() -> List[str]:
    return _csv("ARES_SENSITIVITY_CATEGORIES", DEFAULT_SENSITIVITY)


def retention() -> int:
    try:
        return max(1, int(os.environ.get("ARES_RUN_RETENTION", "50")))
    except ValueError:
        return 50


def mock_delay() -> float:
    try:
        return float(os.environ.get("ARES_MOCK_STEP_DELAY", "0.6"))
    except ValueError:
        return 0.6


def target() -> Dict[str, str]:
    return {
        "host_name": os.environ.get("ARES_TARGET_HOST", "rhel8-stig-lab"),
        "host_ip": os.environ.get("ARES_TARGET_IP", "10.0.2.15"),
    }


def stig() -> Dict[str, str]:
    return {
        "title": os.environ.get("ARES_STIG_TITLE", "RHEL 8 STIG"),
        "version": os.environ.get("ARES_STIG_VERSION", "V2R7"),
        "source": os.environ.get("ARES_STIG_SOURCE", "Bundled STIG markdown (no RAG)"),
    }


def mcp_server_url() -> str:
    return os.environ.get("MCP_SERVER_URL", "")
