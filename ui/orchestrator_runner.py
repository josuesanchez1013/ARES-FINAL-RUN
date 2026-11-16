"""
Orchestrator Runner for ARES Streamlit UI

Thin orchestration layer that runs the ARES pipeline step by step,
updating st.session_state as each step completes.

Supports two modes:
- use_mock=True: Uses pre-canned responses for agents (dev/demo)
- use_mock=False: Calls real Genesis agents via API (production)

The two Python scripts (Gap Identifier, Comparison) always run locally
regardless of mode — they don't need an LLM.
"""

import json
import sys
import time
import logging
import os
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

import streamlit as st
import requests
import urllib3

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from genesis_integration.gap_identifier import identify_gaps
from genesis_integration.comparison_script import compare_findings
from genesis_integration.agent_client import (
    GenesisAgentClient,
    GenesisAgentError,
    AGENT_IDS,
)
from genesis_integration.local_agent_executor import LocalAgentExecutor
from genesis_integration.stig_loader import get_stig_loader
# Parsers removed - using production MCP workflow only (no local fallback)
from ui.mock_data import (
    MOCK_GAP_COVERAGE_OUTPUT,
    MOCK_DETERMINATION_OUTPUT,
    MOCK_REPORTING_OUTPUT,
)

logger = logging.getLogger(__name__)

# MCP Server Configuration
MCP_SERVER_URL = os.environ.get(
    'MCP_SERVER_URL',
    'https://mcp.example.internal'
)

# SSL Configuration (for Genesis API)
SSL_CERT_FILE = os.environ.get('SSL_CERT_FILE', '')
if SSL_CERT_FILE:
    os.environ['REQUESTS_CA_BUNDLE'] = SSL_CERT_FILE
    os.environ['CURL_CA_BUNDLE'] = SSL_CERT_FILE

# MCP tools each agent is allowed to call autonomously
AGENT_TOOLS = {
    "parser": ["parse_ckl", "parse_csv"],
    "gap_coverage": ["query_genesis_rag", "execute_command"],
    "determination": ["query_genesis_rag", "execute_command"],
    "reporting": ["query_genesis_rag"],
}

# Lazy-initialized client (created on first real agent call)
_genesis_client: GenesisAgentClient | None = None


def _get_client() -> GenesisAgentClient:
    global _genesis_client
    if _genesis_client is None:
        _genesis_client = GenesisAgentClient()
    return _genesis_client


STEP_DEFINITIONS = [
    {
        "name": "Parser Agent",
        "key": "parser_output",
        "type": "agent",
        "description": "Normalizing scan files to common schema via MCP tools",
    },
    {
        "name": "Gap Identifier",
        "key": "identified_gaps",
        "type": "script",
        "description": "Finding all Not_Reviewed items (Python script)",
    },
    {
        "name": "Gap Coverage Agent",
        "key": "gap_coverage_results",
        "type": "agent",
        "has_cli": True,
        "description": "Validating gaps via RAG + CLI execution on target system",
    },
    {
        "name": "Comparison Script",
        "key": "comparison_output",
        "type": "script",
        "description": "Categorizing agreements and disagreements (Python script)",
    },
    {
        "name": "Determination Agent",
        "key": "determination_output",
        "type": "agent",
        "has_cli": True,
        "description": "Resolving all disagreements via RAG + CLI execution",
    },
    {
        "name": "Reporting Agent",
        "key": "final_report",
        "type": "agent",
        "description": "Generating reconciled CKL, metrics, and recommendations",
    },
]


def run_pipeline(use_mock: bool = True) -> Dict[str, Any]:
    """
    Run the full ARES pipeline, updating session state at each step.
    
    DEPRECATED: Use execute_next_step() instead for real-time progress.
    This function runs all steps at once and doesn't show intermediate progress.

    Args:
        use_mock: If True, use mock data for agent steps. If False, call Genesis API.

    Returns:
        Final report dict (also stored in st.session_state.final_report)
    """
    start_time = time.time()

    # Initialize step timing and clear any prior error
    if "step_durations" not in st.session_state:
        st.session_state.step_durations = {}
    st.session_state.pipeline_error = None

    results = {}

    try:
        # Step 0: Parser Agent
        step_start = time.time()
        results["parser"] = _run_parser(use_mock)
        st.session_state.parser_output = results["parser"]
        st.session_state.step_durations["parser_output"] = time.time() - step_start
        st.session_state.workflow_step = 1

        # Step 1: Gap Identifier (always local Python)
        step_start = time.time()
        results["gap_identifier"] = _run_gap_identifier(results["parser"])
        st.session_state.identified_gaps = results["gap_identifier"]
        st.session_state.step_durations["identified_gaps"] = time.time() - step_start
        st.session_state.workflow_step = 2

        # Step 2: Gap Coverage Agent
        step_start = time.time()
        results["gap_coverage"] = _run_gap_coverage(results["gap_identifier"], use_mock)
        st.session_state.gap_coverage_results = results["gap_coverage"]
        st.session_state.step_durations["gap_coverage_results"] = time.time() - step_start
        st.session_state.workflow_step = 3

        # Step 3: Comparison Script (always local Python)
        step_start = time.time()
        results["comparison"] = _run_comparison(results["parser"], results["gap_coverage"])
        st.session_state.comparison_output = results["comparison"]
        st.session_state.step_durations["comparison_output"] = time.time() - step_start
        st.session_state.workflow_step = 4

        # Step 4: Determination Agent
        step_start = time.time()
        results["determination"] = _run_determination(results["comparison"], use_mock)
        st.session_state.determination_output = results["determination"]
        st.session_state.step_durations["determination_output"] = time.time() - step_start
        st.session_state.workflow_step = 5

        # Step 5: Reporting Agent
        step_start = time.time()
        results["reporting"] = _run_reporting(results, use_mock)
        st.session_state.final_report = results["reporting"]
        st.session_state.review_queue = results["reporting"].get("review_queue", [])
        st.session_state.step_durations["final_report"] = time.time() - step_start
        st.session_state.workflow_step = 6
        st.session_state.workflow_complete = True

    except Exception as e:
        logger.error(f"Pipeline failed at step {st.session_state.workflow_step}: {e}")
        st.session_state.pipeline_error = {
            "step": st.session_state.workflow_step,
            "error": str(e),
            "type": type(e).__name__,
        }
        return {}
    finally:
        st.session_state.pipeline_elapsed = time.time() - start_time

    return results["reporting"]


def execute_next_step(use_mock: bool = True) -> bool:
    """
    Execute the NEXT step in the pipeline based on current workflow_step.
    Returns True if more steps remain, False if workflow is complete.
    
    This allows the UI to show progress after each step.
    
    Args:
        use_mock: If True, use mock data for agent steps. If False, call Genesis API.
        
    Returns:
        True if there are more steps to execute, False if complete
    """
    current_step = st.session_state.workflow_step
    logger.info(f"Executing step {current_step}...")
    
    # Initialize step timing on first run
    if "step_durations" not in st.session_state:
        st.session_state.step_durations = {}
    if "pipeline_start_time" not in st.session_state:
        st.session_state.pipeline_start_time = time.time()
    
    step_start = time.time()
    
    try:
        if current_step == 0:
            # Step 0: Parser Agent (ALWAYS PRODUCTION - NO MOCK DATA)
            logger.info("Running Parser Agent (PRODUCTION MODE ONLY)...")
            result = _run_parser(use_mock=False)  # Force production mode
            st.session_state.parser_output = result
            st.session_state.step_durations["parser_output"] = time.time() - step_start
            st.session_state.workflow_step = 1
            logger.info(f"Parser complete: {len(result.get('tool1_findings', []))} + {len(result.get('tool2_findings', []))} findings")
            
        elif current_step == 1:
            # Step 1: Gap Identifier (ALWAYS PRODUCTION - NO MOCK DATA)
            logger.info("Running Gap Identifier (PRODUCTION MODE ONLY)...")
            result = _run_gap_identifier(st.session_state.parser_output)
            st.session_state.identified_gaps = result
            st.session_state.step_durations["identified_gaps"] = time.time() - step_start
            st.session_state.workflow_step = 2
            logger.info(f"Gap Identifier complete: {len(result)} gaps found")
            
        elif current_step == 2:
            # Step 2: Gap Coverage Agent
            logger.info("Running Gap Coverage Agent...")
            result = _run_gap_coverage(st.session_state.identified_gaps, use_mock)
            st.session_state.gap_coverage_results = result
            st.session_state.step_durations["gap_coverage_results"] = time.time() - step_start
            st.session_state.workflow_step = 3
            logger.info(f"Gap Coverage complete: {len(result)} gaps validated")
            
        elif current_step == 3:
            # Step 3: Comparison Script
            logger.info("Running Comparison Script...")
            result = _run_comparison(st.session_state.parser_output, st.session_state.gap_coverage_results)
            st.session_state.comparison_output = result
            st.session_state.step_durations["comparison_output"] = time.time() - step_start
            st.session_state.workflow_step = 4
            agreements = len(result.get("agreements", []))
            disagreements = len(result.get("disagreements", []))
            logger.info(f"Comparison complete: {agreements} agreements, {disagreements} disagreements")
            
        elif current_step == 4:
            # Step 4: Determination Agent
            logger.info("Running Determination Agent...")
            result = _run_determination(st.session_state.comparison_output, use_mock)
            st.session_state.determination_output = result
            st.session_state.step_durations["determination_output"] = time.time() - step_start
            st.session_state.workflow_step = 5
            logger.info(f"Determination complete: {len(result)} disagreements resolved")
            
        elif current_step == 5:
            # Step 5: Reporting Agent
            logger.info("Running Reporting Agent...")
            all_results = {
                "parser": st.session_state.parser_output,
                "gap_identifier": st.session_state.identified_gaps,
                "gap_coverage": st.session_state.gap_coverage_results,
                "comparison": st.session_state.comparison_output,
                "determination": st.session_state.determination_output,
            }
            result = _run_reporting(all_results, use_mock)
            st.session_state.final_report = result
            st.session_state.review_queue = result.get("review_queue", [])
            st.session_state.step_durations["final_report"] = time.time() - step_start
            st.session_state.workflow_step = 6
            st.session_state.workflow_complete = True
            st.session_state.pipeline_elapsed = time.time() - st.session_state.pipeline_start_time
            logger.info("Reporting complete: Workflow finished!")
            return False  # No more steps
            
        else:
            logger.warning(f"Invalid step number: {current_step}")
            return False
            
    except Exception as e:
        logger.error(f"Pipeline failed at step {current_step}: {type(e).__name__}: {e}", exc_info=True)
        st.session_state.pipeline_error = {
            "step": current_step,
            "step_name": STEP_DEFINITIONS[current_step]["name"],
            "error": str(e),
            "type": type(e).__name__,
        }
        st.session_state.workflow_started = False
        raise  # Re-raise so UI can catch and display
    
    # More steps remain
    return True


# LOCAL PARSING FALLBACK REMOVED
# Parser Agent must work via production MCP workflow:
# Upload to MCP → Genesis Agent → MCP parse tools → Download parsed files
# No local fallback allowed for production validation.


def _run_parser(use_mock: bool) -> Dict[str, Any]:
    """
    Run Parser Agent step with full MCP workflow.
    
    Production workflow (use_mock=False):
    1. Upload files to MCP server (POST /api/upload)
    2. Call Genesis Parser Agent with file paths
    3. Agent calls MCP parse tools → files written to /tmp/data/output/
    4. Download parsed JSON files (GET /api/files/{filename})
    5. Return combined findings
    
    If parser_output already exists in session state (e.g., from "Use Sample Data"),
    just return it. Otherwise, call the agent or use mock.
    """
    existing = st.session_state.get("parser_output")
    if existing is not None:
        logger.info("Parser: using existing parser_output from session state")
        return existing

    # Helper to add status message to UI
    def add_status(msg: str, level: str = "info"):
        """Add status message to session state for UI display."""
        if "all_step_logs" not in st.session_state:
            st.session_state.all_step_logs = {}
        if "parser_output" not in st.session_state.all_step_logs:
            st.session_state.all_step_logs["parser_output"] = []
        st.session_state.all_step_logs["parser_output"].append({"level": level, "message": msg})
        logger.info(msg)
    
    # PRODUCTION MODE ONLY - NO MOCK DATA FOR PARSER
    if use_mock:
        raise ValueError(
            "Parser Agent does not support mock mode. "
            "Production workflow is required: MCP upload → Genesis Agent → MCP parse → Download."
        )
    else:
        # Production mode: Full MCP workflow
        add_status("PARSER AGENT STATUS LOGS", "header")
        add_status("📌 Data Source: REAL production data from uploaded files (not mock)", "info")
        uploaded = st.session_state.get("uploaded_files", {})
        
        if not uploaded or not uploaded.get("tool1_bytes") or not uploaded.get("tool2_bytes"):
            raise ValueError("No uploaded files found in session state")
        
        tool1_name = uploaded["tool1_name"]
        tool2_name = uploaded["tool2_name"]
        tool1_bytes = uploaded["tool1_bytes"]
        tool2_bytes = uploaded["tool2_bytes"]
        
        add_status(f"\n📁 Input Files", "info")
        add_status(f"• Tool 1: {tool1_name} ({len(tool1_bytes):,} bytes)", "info")
        add_status(f"• Tool 2: {tool2_name} ({len(tool2_bytes):,} bytes)", "info")
        
        # Step 1: Upload both files to MCP server
        add_status(f"\n📤 STEP 1/5: Uploading files to MCP server", "header")
        add_status(f"MCP Server: {MCP_SERVER_URL}", "info")
        
        add_status(f"Uploading Tool 1: {tool1_name}...", "info")
        files1 = {'file': (tool1_name, tool1_bytes)}
        upload1_response = requests.post(
            f"{MCP_SERVER_URL}/api/upload",
            files=files1,
            verify=False,
            timeout=60
        )
        upload1_response.raise_for_status()
        upload1 = upload1_response.json()
        add_status(f"Tool 1 uploaded → {upload1['path']}", "success")
        
        add_status(f"Uploading Tool 2: {tool2_name}...", "info")
        files2 = {'file': (tool2_name, tool2_bytes)}
        upload2_response = requests.post(
            f"{MCP_SERVER_URL}/api/upload",
            files=files2,
            verify=False,
            timeout=60
        )
        upload2_response.raise_for_status()
        upload2 = upload2_response.json()
        add_status(f"Tool 2 uploaded → {upload2['path']}", "success")
        
        # Step 2: Call Genesis Parser Agent (TWO SEPARATE CALLS - one per file)
        client = _get_client()
        agent_id = AGENT_IDS["parser"]
        if not agent_id:
            raise GenesisAgentError(
                "ARES_PARSER_AGENT_ID not configured. "
                "Set it in .env or environment variables."
            )
        
        # CALL 1: Parse first file (Tool 1)
        add_status(f"\n📝 STEP 2/5: Calling Genesis Parser Agent (File 1)", "header")
        add_status(f"Agent ID: {agent_id}", "info")
        add_status(f"File: {tool1_name} → {upload1['path']}", "info")
        
        # Determine which tool to use based on file extension
        file_ext1 = Path(tool1_name).suffix.lower()
        tool_name1 = "parse_ckl" if file_ext1 == ".ckl" else "parse_csv"
        # Create explicit prompt with tool name for clarity
        prompt1 = f"Use {tool_name1} to parse {upload1['path']}"
        add_status(f"Tool: {tool_name1}", "info")
        
        # CKL files take longer to parse, use 180s timeout
        timeout1 = 180 if file_ext1 == ".ckl" else 120
        
        try:
            add_status(f"Calling agent... (timeout: {timeout1}s)", "info")
            agent_response1 = client.call_agent(
                agent_id=agent_id,
                prompt=prompt1,
                auto_approve_tools=AGENT_TOOLS["parser"],
                timeout=timeout1
            )
            add_status(f"Tool 1 parsing complete", "success")
            
            # Extract output filename from response
            tool1_output_filename = Path(upload1['path']).stem + "_parsed.json"
            
            # Add LLM response
            add_status(f"\nAgent Response:", "info")
            add_status(f"{agent_response1}", "info")
            
            # Add download link
            download_url1 = f"{MCP_SERVER_URL}/api/files/{tool1_output_filename}"
            add_status(f"\nDownload: {download_url1}", "info")
            
        except Exception as e:
            logger.error(f"Parser Agent (Tool 1) failed: {e}", exc_info=True)
            raise RuntimeError(
                f"Parser Agent failed on Tool 1 ({tool1_name}): {str(e)}\n\n"
                f"Production workflow requires:\n"
                f"1. MCP server accessible at {MCP_SERVER_URL}\n"
                f"2. Genesis API accessible with valid token\n"
                f"3. Parser Agent ID configured: {agent_id}\n\n"
                f"Check your .env configuration and network connectivity."
            ) from e
        
        # CALL 2: Parse second file (Tool 2)
        add_status(f"\n📝 STEP 3/5: Calling Genesis Parser Agent (File 2)", "header")
        add_status(f"Agent ID: {agent_id}", "info")
        add_status(f"File: {tool2_name} → {upload2['path']}", "info")
        
        # Determine which tool to use based on file extension
        file_ext2 = Path(tool2_name).suffix.lower()
        tool_name2 = "parse_ckl" if file_ext2 == ".ckl" else "parse_csv"
        # Create explicit prompt with tool name for clarity
        prompt2 = f"Use {tool_name2} to parse {upload2['path']}"
        add_status(f"Tool: {tool_name2}", "info")
        
        # CKL files take longer to parse, use 180s timeout
        timeout2 = 180 if file_ext2 == ".ckl" else 120
        
        try:
            add_status(f"Calling agent... (timeout: {timeout2}s)", "info")
            agent_response2 = client.call_agent(
                agent_id=agent_id,
                prompt=prompt2,
                auto_approve_tools=AGENT_TOOLS["parser"],
                timeout=timeout2
            )
            add_status(f"Tool 2 parsing complete", "success")
            
            # Extract output filename from response
            tool2_output_filename = Path(upload2['path']).stem + "_parsed.json"
            
            # Add LLM response
            add_status(f"\nAgent Response:", "info")
            add_status(f"{agent_response2}", "info")
            
            # Add download link
            download_url2 = f"{MCP_SERVER_URL}/api/files/{tool2_output_filename}"
            add_status(f"\nDownload: {download_url2}", "info")
            
            # Store both output filenames for download
            metadata = {
                "tool1_output_filename": tool1_output_filename,
                "tool2_output_filename": tool2_output_filename,
            }
        except Exception as e:
            logger.error(f"Parser Agent call failed: {e}", exc_info=True)
            # NO FALLBACK - Production mode must work
            raise RuntimeError(
                f"Parser Agent failed: {str(e)}\n\n"
                f"Production workflow requires:\n"
                f"1. MCP server accessible at {MCP_SERVER_URL}\n"
                f"2. Genesis API accessible with valid token\n"
                f"3. Parser Agent ID configured: {agent_id}\n\n"
                f"Check your .env configuration and network connectivity."
            ) from e
        
        # Step 3: Download parsed files from MCP server
        add_status(f"\n⬇️  STEP 4/5: Downloading parsed files from MCP server", "header")
        parsed1_filename = metadata.get('tool1_output_filename', Path(upload1['path']).stem + "_parsed.json")
        parsed2_filename = metadata.get('tool2_output_filename', Path(upload2['path']).stem + "_parsed.json")
        
        add_status(f"Downloading: {parsed1_filename}", "info")
        parsed1_response = requests.get(
            f"{MCP_SERVER_URL}/api/files/{parsed1_filename}",
            verify=False,
            timeout=30
        )
        parsed1_response.raise_for_status()
        parsed1_data = parsed1_response.json()
        add_status(f"Tool 1 downloaded ({len(parsed1_response.content):,} bytes)", "success")
        
        add_status(f"Downloading: {parsed2_filename}", "info")
        parsed2_response = requests.get(
            f"{MCP_SERVER_URL}/api/files/{parsed2_filename}",
            verify=False,
            timeout=30
        )
        parsed2_response.raise_for_status()
        parsed2_data = parsed2_response.json()
        add_status(f"Tool 2 downloaded ({len(parsed2_response.content):,} bytes)", "success")
        
        # Step 4: Extract findings and return in expected format
        add_status(f"\n📊 STEP 5/5: Extracting findings from downloaded files", "header")
        tool1_findings = parsed1_data.get('findings', [])
        tool2_findings = parsed2_data.get('findings', [])
        
        add_status(f"Tool 1: {len(tool1_findings)} findings extracted", "success")
        add_status(f"Tool 2: {len(tool2_findings)} findings extracted", "success")
        
        add_status(f"\nParser Agent complete!", "success")
        
        return {
            "tool1_findings": tool1_findings,
            "tool2_findings": tool2_findings,
            "metadata": {
                "source_tools": {
                    "tool1": {"file": tool1_name, "count": len(tool1_findings)},
                    "tool2": {"file": tool2_name, "count": len(tool2_findings)}
                },
                "parsed_at": parsed1_data.get('parsed_at'),
                "parser_version": "1.3.0",
                "mcp_server_url": MCP_SERVER_URL
            }
        }


def _run_gap_identifier(parser_output: Dict[str, Any]) -> List[Dict]:
    """Run Gap Identifier script (always local, deterministic)."""
    # Helper to add status message to UI
    def add_status(msg: str, level: str = "info"):
        """Add status message to session state for UI display."""
        if "all_step_logs" not in st.session_state:
            st.session_state.all_step_logs = {}
        if "identified_gaps" not in st.session_state.all_step_logs:
            st.session_state.all_step_logs["identified_gaps"] = []
        st.session_state.all_step_logs["identified_gaps"].append({"level": level, "message": msg})
        logger.info(msg)
    
    add_status("GAP IDENTIFIER STATUS LOGS", "header")
    tool1 = parser_output.get("tool1_findings", [])
    tool2 = parser_output.get("tool2_findings", [])
    
    # Get metadata for file names
    metadata = parser_output.get("metadata", {})
    tool1_name = metadata.get("source_tools", {}).get("tool1", {}).get("file", "Tool 1")
    tool2_name = metadata.get("source_tools", {}).get("tool2", {}).get("file", "Tool 2")
    
    # Run gap detection (no status message needed)
    gaps = identify_gaps(tool1, tool2)
    
    tool1_only = len([g for g in gaps if g.get('reviewed_by') == 'tool1_only'])
    tool2_only = len([g for g in gaps if g.get('reviewed_by') == 'tool2_only'])
    neither = len([g for g in gaps if g.get('reviewed_by') == 'neither'])
    
    # Detailed analysis per file (moved from Parser Agent)
    add_status(f"\n📊 Detailed Analysis", "header")
    
    # Tool 1 status breakdown
    tool1_not_reviewed = len([f for f in tool1 if f.get('status') == 'Not_Reviewed'])
    tool1_open = len([f for f in tool1 if f.get('status') == 'Open'])
    tool1_not_finding = len([f for f in tool1 if f.get('status') == 'NotAFinding'])
    tool1_not_applicable = len([f for f in tool1 if f.get('status') == 'Not_Applicable'])
    
    add_status(f"\n📄 {tool1_name}", "info")
    add_status(f"• Total rules: {len(tool1)}", "info")
    add_status(f"• Not Reviewed: {tool1_not_reviewed}", "info")
    add_status(f"• Open (failures): {tool1_open}", "info")
    add_status(f"• NotAFinding (passes): {tool1_not_finding}", "info")
    add_status(f"• Not Applicable: {tool1_not_applicable}", "info")
    
    # Tool 2 status breakdown
    tool2_not_reviewed = len([f for f in tool2 if f.get('status') == 'Not_Reviewed'])
    tool2_open = len([f for f in tool2 if f.get('status') == 'Open'])
    tool2_not_finding = len([f for f in tool2 if f.get('status') == 'NotAFinding'])
    tool2_not_applicable = len([f for f in tool2 if f.get('status') == 'Not_Applicable'])
    
    add_status(f"\n📄 {tool2_name}", "info")
    add_status(f"• Total rules: {len(tool2)}", "info")
    add_status(f"• Not Reviewed: {tool2_not_reviewed}", "info")
    add_status(f"• Open (failures): {tool2_open}", "info")
    add_status(f"• NotAFinding (passes): {tool2_not_finding}", "info")
    add_status(f"• Not Applicable: {tool2_not_applicable}", "info")
    
    # Gap Analysis
    add_status(f"\n🔍 Gap Analysis", "header")
    add_status(f"• Total gaps identified: {len(gaps)}", "success")
    add_status(f"• Reviewed by Tool 1 only: {tool1_only}", "info")
    add_status(f"• Reviewed by Tool 2 only: {tool2_only}", "info")
    add_status(f"• Not reviewed by either tool: {neither}", "info")
    
    add_status(f"\nGap Identifier complete!", "success")
    
    return gaps


def _run_gap_coverage(gaps: List[Dict], use_mock: bool) -> List[Dict]:
    """Run Gap Coverage Agent with local MCP execute_command."""
    # Helper to add status to logs
    def add_status(msg: str, level: str = "info"):
        """Add status message to session state for UI display."""
        if "all_step_logs" not in st.session_state:
            st.session_state.all_step_logs = {}
        
        step_key = "gap_coverage_results"
        if step_key not in st.session_state.all_step_logs:
            st.session_state.all_step_logs[step_key] = []
        st.session_state.all_step_logs[step_key].append({"level": level, "message": msg})
        # Also log to console for real-time viewing
        print(f"[GAP COVERAGE] {level.upper()}: {msg}", flush=True)
        logger.info(f"[GAP COVERAGE] {msg}")
    
    if use_mock:
        add_status("Using mock data for Gap Coverage", "info")
        return MOCK_GAP_COVERAGE_OUTPUT
    
    add_status(f"\n🔍 Starting Gap Coverage Agent", "header")
    add_status(f"Found {len(gaps)} gaps to validate", "info")
    
    print(f"\n{'='*80}", flush=True)
    print(f"[GAP COVERAGE] Starting with {len(gaps)} gaps", flush=True)
    print(f"[GAP COVERAGE] Model: nemotron-3-ultra-550b-a55b", flush=True)
    print(f"[GAP COVERAGE] MCP Server: {os.environ.get('MCP_LOCAL_URL', 'http://localhost:8000')}", flush=True)
    print(f"{'='*80}\n", flush=True)
    
    # Load STIG data from markdown (bypasses RAG)
    add_status(f"Loading STIG data from markdown...", "info")
    stig_loader = get_stig_loader()
    add_status(f"Loaded {len(stig_loader.get_all_vuln_ids())} STIG rules", "success")
    
    # Use local agent executor with Genesis LLM + local MCP (NO RAG)
    prompt_file = PROJECT_ROOT / "genesis_agents" / "gap_coverage_agent_prompt_NO_RAG.txt"
    
    add_status(f"Model: nemotron-3-ultra-550b-a55b", "info")
    add_status(f"STIG Data: Loaded from markdown (bypassing RAG)", "info")
    add_status(f"Local MCP: {os.environ.get('MCP_LOCAL_URL', 'http://localhost:8000')}", "info")
    
    executor = LocalAgentExecutor(
        agent_prompt_file=str(prompt_file),
        model="nemotron-3-ultra-550b-a55b",
        vector_store_id=None,  # NO RAG - using pre-loaded Check Text
        max_iterations=25,  # Allow multiple tool calls per gap
    )
    
    add_status(f"\nAgent initialized successfully", "success")
    print(f"[GAP COVERAGE] Agent initialized (NO RAG - using pre-loaded STIG data)\n", flush=True)
    
    # Process gaps one by one (as per agent design)
    validated_gaps = []
    success_count = 0
    error_count = 0
    manual_review_items = []  # Track items requiring manual review
    
    for i, gap in enumerate(gaps, 1):
        vuln_id = gap.get('vuln_id', 'unknown')
        
        # Load STIG data for this vuln_id
        stig_data = stig_loader.get_rule_data(vuln_id)
        
        if stig_data:
            # Use STIG data from markdown
            stig_title = stig_data.get('rule_title', 'Unknown rule')
            severity = stig_data.get('severity', 'Unknown')
            check_text = stig_data.get('check_text', 'Check Text not found')
            discussion = stig_data.get('discussion', '')
            rule_id = stig_data.get('rule_id', gap.get('rule_id', 'unknown'))
            
            # Attach all STIG data to gap for agent
            gap['stig_title'] = stig_title
            gap['severity'] = severity
            gap['check_text'] = check_text
            gap['discussion'] = discussion
            gap['rule_id'] = rule_id
        else:
            # Fallback to finding data if STIG data not found
            print(f"[WARNING] No STIG data found for {vuln_id}, using finding data", flush=True)
            tool1_finding = gap.get('tool1_finding', {})
            tool2_finding = gap.get('tool2_finding', {})
            finding = tool1_finding or tool2_finding
            
            stig_title = finding.get('rule_title') or finding.get('title') or 'Unknown rule'
            severity = finding.get('severity', 'Unknown')
            
            gap['stig_title'] = stig_title
            gap['severity'] = severity
            gap['check_text'] = 'Check Text not available - STIG data not found'
            gap['discussion'] = ''
        
        add_status(f"\n📋 Gap {i}/{len(gaps)}: {vuln_id}", "header")
        add_status(f"Rule: {stig_title[:60]}...", "info")
        
        print(f"\n{'-'*80}", flush=True)
        print(f"[GAP {i}/{len(gaps)}] Processing: {vuln_id}", flush=True)
        print(f"[GAP {i}/{len(gaps)}] Rule: {stig_title[:70]}", flush=True)
        print(f"[GAP {i}/{len(gaps)}] Severity: {severity}", flush=True)
        print(f"{'-'*80}", flush=True)
        
        try:
            print(f"[GAP {i}/{len(gaps)}] Calling Genesis LLM (timeout=180s)...", flush=True)
            add_status(f"⏳ Calling Genesis LLM...", "info")
            
            # Call local agent executor (LLM will query RAG via vector_store_id)
            response_text = executor.execute(gap, timeout=180)
            
            print(f"[GAP {i}/{len(gaps)}] Agent completed", flush=True)
            add_status(f"Agent completed", "success")
            
            # Parse JSON response from agent
            try:
                response = json.loads(response_text)
                
                # Normalize verdict format (handle LLM variations)
                raw_verdict = response.get('ares_verdict', 'Unknown')
                verdict_map = {
                    'Not A Finding': 'NotAFinding',
                    'Not a Finding': 'NotAFinding',
                    'Not_A_Finding': 'NotAFinding',
                    'NotAFinding': 'NotAFinding',
                    'Not Applicable': 'Not_Applicable',
                    'NotApplicable': 'Not_Applicable',
                    'Not_Applicable': 'Not_Applicable',
                    'N/A': 'Not_Applicable',
                    'Open': 'Open',
                }
                status = verdict_map.get(raw_verdict, raw_verdict)
                response['ares_verdict'] = status  # Normalize in response
                
                confidence = response.get('confidence', 0)
                requires_review = response.get('requires_human_review', False)
                finding_details = response.get('finding_details', 'No details provided')
                
                # Auto-flag for manual review if confidence < 80%
                if confidence < 80:
                    response['requires_human_review'] = True
                    requires_review = True
                    print(f"[GAP {i}/{len(gaps)}] ⚠️  Low confidence ({confidence}%) - FLAGGED FOR MANUAL REVIEW", flush=True)
                
                # Log finding details
                print(f"[GAP {i}/{len(gaps)}] Finding Details: {finding_details[:200]}...", flush=True) if len(finding_details) > 200 else print(f"[GAP {i}/{len(gaps)}] Finding Details: {finding_details}", flush=True)
                
                if requires_review:
                    manual_review_items.append({
                        'vuln_id': vuln_id,
                        'reason': f'Confidence {confidence}%' if confidence < 80 else 'Agent flagged for review',
                        'verdict': status,
                        'confidence': confidence
                    })
                    print(f"[GAP {i}/{len(gaps)}] Result: {status}, Confidence: {confidence}% [MANUAL REVIEW REQUIRED]", flush=True)
                    # Add full rule title and finding details to UI
                    add_status(f"Result: {status}, Confidence: {confidence}%", "warning")
                    add_status(f"  Rule: {stig_title}", "info")
                    add_status(f"  Details: {finding_details[:200]}...", "info") if len(finding_details) > 200 else add_status(f"  Details: {finding_details}", "info")
                else:
                    print(f"[GAP {i}/{len(gaps)}] Result: {status}, Confidence: {confidence}%", flush=True)
                    # Add full rule title and finding details to UI
                    add_status(f"Result: {status}, Confidence: {confidence}%", "success")
                    add_status(f"  Rule: {stig_title}", "info")
                    add_status(f"  Details: {finding_details[:200]}...", "info") if len(finding_details) > 200 else add_status(f"  Details: {finding_details}", "info")
                
                validated_gaps.append(response)
                success_count += 1
                
            except json.JSONDecodeError as je:
                # Try to extract JSON from response (in case LLM added text before/after)
                print(f"[GAP {i}/{len(gaps)}] WARNING: Direct JSON parse failed, trying extraction...", flush=True)
                
                import re
                # Try to find JSON object in response
                json_match = re.search(r'\{[^{}]*"vuln_id"[^{}]*\}', response_text, re.DOTALL)
                if not json_match:
                    # Try more permissive match
                    json_match = re.search(r'\{.*?\}', response_text, re.DOTALL)
                
                if json_match:
                    try:
                        json_text = json_match.group(0)
                        response = json.loads(json_text)
                        
                        # Normalize verdict and flag for review
                        raw_verdict = response.get('ares_verdict', 'Unknown')
                        verdict_map = {
                            'Not A Finding': 'NotAFinding',
                            'Not a Finding': 'NotAFinding',
                            'Not_A_Finding': 'NotAFinding',
                            'Not Applicable': 'Not_Applicable',
                            'NotApplicable': 'Not_Applicable',
                        }
                        status = verdict_map.get(raw_verdict, raw_verdict)
                        response['ares_verdict'] = status
                        
                        confidence = response.get('confidence', 0)
                        
                        # Flag for review since JSON was malformed
                        response['requires_human_review'] = True
                        response['extraction_warning'] = 'JSON was extracted from malformed response'
                        
                        # Flag for review and track
                        manual_review_items.append({
                            'vuln_id': vuln_id,
                            'reason': 'Malformed JSON (extracted)',
                            'verdict': status,
                            'confidence': confidence
                        })
                        
                        print(f"[GAP {i}/{len(gaps)}] ✅ Extracted JSON successfully", flush=True)
                        print(f"[GAP {i}/{len(gaps)}] Result: {status}, Confidence: {confidence}% [MANUAL REVIEW - Malformed JSON]", flush=True)
                        add_status(f"Status: {status}, Confidence: {confidence}% - Manual Review (Malformed JSON)", "warning")
                        validated_gaps.append(response)
                        success_count += 1
                        continue  # Skip error handling below
                    except json.JSONDecodeError:
                        pass  # Fall through to error handling
                
                # JSON extraction failed - flag for manual review
                manual_review_items.append({
                    'vuln_id': vuln_id,
                    'reason': 'JSON decode failed',
                    'verdict': 'Not_Reviewed',
                    'confidence': 0
                })
                
                print(f"[GAP {i}/{len(gaps)}] ERROR: JSON decode failed (even after extraction)", flush=True)
                print(f"[GAP {i}/{len(gaps)}] Response preview: {response_text[:300]}", flush=True)
                add_status(f"Agent returned non-JSON response - MANUAL REVIEW REQUIRED", "warning")
                add_status(f"Response preview: {response_text[:100]}...", "warning")
                logger.error(f"JSON decode error for {vuln_id}: {je}")
                
                # Add as Not_Reviewed with manual review flag
                validated_gaps.append({
                    "vuln_id": vuln_id,
                    "rule_id": gap.get("rule_id", "unknown"),
                    "ares_verdict": "Not_Reviewed",
                    "confidence": 0,
                    "requires_human_review": True,
                    "error": f"Invalid JSON response: {str(je)}",
                    "validation_source": "gap_coverage_agent_error",
                    "finding_details": "Agent failed to return valid JSON. Manual review required.",
                })
                error_count += 1
            
        except Exception as e:
            error_msg = str(e)
            manual_review_items.append({
                'vuln_id': vuln_id,
                'reason': f'Exception: {error_msg[:100]}',
                'verdict': 'Not_Reviewed',
                'confidence': 0
            })
            
            print(f"[GAP {i}/{len(gaps)}] EXCEPTION: {error_msg[:150]}", flush=True)
            add_status(f"Error: {error_msg[:80]}... - MANUAL REVIEW REQUIRED", "error")
            logger.error(f"Gap validation failed for {vuln_id}: {e}", exc_info=True)
            
            # Add error entry with manual review flag
            validated_gaps.append({
                "vuln_id": vuln_id,
                "rule_id": gap.get("rule_id", "unknown"),
                "ares_verdict": "Not_Reviewed",
                "confidence": 0,
                "requires_human_review": True,
                "error": error_msg,
                "validation_source": "gap_coverage_agent_error",
                "finding_details": f"Validation error: {error_msg[:200]}",
            })
            error_count += 1
    
    print(f"\n{'='*80}", flush=True)
    print(f"[GAP COVERAGE] COMPLETE: {success_count} successful, {error_count} errors", flush=True)
    print(f"{'='*80}\n", flush=True)
    
    # Summary
    add_status(f"\nGap Coverage Complete!", "header")
    add_status(f"Successful: {success_count}/{len(gaps)}", "success")
    if error_count > 0:
        add_status(f"Errors: {error_count}/{len(gaps)}", "error")
    
    # Manual review summary
    if manual_review_items:
        add_status(f"\nManual Review Required: {len(manual_review_items)}/{len(gaps)}", "warning")
        print(f"\n[MANUAL REVIEW REQUIRED] {len(manual_review_items)} items:", flush=True)
        for item in manual_review_items:
            vuln = item['vuln_id']
            reason = item['reason']
            verdict = item['verdict']
            conf = item['confidence']
            print(f"  - {vuln}: {verdict} ({conf}%) - {reason}", flush=True)
            add_status(f"  • {vuln}: {verdict} ({conf}%) - {reason}", "info")
    
    # Save results to JSON file for comparison script
    output_file = PROJECT_ROOT / "data" / "output" / "gap_coverage_results.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(validated_gaps, f, indent=2)
    print(f"\n[SAVED] Gap coverage results saved to: {output_file}", flush=True)
    logger.info(f"Gap coverage results saved to {output_file}")
    
    logger.info(f"Gap Coverage complete: {len(validated_gaps)} gaps validated (success: {success_count}, errors: {error_count}, manual review: {len(manual_review_items)})")
    return validated_gaps


def _run_comparison(parser_output: Dict[str, Any], gap_coverage_results: List[Dict]) -> Dict[str, Any]:
    """Run Comparison Script (always local, deterministic).
    
    Uses enhanced comparison script with data from session state:
    - Tool1/Tool2 findings from parser_output
    - Gap coverage results from gap_coverage_results
    - Loads STIG data for full context
    """
    # Helper to add status message to UI
    def add_status(msg: str, level: str = "info"):
        """Add status message to session state for UI display."""
        if "all_step_logs" not in st.session_state:
            st.session_state.all_step_logs = {}
        if "comparison_output" not in st.session_state.all_step_logs:
            st.session_state.all_step_logs["comparison_output"] = []
        st.session_state.all_step_logs["comparison_output"].append({"message": msg, "level": level})
    
    from genesis_integration.comparison_script_enhanced import run_comparison
    
    logger.info("Running enhanced comparison script...")
    add_status("Comparison Script", "header")
    add_status("Comparing Tool 1 and Tool 2 findings...", "info")
    
    print(f"\n{'='*80}", flush=True)
    print(f"COMPARISON SCRIPT - Analyzing Findings", flush=True)
    print(f"{'='*80}\n", flush=True)
    
    # Extract counts for status logs
    tool1_count = len(parser_output.get('tool1_findings', []))
    tool2_count = len(parser_output.get('tool2_findings', []))
    gap_count = len(gap_coverage_results)
    
    add_status(f"Tool 1 Findings: {tool1_count}", "info")
    add_status(f"Tool 2 Findings: {tool2_count}", "info")
    add_status(f"Gap Coverage Validated: {gap_count}", "info")
    
    print(f"[COMPARE] Tool 1: {tool1_count} findings", flush=True)
    print(f"[COMPARE] Tool 2: {tool2_count} findings", flush=True)
    print(f"[COMPARE] Gap Coverage: {gap_count} findings", flush=True)
    
    try:
        # Pass data from session state to comparison
        add_status("Identifying agreements and disagreements...", "info")
        result = run_comparison(parser_output, gap_coverage_results)
        
        agreements = result['summary']['agreements']
        disagreements = result['summary']['disagreements']
        gap_applied = result['summary']['gap_coverage_applied']
        
        add_status(f"\nComparison Complete!", "header")
        add_status(f"✓ Agreements: {agreements}", "success")
        add_status(f"⚠ Disagreements: {disagreements}", "warning" if disagreements > 0 else "info")
        add_status(f"📋 Gap Coverage Applied: {gap_applied}", "info")
        
        # Show breakdown of disagreement types
        disagreement_list = result.get('disagreements', [])
        if disagreement_list:
            conflict_types = {}
            for d in disagreement_list:
                ct = d.get('conflict_type', 'unknown')
                conflict_types[ct] = conflict_types.get(ct, 0) + 1
            
            add_status(f"\nDisagreement Breakdown:", "info")
            for ct, count in sorted(conflict_types.items()):
                add_status(f"  • {ct}: {count}", "info")
        
        print(f"\n[COMPARISON] Results:", flush=True)
        print(f"  Agreements: {agreements}", flush=True)
        print(f"  Disagreements: {disagreements}", flush=True)
        print(f"  Gap Coverage Applied: {gap_applied}", flush=True)
        
        return result
    except Exception as e:
        logger.error(f"Comparison failed: {e}", exc_info=True)
        add_status(f"Comparison error: {str(e)}", "error")
        print(f"[ERROR] Comparison failed: {e}", flush=True)
        raise


def _run_determination(comparison_output: Dict[str, Any], use_mock: bool) -> List[Dict]:
    """Run Determination Agent with local MCP execute_command."""
    # Helper to add status message to UI
    def add_status(msg: str, level: str = "info"):
        """Add status message to session state for UI display."""
        if "all_step_logs" not in st.session_state:
            st.session_state.all_step_logs = {}
        if "determination_output" not in st.session_state.all_step_logs:
            st.session_state.all_step_logs["determination_output"] = []
        st.session_state.all_step_logs["determination_output"].append({"message": msg, "level": level})
    
    # Helper to normalize status strings
    def normalize_status(status: str) -> str:
        """Normalize status strings to consistent format."""
        canonical = {
            "open": "Open",
            "notafinding": "NotAFinding",
            "not_a_finding": "NotAFinding",
            "notapplicable": "Not_Applicable",
            "not_applicable": "Not_Applicable",
            "notreviewed": "Not_Reviewed",
            "not_reviewed": "Not_Reviewed",
        }
        if not status:
            return "Not_Reviewed"
        cleaned = status.strip().lower().replace(" ", "_").replace("-", "_")
        if cleaned in canonical:
            return canonical[cleaned]
        squished = cleaned.replace("_", "")
        for key, value in canonical.items():
            if key.replace("_", "") == squished:
                return value
        return status.strip().capitalize()
    
    if use_mock:
        return MOCK_DETERMINATION_OUTPUT
    
    disagreements = comparison_output.get("disagreements", [])
    logger.info(f"Running Determination with local agent executor ({len(disagreements)} disagreements)")
    
    add_status(f"Determination Agent", "header")
    add_status(f"Found {len(disagreements)} disagreements to resolve", "info")
    print(f"\n{'='*80}", flush=True)
    print(f"DETERMINATION AGENT - Resolving {len(disagreements)} Disagreements", flush=True)
    print(f"{'='*80}\n", flush=True)
    
    if len(disagreements) == 0:
        add_status("No disagreements found - all sources agree!", "success")
        print(f"[INFO] No disagreements to resolve. All sources agree!", flush=True)
        return []
    
    # Load STIG data for check text and discussion
    stig_loader = get_stig_loader()
    add_status(f"Loaded {len(stig_loader.get_all_vuln_ids())} STIG rules", "success")
    logger.info(f"STIG loader ready with {len(stig_loader.get_all_vuln_ids())} rules")
    
    # Use local agent executor with Genesis LLM + local MCP
    prompt_file = PROJECT_ROOT / "genesis_agents" / "determination_agent_prompt.txt"
    vector_store_id = None  # No RAG - using pre-loaded STIG data like gap coverage
    
    add_status("Initializing Determination Agent...", "info")
    print(f"[INIT] Loading determination agent prompt from: {prompt_file}", flush=True)
    
    try:
        executor = LocalAgentExecutor(
            agent_prompt_file=str(prompt_file),
            model="nemotron-3-ultra-550b-a55b",
            vector_store_id=vector_store_id,
            max_iterations=25,  # Allow more iterations for complex disagreements
        )
        add_status("Agent initialized successfully", "success")
        print(f"[INIT] Determination agent ready (model: nemotron-3-ultra-550b-a55b)", flush=True)
    except Exception as e:
        error_msg = f"Failed to initialize determination agent: {e}"
        logger.error(error_msg, exc_info=True)
        add_status(error_msg, "error")
        print(f"[ERROR] {error_msg}", flush=True)
        raise
    
    # Process disagreements one by one
    resolved_findings = []
    success_count = 0
    error_count = 0
    manual_review_items = []
    
    for i, disagreement in enumerate(disagreements, 1):
        vuln_id = disagreement.get('vuln_id', 'unknown')
        conflict_type = disagreement.get('conflict_type', 'unknown')
        severity = disagreement.get('severity', 'CAT II')
        
        # Load STIG data for this vuln_id
        stig_data = stig_loader.get_rule_data(vuln_id)
        if not stig_data:
            logger.warning(f"No STIG data found for {vuln_id}")
            stig_data = {}
        
        stig_title = stig_data.get('rule_title', 'Unknown rule')
        check_text = stig_data.get('check_text', '')
        discussion = stig_data.get('discussion', '')
        
        # Enrich disagreement with STIG data
        disagreement['check_text'] = check_text
        disagreement['discussion'] = discussion
        disagreement['stig_title'] = stig_title
        
        tool1_status = disagreement.get('tool1_status', 'N/A')
        tool2_status = disagreement.get('tool2_status', 'N/A')
        gap_status = disagreement.get('gap_coverage_status', 'N/A')
        
        add_status(f"\n{'='*60}", "info")
        add_status(f"Disagreement {i}/{len(disagreements)}: {vuln_id}", "header")
        add_status(f"Rule: {stig_title}", "info")
        add_status(f"Severity: {severity}", "info")
        add_status(f"Conflict Type: {conflict_type}", "warning")
        add_status(f"Tool 1 Verdict: {tool1_status}", "info")
        add_status(f"Tool 2 Verdict: {tool2_status}", "info")
        if gap_status and gap_status != 'N/A':
            add_status(f"Gap Coverage Verdict: {gap_status}", "info")
        add_status(f"Resolving via CLI validation...", "info")
        
        print(f"\n[DISAGREEMENT {i}/{len(disagreements)}] {vuln_id} ({severity})", flush=True)
        print(f"  Rule: {stig_title[:100]}...", flush=True)
        print(f"  Conflict Type: {conflict_type}", flush=True)
        print(f"  Tool1: {tool1_status}, Tool2: {tool2_status}, Gap: {gap_status}", flush=True)
        
        try:
            add_status(f"  Calling Genesis LLM...", "info")
            print(f"[{i}] Calling Genesis LLM to resolve disagreement...", flush=True)
            
            # Call local agent executor
            response_text = executor.execute(disagreement, timeout=180)
            
            print(f"[{i}] Agent response received ({len(response_text)} chars)", flush=True)
            
            # Parse JSON response from agent
            response = json.loads(response_text)
            
            # Normalize ARES verdict
            ares_verdict = response.get('ares_verdict', 'Not_Reviewed')
            ares_verdict = normalize_status(ares_verdict)
            response['ares_verdict'] = ares_verdict
            
            # Extract key fields
            confidence = response.get('confidence', 0)
            requires_review = response.get('requires_human_review', False)
            finding_details = response.get('finding_details', '')
            
            # Auto-flag for manual review if confidence < 80%
            if confidence < 80:
                response['requires_human_review'] = True
                requires_review = True
            
            resolved_findings.append(response)
            success_count += 1
            
            # Track manual review items
            if requires_review:
                manual_review_items.append({
                    'vuln_id': vuln_id,
                    'reason': f'Confidence {confidence}%' if confidence < 80 else 'Agent flagged for review',
                    'verdict': ares_verdict,
                    'confidence': confidence,
                    'conflict_type': conflict_type,
                    'stig_title': stig_title
                })
                print(f"[{i}] Result: {ares_verdict}, Confidence: {confidence}% [MANUAL REVIEW REQUIRED]", flush=True)
                add_status(f"✓ ARES Verdict: {ares_verdict}", "warning")
                add_status(f"  Confidence: {confidence}% [MANUAL REVIEW REQUIRED]", "warning")
                add_status(f"  Finding Details: {finding_details[:200]}..." if len(finding_details) > 200 else f"  Finding Details: {finding_details}", "info")
            else:
                print(f"[{i}] Result: {ares_verdict}, Confidence: {confidence}%", flush=True)
                add_status(f"✓ ARES Verdict: {ares_verdict}", "success")
                add_status(f"  Confidence: {confidence}%", "success")
                add_status(f"  Finding Details: {finding_details[:200]}..." if len(finding_details) > 200 else f"  Finding Details: {finding_details}", "info")
            
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON response from agent: {str(e)[:100]}"
            logger.error(f"[{vuln_id}] {error_msg}\nResponse text: {response_text[:500]}")
            add_status(f"  Error: {error_msg}", "error")
            print(f"[{i}] ERROR: {error_msg}", flush=True)
            error_count += 1
            
            resolved_findings.append({
                "vuln_id": vuln_id,
                "rule_id": disagreement.get("rule_id", "unknown"),
                "ares_verdict": "Not_Reviewed",
                "confidence": 0,
                "requires_human_review": True,
                "error": error_msg,
                "validation_source": "determination_agent_error",
            })
            
        except Exception as e:
            error_msg = str(e)
            if "HTTP 502" in error_msg or "Bad Gateway" in error_msg:
                error_msg = "Genesis LLM call failed (HTTP 502): Bad Gateway"
            
            logger.error(f"[{vuln_id}] Disagreement resolution failed: {e}", exc_info=True)
            add_status(f"  Exception: {error_msg[:80]}...", "error")
            print(f"[{i}] EXCEPTION: {error_msg[:150]}...", flush=True)
            error_count += 1
            
            resolved_findings.append({
                "vuln_id": vuln_id,
                "rule_id": disagreement.get("rule_id", "unknown"),
                "ares_verdict": "Not_Reviewed",
                "confidence": 0,
                "requires_human_review": True,
                "error": error_msg,
                "validation_source": "determination_agent_error",
            })
    
    # Save results to JSON file
    output_file = PROJECT_ROOT / "data" / "output" / "determination_output.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(resolved_findings, f, indent=2)
    print(f"\n[SAVED] Determination results saved to: {output_file}", flush=True)
    logger.info(f"Determination results saved to {output_file}")
    
    # Calculate verdict breakdown
    verdict_counts = {
        'Open': 0,
        'NotAFinding': 0,
        'Not_Applicable': 0,
        'Not_Reviewed': 0
    }
    
    for finding in resolved_findings:
        verdict = finding.get('ares_verdict', 'Not_Reviewed')
        if verdict in verdict_counts:
            verdict_counts[verdict] += 1
        else:
            verdict_counts['Not_Reviewed'] += 1
    
    # Summary header
    print(f"\n{'='*80}", flush=True)
    print(f"[DETERMINATION] COMPLETE: {success_count} successful, {error_count} errors", flush=True)
    print(f"{'='*80}\n", flush=True)
    
    add_status(f"\n{'='*60}", "info")
    add_status(f"Determination Complete!", "header")
    add_status(f"Successful: {success_count}/{len(disagreements)}", "success")
    if error_count > 0:
        add_status(f"Errors: {error_count}/{len(disagreements)}", "error")
    
    # Verdict breakdown
    add_status(f"\nFinal Verdict Breakdown:", "header")
    add_status(f"Open: {verdict_counts['Open']}", "warning" if verdict_counts['Open'] > 0 else "info")
    add_status(f"NotAFinding: {verdict_counts['NotAFinding']}", "success")
    add_status(f"Not_Applicable: {verdict_counts['Not_Applicable']}", "info")
    add_status(f"Not_Reviewed: {verdict_counts['Not_Reviewed']}", "warning" if verdict_counts['Not_Reviewed'] > 0 else "info")
    
    print(f"[DETERMINATION] HEADER:\nDetermination Complete!", flush=True)
    print(f"[DETERMINATION] SUCCESS: Successful: {success_count}/{len(disagreements)}", flush=True)
    if error_count > 0:
        print(f"[DETERMINATION] ERROR: Errors: {error_count}/{len(disagreements)}", flush=True)
    print(f"\n[VERDICT BREAKDOWN]", flush=True)
    print(f"  Open: {verdict_counts['Open']}", flush=True)
    print(f"  NotAFinding: {verdict_counts['NotAFinding']}", flush=True)
    print(f"  Not_Applicable: {verdict_counts['Not_Applicable']}", flush=True)
    print(f"  Not_Reviewed: {verdict_counts['Not_Reviewed']}", flush=True)
    
    # Manual review summary
    if manual_review_items:
        add_status(f"\nManual Review Required: {len(manual_review_items)}/{len(disagreements)}", "warning")
        print(f"\n[MANUAL REVIEW REQUIRED] {len(manual_review_items)} items:", flush=True)
        for item in manual_review_items:
            vuln = item['vuln_id']
            reason = item['reason']
            verdict = item['verdict']
            conf = item['confidence']
            conflict = item['conflict_type']
            title = item.get('stig_title', 'Unknown')
            print(f"  - {vuln}: {verdict} ({conf}%) - {reason}", flush=True)
            add_status(f"  • {vuln}: {verdict} ({conf}%) - {reason}", "warning")
            add_status(f"    {title[:80]}...", "info")
    
    logger.info(f"Determination complete: {len(resolved_findings)} disagreements resolved (success: {success_count}, errors: {error_count}, manual review: {len(manual_review_items)})")
    return resolved_findings


def _run_reporting(all_results: Dict[str, Any], use_mock: bool) -> Dict[str, Any]:
    """Run Reporting Agent with local agent executor to generate final reconciled report."""
    # Helper to add status message to UI
    def add_status(msg: str, level: str = "info"):
        """Add status message to session state for UI display."""
        if "all_step_logs" not in st.session_state:
            st.session_state.all_step_logs = {}
        if "final_report" not in st.session_state.all_step_logs:
            st.session_state.all_step_logs["final_report"] = []
        st.session_state.all_step_logs["final_report"].append({"message": msg, "level": level})
    
    if use_mock:
        return MOCK_REPORTING_OUTPUT
    
    logger.info("Running Reporting Agent to generate final reconciled report")
    
    add_status("Reporting Agent", "header")
    add_status("Compiling final reconciliation report...", "info")
    print(f"\n{'='*80}", flush=True)
    print(f"REPORTING AGENT - Generating Final Report", flush=True)
    print(f"{'='*80}\n", flush=True)
    
    # Compile findings from all sources
    comparison = all_results.get("comparison", {})
    agreements = comparison.get("agreements", [])
    gap_coverage_results = all_results.get("gap_coverage", [])
    determination_results = all_results.get("determination", [])
    
    add_status(f"Agreements: {len(agreements)}", "success")
    add_status(f"Disagreements Resolved: {len(determination_results)}", "info")
    add_status(f"Gaps Filled: {len(gap_coverage_results)}", "info")
    
    print(f"[COMPILE] Agreements: {len(agreements)}", flush=True)
    print(f"[COMPILE] Disagreements resolved: {len(determination_results)}", flush=True)
    print(f"[COMPILE] Gaps filled: {len(gap_coverage_results)}", flush=True)
    
    # Compile final findings list for CKL generation
    add_status("Merging all findings...", "info")
    final_findings = []
    
    # Add agreements (use the agreed status)
    for agreement in agreements:
        final_findings.append({
            "vuln_id": agreement.get("vuln_id"),
            "group_id": agreement.get("vuln_id"),  # Alias
            "rule_id": agreement.get("rule_id", ""),
            "severity": agreement.get("severity", "CAT II"),
            "status": agreement.get("final_status", "NotAFinding"),
            "rule_title": agreement.get("rule_title", ""),
            "finding_details": f"Both tools agreed: {agreement.get('final_status')}",
            "comments": "Agreement between scanning tools",
        })
    
    # Add gap coverage results (ARES validated)
    for gap in gap_coverage_results:
        final_findings.append({
            "vuln_id": gap.get("vuln_id"),
            "group_id": gap.get("vuln_id"),
            "rule_id": gap.get("rule_id", ""),
            "severity": gap.get("severity", "CAT II"),
            "status": gap.get("ares_verdict", "Not_Reviewed"),
            "rule_title": gap.get("stig_title", ""),
            "finding_details": gap.get("finding_details", ""),
            "comments": f"ARES Gap Coverage validation (confidence: {gap.get('confidence', 0)}%)",
        })
    
    # Add determination results (ARES resolved disagreements)
    for determination in determination_results:
        final_findings.append({
            "vuln_id": determination.get("vuln_id"),
            "group_id": determination.get("vuln_id"),
            "rule_id": determination.get("rule_id", ""),
            "severity": determination.get("severity", "CAT II"),
            "status": determination.get("ares_verdict", "Not_Reviewed"),
            "rule_title": determination.get("stig_title", ""),
            "finding_details": determination.get("finding_details", ""),
            "comments": f"ARES Determination (confidence: {determination.get('confidence', 0)}%)",
        })
    
    add_status(f"Total findings compiled: {len(final_findings)}", "success")
    print(f"[COMPILE] Total findings: {len(final_findings)}", flush=True)
    
    # Calculate metrics
    verdict_counts = {"Open": 0, "NotAFinding": 0, "Not_Applicable": 0, "Not_Reviewed": 0}
    for f in final_findings:
        status = f.get("status", "Not_Reviewed")
        if status in verdict_counts:
            verdict_counts[status] += 1
    
    add_status(f"\nFinal Verdict Breakdown:", "header")
    add_status(f"Open: {verdict_counts['Open']}", "warning" if verdict_counts['Open'] > 0 else "info")
    add_status(f"NotAFinding: {verdict_counts['NotAFinding']}", "success")
    add_status(f"Not_Applicable: {verdict_counts['Not_Applicable']}", "info")
    add_status(f"Not_Reviewed: {verdict_counts['Not_Reviewed']}", "warning" if verdict_counts['Not_Reviewed'] > 0 else "info")
    
    # Generate CKL file using CKLGenerator
    add_status("Generating CKL file...", "info")
    print(f"\n[CKL] Generating STIG Viewer-compatible CKL file...", flush=True)
    
    try:
        from mcp_server.generators.ckl_generator import CKLGenerator
        
        generator = CKLGenerator()
        metadata = {
            "stig_title": "Red Hat Enterprise Linux 8 Security Technical Implementation Guide",
            "version": "2",
            "releaseinfo": "Release: 7",
            "stigid": "RHEL_8_STIG",
        }
        asset_info = {
            "host_name": "rhel8-stig-lab",
            "host_ip": "10.0.2.15",
        }
        
        output_dir = PROJECT_ROOT / "data" / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        ckl_filepath = generator.generate_to_file(final_findings, metadata, asset_info, str(output_dir))
        
        add_status(f"✓ CKL File Generated: {ckl_filepath.name}", "success")
        print(f"[CKL] Generated: {ckl_filepath}", flush=True)
        
        # Build report object
        report = {
            "ckl_file": str(ckl_filepath),
            "metrics": {
                "total_findings": len(final_findings),
                "final_open": verdict_counts["Open"],
                "final_not_a_finding": verdict_counts["NotAFinding"],
                "final_not_applicable": verdict_counts["Not_Applicable"],
                "final_not_reviewed": verdict_counts["Not_Reviewed"],
                "agreements": len(agreements),
                "disagreements_resolved": len(determination_results),
                "gaps_filled": len(gap_coverage_results),
            },
            "human_review_queue": [],
            "recommendations": [],
            "visualization_data": {
                "status_breakdown": verdict_counts
            }
        }
        
        # Save report to JSON
        output_file = PROJECT_ROOT / "data" / "output" / "reporting_output.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        add_status(f"Report saved to: {output_file.name}", "success")
        print(f"[SAVED] Report saved to: {output_file}", flush=True)
        
        logger.info(f"Reporting complete: {len(final_findings)} findings, CKL generated at {ckl_filepath}")
        return report
        
    except Exception as e:
        error_msg = f"Failed to generate CKL: {str(e)}"
        logger.error(error_msg, exc_info=True)
        add_status(f"Error: {error_msg}", "error")
        print(f"[ERROR] {error_msg}", flush=True)
        raise
