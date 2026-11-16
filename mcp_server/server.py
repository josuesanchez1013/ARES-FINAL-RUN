"""
ARES MCP Server - FastMCP with HTTP ASGI App + REST Endpoints

This version combines:
1. MCP protocol for Genesis agents (SSE/JSON-RPC)
2. REST API for Streamlit file downloads

Architecture:
- FastMCP handles MCP protocol for Genesis agents
- FastAPI provides REST endpoints for Streamlit
- MCP tools write files to /data/output/ (metadata only in response)
- Streamlit downloads full JSON files via HTTP GET
- Clean separation: Genesis gets metadata, Streamlit gets full data

Version: 2.0.0
"""

from fastmcp import FastMCP
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse
from starlette.applications import Starlette
from starlette.routing import Mount
import json
import os
from pathlib import Path
import logging
from datetime import datetime
import shutil

from .parsers.ckl_parser import CKLParser
from .parsers.csv_parser import CSVParser
from .generators.ckl_generator import CKLGenerator
from .schemas.finding_schema import Finding
from cli_executor.ares_mcp_tool import ARESCliMcpTool

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastMCP server instance
mcp = FastMCP("ares-mcp-server")


# Register MCP Tools using @mcp.tool() decorator
@mcp.tool()
def parse_ckl(filepath: str) -> dict:
    """
    Parse CKL (Checklist XML) file and write to JSON file.
    Returns metadata only (not full findings) to avoid LLM truncation.
    
    Args:
        filepath: Absolute path to CKL (XML) file
        
    Returns:
        dict with metadata: success, output_filename, count, message
        Full findings are written to file, accessible via /api/files/{filename}
    """
    try:
        logger.info(f"parse_ckl called with filepath: {filepath}")
        parser = CKLParser()
        findings = parser.parse(filepath)
        
        # Generate output filename
        input_filename = Path(filepath).stem
        output_filename = f"{input_filename}_parsed.json"
        output_dir = "/tmp/data/output"  # Fixed output directory
        output_path = Path(output_dir) / output_filename
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Write full findings to file
        output_data = {
            "source_file": Path(filepath).name,
            "parsed_at": datetime.now().isoformat(),
            "parser_version": "2.0.0",
            "count": len(findings),
            "findings": [f.model_dump() for f in findings]
        }
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"parse_ckl completed: {len(findings)} findings written to {output_path}")
        
        # Return ONLY metadata (small response for Genesis Agent)
        return {
            "success": True,
            "output_filename": output_filename,
            "source_file": Path(filepath).name,
            "count": len(findings),
            "message": f"Successfully parsed {len(findings)} findings from {Path(filepath).name}"
        }
    except Exception as e:
        logger.error(f"parse_ckl error: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def parse_csv(filepath: str) -> dict:
    """
    Parse CSV file and write to JSON file.
    Returns metadata only (not full findings) to avoid LLM truncation.
    
    Args:
        filepath: Absolute path to CSV file
        
    Returns:
        dict with metadata: success, output_filename, count, message
        Full findings are written to file, accessible via /api/files/{filename}
    """
    try:
        logger.info(f"parse_csv called with filepath: {filepath}")
        parser = CSVParser()
        findings = parser.parse(filepath)
        
        # Generate output filename
        input_filename = Path(filepath).stem
        output_filename = f"{input_filename}_parsed.json"
        output_dir = "/tmp/data/output"  # Fixed output directory
        output_path = Path(output_dir) / output_filename
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Write full findings to file
        output_data = {
            "source_file": Path(filepath).name,
            "parsed_at": datetime.now().isoformat(),
            "parser_version": "2.0.0",
            "count": len(findings),
            "findings": [f.model_dump() for f in findings]
        }
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"parse_csv completed: {len(findings)} findings written to {output_path}")
        
        # Return ONLY metadata (small response for Genesis Agent)
        return {
            "success": True,
            "output_filename": output_filename,
            "source_file": Path(filepath).name,
            "count": len(findings),
            "message": f"Successfully parsed {len(findings)} findings from {Path(filepath).name}"
        }
    except Exception as e:
        logger.error(f"parse_csv error: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def generate_ckl(findings: list, metadata: dict, output_dir: str = "/tmp/data/output") -> dict:
    """
    Generate STIG Viewer-compatible CKL XML file from reconciled findings.
    
    Args:
        findings: List of reconciled findings with final status, confidence, source
        metadata: STIG metadata (stig_title, version, release, hostname, etc.)
        output_dir: Directory to write output CKL (default: /data/output)
    
    Returns:
        dict with: success, filepath, finding_count, ckl_content (if < 1MB)
    """
    try:
        logger.info(f"generate_ckl called with {len(findings)} findings")
        
        # Extract asset_info from metadata (generator separates asset from STIG info)
        asset_info = {}
        asset_keys = ["host_name", "host_ip", "host_mac", "host_fqdn",
                      "tech_area", "target_key", "marking"]
        for key in asset_keys:
            if key in metadata:
                asset_info[key] = metadata[key]
        # Also accept "hostname" as alias for "host_name"
        if "hostname" in metadata and "host_name" not in asset_info:
            asset_info["host_name"] = metadata["hostname"]
        
        generator = CKLGenerator()
        filepath = generator.generate_to_file(
            findings, metadata, asset_info, output_dir
        )
        
        ckl_content = filepath.read_text(encoding="utf-8")
        logger.info(f"generate_ckl completed: {len(findings)} findings written to {filepath}")
        
        result = {
            "success": True,
            "filepath": str(filepath),
            "output_filename": filepath.name,
            "finding_count": len(findings),
            "message": f"Generated CKL with {len(findings)} findings",
        }
        
        # Include content in response if under 1MB
        if len(ckl_content) < 1_000_000:
            result["ckl_content"] = ckl_content
        
        return result
    except Exception as e:
        logger.error(f"generate_ckl error: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool(name="execute_command")
def execute_command(
    command: str,
    rule_id: str,
    use_sudo: bool = False,
    max_retries: int = 3,
    host: str = None,
    user: str = None,
    password: str = None,
    key_path: str = None,
    port: int = None,
    timeout: int = None
):
    """
    Execute STIG validation command on remote RHEL 8 target via SSH.
    
    Uses blacklist-only validation (no whitelist) to block dangerous commands
    while allowing all safe STIG check commands.
    
    Args:
        command: Shell command to execute on target host
        rule_id: STIG rule identifier for audit logging
        use_sudo: Whether to use sudo (default: False)
        max_retries: Maximum retry attempts (default: 3)
        host: Optional SSH host override
        user: Optional SSH user override
        password: Optional SSH password override
        key_path: Optional SSH key path override
        port: Optional SSH port override
        timeout: Optional SSH timeout override
    
    Returns:
        dict with: status, output, exit_code, error, execution_time, rule_id
    """
    tool = ARESCliMcpTool()
    return tool.run(
        command=command,
        rule_id=rule_id,
        use_sudo=use_sudo,
        max_retries=max_retries,
        host=host,
        user=user,
        password=password,
        key_path=key_path,
        port=port,
        timeout=timeout
    )


# Create REST API for Streamlit file downloads
rest_api = FastAPI(title="ARES MCP REST API", version="2.0.0")

@rest_api.post("/upload")
async def upload_file(file: UploadFile):
    """
    Upload CKL or CSV file from Streamlit for parsing.
    
    Workflow:
    1. Streamlit user uploads CKL/CSV file
    2. Streamlit calls: POST /api/upload (with file data)
    3. MCP server writes to /data/input/{filename}
    4. Streamlit calls Genesis Agent with filepath: '/data/input/{filename}'
    5. Agent calls MCP parse tool → file written to /data/output/
    6. Streamlit downloads parsed file via GET /api/files/{parsed_filename}
    
    Args:
        file: Uploaded file (CKL XML or CSV)
        
    Returns:
        Success status, filename, and full path for Genesis agent
    """
    try:
        # Ensure input directory exists (use /tmp for container write permissions)
        input_dir = Path("/tmp/data/input")
        input_dir.mkdir(parents=True, exist_ok=True)
        
        # Write uploaded file to input directory
        file_path = input_dir / file.filename
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        
        logger.info(f"File uploaded successfully: {file_path} ({file.size} bytes)")
        
        return {
            "success": True,
            "filename": file.filename,
            "path": str(file_path),
            "size_bytes": file.size,
            "message": f"File uploaded successfully: {file.filename}"
        }
    except Exception as e:
        logger.error(f"File upload failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")

@rest_api.get("/files/{filename}")
async def serve_file(filename: str):
    """
    Serve parsed JSON files to Streamlit.
    
    Streamlit workflow:
    1. Call Genesis Agent → Agent calls MCP tool → File written to /data/output/
    2. Agent returns metadata with filename
    3. Streamlit downloads: GET /api/files/{filename}
    
    Args:
        filename: Name of parsed JSON file (e.g., 'rhel8-prestige-auto_parsed.json')
        
    Returns:
        JSON file with full findings data
    """
    file_path = Path("/tmp/data/output") / filename
    
    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")
    
    logger.info(f"Serving file: {file_path}")
    return FileResponse(file_path, media_type="application/json")

@rest_api.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "services": {
            "mcp_protocol": "operational",
            "rest_api": "operational"
        }
    }

# Combine MCP and REST endpoints
# Genesis agents use /mcp (MCP protocol via SSE/JSON-RPC)
# Streamlit uses /api (REST API for file downloads)
mcp_app = mcp.http_app(path="/")
app = Starlette(
    routes=[
        Mount("/mcp", app=mcp_app),  # MCP protocol endpoint
        Mount("/api", app=rest_api),  # REST API endpoint
    ],
    lifespan=mcp_app.lifespan  # CRITICAL: Pass MCP lifespan to parent app
)

logger.info("="*60)
logger.info("ARES MCP Server v2.0.0 Initialized")
logger.info("="*60)
logger.info("MCP Tools registered: parse_ckl, parse_csv, generate_ckl, execute_command")
logger.info("Endpoints:")
logger.info("  - /mcp: MCP protocol (for Genesis agents)")
logger.info("  - /api/files/{filename}: File serving (for Streamlit)")
logger.info("  - /api/health: Health check")
logger.info("Output directory: /data/output")
logger.info("="*60)
