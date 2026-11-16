"""
Entry point for running ARES MCP server as a module.

Usage:
    python -m mcp_server
    
Version 1.3.0: File-based architecture with dual endpoints
- MCP protocol (/mcp) for Genesis agents - returns metadata only
- REST API (/api) for Streamlit file downloads - serves full JSON
- Tools write findings to /data/output/ (avoids LLM truncation)
- Starlette combines both FastMCP and FastAPI endpoints
"""

if __name__ == "__main__":
    import os
    import uvicorn
    from .server import app
    import logging
    
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Get host/port from environment (for Knative compatibility)
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8000"))
    
    logger.info(f"Starting ARES MCP Server v1.3.0 on {host}:{port}")
    logger.info("Architecture: Dual endpoints (MCP + REST API)")
    logger.info("MCP endpoint: /mcp (Genesis agents)")
    logger.info("REST endpoint: /api/files (Streamlit downloads)")
    logger.info("File-based data transfer (metadata only through LLM)")
    
    # Run with uvicorn - app is FastMCP's ASGI application
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )
