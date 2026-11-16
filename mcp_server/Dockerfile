FROM python:3.10-slim

WORKDIR /app

# Copy project configuration (from mcp_server/ and root)
COPY mcp_server/pyproject.toml ./
COPY README.md ./

# Copy mcp_server package
COPY mcp_server/server.py mcp_server/__init__.py mcp_server/__main__.py ./mcp_server/
COPY mcp_server/parsers/ ./mcp_server/parsers/
COPY mcp_server/schemas/ ./mcp_server/schemas/
COPY mcp_server/generators/ ./mcp_server/generators/

# Copy cli_executor package (for execute_command tool)
COPY cli_executor/ ./cli_executor/

# Copy security package (for command validation)
COPY security/ ./security/

# Install dependencies (with trusted-host for corporate SSL inspection)
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org -e .

# Expose port 8000 for MCP server
EXPOSE 8000

# Run MCP server
CMD ["python", "-m", "mcp_server"]
