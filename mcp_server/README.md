# ARES STIG Parser MCP Server

**Version:** 1.3.0  
**Architecture:** File-based data transfer with dual endpoints

Model Context Protocol (MCP) server for parsing STIG compliance scan outputs from any tool (CKL/CSV formats) to a normalized Finding schema. Designed for AI-powered compliance automation with Genesis.

## What This MCP Server Does

**Tools Exposed:**
- `parse_ckl` - Parse CKL (Checklist XML) files, write to JSON, return metadata only
- `parse_csv` - Parse CSV files from any STIG tool, write to JSON, return metadata only

**REST API:**
- `POST /api/upload` - Upload CKL/CSV files from Streamlit (writes to /tmp/data/input/)
- `GET /api/files/{filename}` - Download parsed JSON files (for Streamlit)
- `GET /api/health` - Health check endpoint

**Architecture (v1.3.0):**
- Streamlit uploads files via POST /api/upload → stored at /tmp/data/input/
- Genesis agents call MCP parse tools with filepath
- MCP tools write full findings to `/tmp/data/output/{filename}_parsed.json`
- Return only metadata (~200 bytes) to Genesis agents (avoids LLM truncation)
- Streamlit downloads full JSON files via HTTP REST API

**Dual Endpoints Explained:**
- `/mcp` - MCP Protocol (SSE/JSON-RPC) for Genesis agents to discover and call tools
- `/api` - REST API (HTTP) for Streamlit file upload/download
- Both mounted on same server using Starlette routing, serve different consumers

**Use Case:** Enable Genesis AI agents to ingest STIG scan results from multiple tools (PreSTIGe, evaluate-STIG, SCAP Compliance Checker, etc.) in a unified format for automated reconciliation and validation.

---

## Deployment to (OpenShift)

### Prerequisites

1. **Panel Group Access**
   - Submit onboarding form: https://panel.example.internal/onboarding
   - Approval time: 1-2 business days
   - Provides: Namespace on OpenShift cluster

2. **Genesis Organization**
   - Name: `ARES`
   - MCP server will be visible to this org

3. **Container Image** (✅ Already Done)
   - Location: `registry.example.internal:443/your-group/ares/ares-mcp-server:1.3.0`
   - Size: ~190 MB
   - Status: Built and ready to push

4. **OpenShift CLI (`oc`)**
   - Download from: https://cluster.example.internal
   - Click `?` → `Command Line Tools` → Select your OS

---

## Deployment Steps (Once You Have Panel Access)

### Step 1: Configure GitLab Registry in Panel

1. Log in to Panel: https://panel.example.internal
2. Navigate to your panel-group settings
3. Go to: `Settings` → `Image Registries` tab
4. Click `+ Registry` and add:
   - **Registry URL:** `registry.example.internal:443`
   - **Username:** `your-user`
   - **Password:** Your GitLab Personal Access Token (PAT)
     - Create at: https://gitlab.example.internal/-/user_settings/personal_access_tokens
     - Required scopes: `read_registry`, `write_registry`

This allows OpenShift to authenticate and pull your container image.

### Step 2: Find Image Pull Secret in OpenShift

1. Log in to OpenShift console: https://cluster.example.internal
2. Select your Panel namespace/project (top-left dropdown)
3. Navigate: `Workloads` → `Secrets`
4. Find secret with type `kubernetes.io/dockerconfigjson`
5. **Copy the secret name** (e.g., `youthful-skunk`) - you'll need this for ksvc.yml

### Step 3: Update ksvc.yml

Edit `mcp_server/ksvc.yml` and replace placeholders:

```yaml
metadata:
  namespace: REPLACE_WITH_YOUR_NAMESPACE  # Your Panel group namespace
  
spec:
  template:
    spec:
      imagePullSecrets:
        - name: REPLACE_WITH_IMAGE_PULL_SECRET  # Secret name from Step 2
```

**Everything else is already configured:**
- ✅ Image URL: `registry.example.internal:443/your-group/ares/ares-mcp-server:1.3.0`
- ✅ Labels for Genesis discovery: `factory.ai/resource-type: mcp`
- ✅ Genesis org: `ARES`
- ✅ MCP path: `/mcp`
- ✅ Port: `8000`

### Step 4: Deploy to the cluster

```bash
# 1. Log in to OpenShift CLI
# Go to https://cluster.example.internal
# Click your username → "Copy login command" → "Display Token"
# Copy and run the command (looks like):
oc login --token=sha256~... --server=https://cluster-api.example.internal:6443

# 2. Verify you're in the correct namespace
oc project  # Shows current project
oc project <your-namespace>  # Switch if needed

# 3. Deploy the MCP server
cd mcp_server
oc apply -f ksvc.yml

# 4. Verify deployment
oc get ksvc ares-stig-parser
oc get pods | grep ares-stig-parser

# 5. Check logs if needed
oc logs -l app=ares-stig-parser --tail=50
```

### Step 5: Verify in Genesis

1. Wait 2-3 minutes for Genesis to discover the service
2. Go to: https://genesis.example.internal/tools
3. Search: `ares-stig-parser`
4. Verify tools are visible: `parse_ckl`, `parse_csv`

---

## Rebuilding the Container Image (If Needed)

If you make code changes and need to rebuild:

```bash
# 1. Rebuild container
cd mcp_server
podman build -t ares-mcp-server:1.3.0 .

# 2. Tag for GitLab
podman tag ares-mcp-server:1.3.0 registry.example.internal:443/your-group/ares/ares-mcp-server:1.3.0

# 3. Login to GitLab registry (if not already logged in)
podman login --tls-verify=false registry.example.internal:443
# Username: your-user
# Password: [Your GitLab PAT]

# 4. Push to GitLab
podman push --tls-verify=false registry.example.internal:443/your-group/ares/ares-mcp-server:1.3.0

# 5. Apply updated ksvc.yml (if image tag changed)
oc apply -f ksvc.yml

# 6. Watch rollout
oc get ksvc ares-stig-parser -w
```

**Note:** Use `--tls-verify=false` flag with Podman to handle corporate SSL inspection.

---

## Local Development & Testing

### Run MCP Server Locally

```bash
# From project root
cd mcp_server

# Install in editable mode
pip install -e .

# Run server
python -m mcp_server

# Server starts on: http://localhost:8000/mcp
```

### Test with MCP Inspector

```bash
# Install MCP Inspector globally
npm install -g @modelcontextprotocol/inspector

# Test the server
npx @modelcontextprotocol/inspector python -m mcp_server
```

This opens a web UI where you can:
- View available tools (`parse_ckl`, `parse_csv`)
- Test tool invocations with sample file paths
- Inspect request/response payloads

---

## Architecture

**Container Structure:**
```
/app/
├── mcp_server/
│   ├── server.py          # FastMCP server with tool definitions
│   ├── parsers/
│   │   ├── ckl_parser.py  # CKL XML parser
│   │   └── csv_parser.py  # CSV parser
│   └── schemas/
│       └── finding.py     # Normalized Finding schema
├── pyproject.toml         # Package metadata
└── Dockerfile             # Container image definition
```

**MCP Server:**
- Framework: FastMCP (recommended by the internal MCP docs)
- Transport: HTTP/SSE (Server-Sent Events)
- Port: 8000
- Path: /mcp

**Tools:**
1. `parse_ckl(filepath: str)` → List[Finding]
2. `parse_csv(filepath: str)` → List[Finding]

**Normalized Finding Schema:**
```python
{
  "vuln_id": str,           # e.g., "V-230221"
  "rule_id": str,           # e.g., "SV-230221r627750_rule"
  "severity": str,          # "high", "medium", "low"
  "status": str,            # "Open", "NotAFinding", "Not_Reviewed"
  "finding_details": str,   # Evidence/justification
  "comments": str,          # Additional notes
  "stig_title": str         # Human-readable rule title
}
```

---

## Troubleshooting

### Issue: Genesis shows "No tools available"

**Cause:** MCP server not running or not discoverable.

**Solution:**
1. Check pod is running: `oc get pods -l app=ares-stig-parser`
2. Check logs: `oc logs -l app=ares-stig-parser --tail=100`
3. Verify labels in ksvc.yml:
   - `factory.ai/resource-type: mcp`
   - `factory.ai/api-env: prod`
4. Wait 2-3 minutes for Genesis to re-scan

### Issue: Image pull error

**Cause:** OpenShift can't authenticate to GitLab registry.

**Solution:**
1. Verify registry configured in Panel: `Settings` → `Image Registries`
2. Check image pull secret exists: `oc get secrets`
3. Verify secret name matches ksvc.yml: `spec.template.spec.imagePullSecrets[].name`
4. Test manual pull: `podman pull --tls-verify=false registry.example.internal:443/your-group/ares/ares-mcp-server:1.3.0`

### Issue: Pod stuck in "Not Ready"

**Cause:** Container starting up or failing health checks.

**Solution:**
1. Check logs: `oc logs -l app=ares-stig-parser`
2. Check events: `oc get events | grep ares-stig-parser`
3. Verify container starts locally: `podman run -p 8000:8000 ares-mcp-server:1.3.0`

---

## Files in This Directory

**Core Files (DO NOT DELETE):**
- `server.py` - MCP server implementation
- `parsers/` - CKL and CSV parsing logic
- `schemas/` - Finding schema definition
- `Dockerfile` - Container image build instructions
- `pyproject.toml` - Python package configuration
- `ksvc.yml` - Knative service deployment manifest

**Supporting Files:**
- `__init__.py` - Package initialization
- `__main__.py` - Module entry point
- `README.md` - This file

---

## References

- **MCP Community Docs:** https://mcp.example.internal/docs/
- **MCP Catalog:** https://factory.example.internal/docs/genesis/mcp-server-catalog
- **Panel:** https://panel.example.internal
- **OpenShift:** https://cluster.example.internal
- **Genesis:** https://genesis.example.internal

---

## Support

**For deployment help:**
- Teams channel: US-AI-Factory

**For ARES project questions:**
- The ARES maintainers
- ARES AI Intern Challenge team
