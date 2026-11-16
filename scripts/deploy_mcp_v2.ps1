# Deploy ARES MCP Server v2.0.0 to OpenShift
# Includes execute_command tool with CLI executor
# Run from project root: .\scripts\deploy_mcp_v2.ps1

$ErrorActionPreference = "Stop"

# Load environment variables
if (Test-Path ".env") {
    Write-Host "Loading .env file..." -ForegroundColor Cyan
    Get-Content .env | ForEach-Object {
        if ($_ -match "^([^=]+)=(.*)$") {
            $key = $matches[1]
            $value = $matches[2]
            [System.Environment]::SetEnvironmentVariable($key, $value, "Process")
        }
    }
} else {
    Write-Host "ERROR: .env file not found!" -ForegroundColor Red
    exit 1
}

# Configuration
$PROJECT_ROOT = (Get-Location).Path
$VERSION = "2.0.0"
$IMAGE_NAME = "ares-mcp-server"
$REGISTRY = $env:GITLAB_REGISTRY
$FULL_IMAGE = "${REGISTRY}/${env:GITLAB_USER}/ares-ai-intern-challenge/${IMAGE_NAME}:${VERSION}"
$OPENSHIFT_PROJECT = $env:OPENSHIFT_PROJECT

Write-Host "="*80 -ForegroundColor Yellow
Write-Host "ARES MCP Server v${VERSION} Deployment" -ForegroundColor Yellow
Write-Host "="*80 -ForegroundColor Yellow
Write-Host "Image: $FULL_IMAGE" -ForegroundColor Cyan
Write-Host "OpenShift Project: $OPENSHIFT_PROJECT" -ForegroundColor Cyan
Write-Host "="*80 -ForegroundColor Yellow

# Step 1: Login to GitLab Container Registry
Write-Host "`n[1/6] Logging into GitLab Container Registry..." -ForegroundColor Green
wsl bash -c "echo '$env:GITLAB_PAT' | podman login --tls-verify=false $REGISTRY -u $env:GITLAB_USER --password-stdin"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Podman login failed!" -ForegroundColor Red
    Write-Host "Try: wsl --shutdown && wsl" -ForegroundColor Yellow
    exit 1
}
Write-Host "✅ Logged in successfully" -ForegroundColor Green

# Step 2: Build container image with Podman
Write-Host "`n[2/6] Building container image with Podman..." -ForegroundColor Green
Write-Host "Build context: mcp_server/" -ForegroundColor Cyan
Write-Host "Dockerfile: mcp_server/Dockerfile" -ForegroundColor Cyan

# Change to mcp_server directory for build (Dockerfile expects to be run from there)
Push-Location mcp_server
try {
    # Build from mcp_server directory using WSL podman
    wsl bash -c "cd /mnt/c/Users/your-group/ares && podman build -f mcp_server/Dockerfile -t $FULL_IMAGE ."
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Podman build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Image built successfully" -ForegroundColor Green
}
finally {
    Pop-Location
}

# Step 3: Push to GitLab Container Registry
Write-Host "`n[3/6] Pushing image to GitLab Container Registry..." -ForegroundColor Green
wsl bash -c "podman push --tls-verify=false $FULL_IMAGE"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Podman push failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Image pushed successfully" -ForegroundColor Green

# Step 4: Login to OpenShift
Write-Host "`n[4/6] Logging into OpenShift..." -ForegroundColor Green
& $env:OC_CLI_PATH login --token=$env:OPENSHIFT_TOKEN --server=$env:OPENSHIFT_SERVER --insecure-skip-tls-verify
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: OpenShift login failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Logged into OpenShift" -ForegroundColor Green

# Switch to project
Write-Host "Switching to project: $OPENSHIFT_PROJECT" -ForegroundColor Cyan
& $env:OC_CLI_PATH project $OPENSHIFT_PROJECT
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to switch to project $OPENSHIFT_PROJECT!" -ForegroundColor Red
    exit 1
}

# Step 5: Set environment variables for SSH connection
Write-Host "`n[5/6] Setting SSH environment variables..." -ForegroundColor Green
$SSH_HOST = $env:ARES_SSH_HOST
$SSH_USER = $env:ARES_SSH_USER
$SSH_PASSWORD = $env:ARES_SSH_PASSWORD
$SSH_PORT = $env:ARES_SSH_PORT
$SSH_TIMEOUT = $env:ARES_SSH_TIMEOUT

Write-Host "SSH Target: ${SSH_USER}@${SSH_HOST}:${SSH_PORT}" -ForegroundColor Cyan

& $env:OC_CLI_PATH set env deployment/ares-stig-parser `
    ARES_SSH_HOST=$SSH_HOST `
    ARES_SSH_USER=$SSH_USER `
    ARES_SSH_PASSWORD=$SSH_PASSWORD `
    ARES_SSH_PORT=$SSH_PORT `
    ARES_SSH_TIMEOUT=$SSH_TIMEOUT

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to set environment variables!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Environment variables set" -ForegroundColor Green

# Step 6: Update deployment image
Write-Host "`n[6/6] Updating deployment image to v${VERSION}..." -ForegroundColor Green
& $env:OC_CLI_PATH set image deployment/ares-stig-parser ares-stig-parser=$FULL_IMAGE
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to update deployment image!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Deployment updated" -ForegroundColor Green

# Wait for rollout
Write-Host "`nWaiting for rollout to complete..." -ForegroundColor Cyan
& $env:OC_CLI_PATH rollout status deployment/ares-stig-parser --timeout=5m
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Rollout status check failed or timed out" -ForegroundColor Yellow
    Write-Host "Check deployment status manually with: oc get pods" -ForegroundColor Yellow
}

# Get deployment info
Write-Host "`n"+"="*80 -ForegroundColor Yellow
Write-Host "DEPLOYMENT SUMMARY" -ForegroundColor Yellow
Write-Host "="*80 -ForegroundColor Yellow

Write-Host "`nPods:" -ForegroundColor Cyan
& $env:OC_CLI_PATH get pods -l app=ares-stig-parser

Write-Host "`nService URL:" -ForegroundColor Cyan
Write-Host $env:MCP_SERVER_URL -ForegroundColor Green

Write-Host "`nDeployment Status:" -ForegroundColor Cyan
& $env:OC_CLI_PATH get deployment ares-stig-parser

Write-Host "`n"+"="*80 -ForegroundColor Yellow
Write-Host "✅ MCP Server v${VERSION} deployed successfully!" -ForegroundColor Green
Write-Host "="*80 -ForegroundColor Yellow

Write-Host "`nMCP Tools Available:" -ForegroundColor Cyan
Write-Host "  ✓ parse_ckl      - Parse CKL XML files" -ForegroundColor White
Write-Host "  ✓ parse_csv      - Parse CSV files" -ForegroundColor White
Write-Host "  ✓ generate_ckl   - Generate reconciled CKL" -ForegroundColor White
Write-Host "  ✓ execute_command - Execute STIG validation commands via SSH (NEW!)" -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "  1. Test execute_command tool: python scripts/test_execute_command_mcp.py" -ForegroundColor White
Write-Host "  2. Test in Streamlit: python -m streamlit run ui/streamlit_app.py" -ForegroundColor White
Write-Host "  3. Check logs: oc logs -f deployment/ares-stig-parser" -ForegroundColor White

Write-Host "`n"+"="*80 -ForegroundColor Yellow
