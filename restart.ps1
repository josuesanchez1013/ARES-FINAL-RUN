# ARES Demo Restart Script
# Clears Python cache and starts Streamlit in NETWORK MODE for judge access

# Kill Python
Write-Host "Stopping any running Python processes..." -ForegroundColor Yellow
taskkill /F /IM python.exe 2>$null | Out-Null
Start-Sleep -Seconds 1

# Clear cache
Write-Host "Clearing Python cache..." -ForegroundColor Yellow
Get-ChildItem -Recurse -Filter "__pycache__" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -Filter "*.pyc" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "  ARES DEMO SERVER - STARTING  " -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starting Streamlit in NETWORK MODE..." -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT: This server is accessible to ANYONE on your network." -ForegroundColor Yellow
Write-Host "Only ONE workflow can run at a time." -ForegroundColor Yellow
Write-Host ""

# Get local IP address
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -like "10.*"}).IPAddress | Select-Object -First 1

Write-Host "Access URLs:" -ForegroundColor Green
Write-Host "  Local:   http://localhost:8501" -ForegroundColor White
if ($localIP) {
    Write-Host "  Network: http://${localIP}:8501" -ForegroundColor White
    Write-Host ""
    Write-Host "Share this link with judges: http://${localIP}:8501" -ForegroundColor Cyan
} else {
    Write-Host "  Network: (IP address not detected - check manually)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Start Streamlit
python -m streamlit run ui/streamlit_app.py
