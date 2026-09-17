# SignalTrust — start the backend and open the frontend
# Run this from C:\Users\HP\SignalTrust\

$backendDir = "$PSScriptRoot\backend"
$frontendFile = "$PSScriptRoot\frontend\index.html"

Write-Host ""
Write-Host "  SignalTrust — Distributed Trust Intelligence Network" -ForegroundColor Cyan
Write-Host "  ─────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# Check if port 8001 is already in use
$portInUse = netstat -ano | Select-String ":8001 " | Select-String "LISTENING"
if ($portInUse) {
    Write-Host "  [!] Port 8001 already in use. Kill the existing process first." -ForegroundColor Yellow
    Write-Host "      netstat -ano | findstr :8001" -ForegroundColor DarkGray
    exit 1
}

# Seed database if it doesn't exist yet
if (-not (Test-Path "$backendDir\signaltrust.db")) {
    Write-Host "  [*] First run — seeding database..." -ForegroundColor Yellow
    python "$backendDir\seed.py"
}

Write-Host "  [*] Starting backend on http://127.0.0.1:8001 ..." -ForegroundColor Green
Write-Host "  [*] Open frontend: $frontendFile" -ForegroundColor Green
Write-Host "  [*] API docs:       http://127.0.0.1:8001/docs" -ForegroundColor Green
Write-Host ""
Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

# Open the frontend in the default browser
Start-Process $frontendFile

# Start uvicorn (blocks until Ctrl+C)
Set-Location $backendDir
python -m uvicorn main:app --host 127.0.0.1 --port 8001
