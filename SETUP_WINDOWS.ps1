# ============================================================
#  GLITCHICONS v0.7.0 - Windows 11 Setup Script
#  Run in PowerShell from D:\project\glitchicons
# ============================================================

$ErrorActionPreference = "Stop"
$TARGET_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  GLITCHICONS SETUP - v0.7.0" -ForegroundColor Cyan
Write-Host "  ==========================" -ForegroundColor Cyan
Write-Host "  Target: $TARGET_DIR"
Write-Host ""

# --- 1. Cek Prerequisites ---
Write-Host "[1/6] Mengecek prerequisites..." -ForegroundColor Yellow

function Check-Command($cmd) {
    return [bool](Get-Command $cmd -ErrorAction SilentlyContinue)
}

$missing = @()
if (-not (Check-Command "git"))    { $missing += "git" }
if (-not (Check-Command "python")) { $missing += "python 3.10+" }
if (-not (Check-Command "docker")) { $missing += "docker (Docker Desktop)" }

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "  ERROR: Dependency berikut belum terinstall:" -ForegroundColor Red
    foreach ($dep in $missing) {
        Write-Host "     - $dep" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  Download:" -ForegroundColor Yellow
    Write-Host "    Git    : https://git-scm.com/download/win"
    Write-Host "    Python : https://www.python.org/downloads/"
    Write-Host "    Docker : https://www.docker.com/products/docker-desktop/"
    exit 1
}

Write-Host "  OK - git, python, docker tersedia" -ForegroundColor Green

# --- 2. Python Virtual Environment ---
Write-Host "[2/6] Membuat Python virtual environment..." -ForegroundColor Yellow

Set-Location $TARGET_DIR

if (-not (Test-Path "$TARGET_DIR\.venv")) {
    python -m venv "$TARGET_DIR\.venv"
    Write-Host "  OK - venv dibuat" -ForegroundColor Green
} else {
    Write-Host "  OK - venv sudah ada, skip" -ForegroundColor Cyan
}

$pip = "$TARGET_DIR\.venv\Scripts\pip.exe"
$python = "$TARGET_DIR\.venv\Scripts\python.exe"

Write-Host "  Upgrade pip..." -ForegroundColor Cyan
& $pip install --upgrade pip -q

Write-Host "  Install requirements..." -ForegroundColor Cyan
& $pip install -r "$TARGET_DIR\requirements.txt" -q

Write-Host "  Install dev tools (pytest, ruff, bandit, responses)..." -ForegroundColor Cyan
& $pip install pytest pytest-cov ruff bandit responses httpretty -q

Write-Host "  OK - dependencies terinstall" -ForegroundColor Green

# --- 3. Buat .env file ---
Write-Host "[3/6] Membuat .env file..." -ForegroundColor Yellow

$envFile = "$TARGET_DIR\.env"
if (-not (Test-Path $envFile)) {
    $envContent = @"
# GLITCHICONS Environment Configuration
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:3b
GLITCHICONS_OUTPUT_DIR=./findings
GLITCHICONS_LOG_LEVEL=INFO

# Optional: Cloud LLM (uncomment jika mau pakai)
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
"@
    $envContent | Out-File -FilePath $envFile -Encoding UTF8
    Write-Host "  OK - .env dibuat (edit sesuai kebutuhan)" -ForegroundColor Green
} else {
    Write-Host "  OK - .env sudah ada, skip" -ForegroundColor Cyan
}

# --- 4. Buat folder struktur ---
Write-Host "[4/6] Membuat folder struktur..." -ForegroundColor Yellow

$folders = @("findings", "engagements", "findings\reports", "findings\crashes", "findings\recon")
foreach ($folder in $folders) {
    $path = "$TARGET_DIR\$folder"
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
        Write-Host "  Created: $folder" -ForegroundColor Cyan
    }
}
Write-Host "  OK - folder struktur siap" -ForegroundColor Green

# --- 5. Cek Docker ---
Write-Host "[5/6] Mengecek Docker Desktop..." -ForegroundColor Yellow

$dockerInfo = docker info 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK - Docker Desktop berjalan" -ForegroundColor Green
    Write-Host "  TIP: jalankan 'docker-compose up -d' untuk start Ollama" -ForegroundColor Cyan
} else {
    Write-Host "  WARNING: Docker Desktop belum running." -ForegroundColor Yellow
    Write-Host "           Start dulu dari system tray, lalu jalankan:" -ForegroundColor Yellow
    Write-Host "           docker-compose up -d" -ForegroundColor Cyan
}

# --- 6. Jalankan Tests ---
Write-Host "[6/6] Menjalankan test suite..." -ForegroundColor Yellow

$pytest = "$TARGET_DIR\.venv\Scripts\pytest.exe"
& $pytest "$TARGET_DIR\tests\" -v --tb=short 2>&1 | Tee-Object -Variable testOutput

if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK - Semua tests passed" -ForegroundColor Green
} else {
    Write-Host "  WARNING: Ada tests yang fail (lihat output di atas)" -ForegroundColor Yellow
    Write-Host "           Ini normal jika modul glitchicons belum semuanya siap" -ForegroundColor Cyan
}

# --- Done ---
Write-Host ""
Write-Host "  SETUP SELESAI!" -ForegroundColor Green
Write-Host ""
Write-Host "  Project location : $TARGET_DIR" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "    1. .\.venv\Scripts\Activate.ps1"
Write-Host "    2. docker-compose up -d          -> start Ollama + Tor"
Write-Host "    3. python glitchicons.py status   -> cek semua module"
Write-Host "    4. pytest tests\ -v               -> jalankan test suite"
Write-Host ""
Write-Host "  Happy hacking!" -ForegroundColor Cyan
Write-Host ""
