<#  setup-dev.ps1
    Usage examples:
      .\setup-dev.ps1
      .\setup-dev.ps1 -DatabaseUrl "postgresql+psycopg://uvt_user:uvt_pass@localhost:5432/uvt"
      .\setup-dev.ps1 -DatabaseUrl "sqlite:///uvt.db"
#>

[CmdletBinding()]
param(
  [string]$DatabaseUrl = "",
  [string]$VenvPath = ".venv",
  [string]$FlaskApp = "backend.uvt_app:create_app"
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[UVT] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[UVT] $msg" -ForegroundColor Yellow }
function Write-Err ($msg) { Write-Host "[UVT] $msg" -ForegroundColor Red }

function Import-DotEnv([string]$Path) {
  if (-not (Test-Path $Path)) { return }

  Write-Info "Loading environment from $Path ..."
  Get-Content $Path | ForEach-Object {
    $line = $_.Trim()
    if (-not $line) { return }
    if ($line.StartsWith("#")) { return }

    $idx = $line.IndexOf("=")
    if ($idx -lt 1) { return }

    $key = $line.Substring(0, $idx).Trim()
    $val = $line.Substring($idx + 1).Trim()

    # Strip surrounding quotes if present
    if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
      $val = $val.Substring(1, $val.Length - 2)
    }

    [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
  }
}

# --- Ensure we're running from repo root (expect backend/) ---
if (-not (Test-Path ".\backend")) {
  Write-Err "Couldn't find .\backend. Run this script from the repo root."
  exit 1
}

# --- Find Python ---
$python = $null
foreach ($cmd in @("python3", "python")) {
  try {
    & $cmd -c "import sys; print(sys.executable)" | Out-Null
    $python = $cmd
    break
  } catch { }
}
if (-not $python) {
  Write-Err "Python not found. Install Python 3.11+ and ensure it's on PATH."
  exit 1
}

Write-Info "Using Python command: $python"
Write-Info "Repo root: $PWD"

# --- Create venv if needed ---
if (-not (Test-Path $VenvPath)) {
  Write-Info "Creating venv at $VenvPath ..."
  & $python -m venv $VenvPath
} else {
  Write-Info "Venv exists at $VenvPath"
}

# --- Activate venv ---
$activateScript = Join-Path $VenvPath "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
  Write-Err "Venv activation script not found: $activateScript"
  exit 1
}

# If execution policy blocks activation, give a helpful note
try {
  . $activateScript
} catch {
  Write-Warn "PowerShell blocked script execution. Try:"
  Write-Warn "  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
  throw
}

Write-Info "Venv activated: $(& $python -c 'import sys; print(sys.executable)')"

# --- Upgrade pip tooling ---
Write-Info "Upgrading pip/setuptools/wheel..."
& $python -m pip install --upgrade pip setuptools wheel | Out-Host

# --- Install dependencies ---
# Prefer requirements.txt if present, otherwise install a known-good minimal set
if (Test-Path ".\requirements.txt") {
  Write-Info "Installing dependencies from requirements.txt..."
  & $python -m pip install -r .\requirements.txt | Out-Host
  if ($env:DATABASE_URL -like "postgres*" -and (Test-Path ".\requirements-postgres.txt")) {
    Write-Info "PostgreSQL detected — installing psycopg driver..."
    & $python -m pip install -r .\requirements-postgres.txt | Out-Host
  }
} else {
  Write-Info "requirements.txt not found; installing baseline dependencies..."
  & $python -m pip install `
    flask flask_sqlalchemy flask_cors `
    pyjwt werkzeug | Out-Host
}

# --- Configure environment variables for current session ---
# Load dev.env if present
Import-DotEnv ".\dev.env"

# Configure environment variables for current session
$env:FLASK_APP = $(if ($env:FLASK_APP) { $env:FLASK_APP } else { $FlaskApp })
$env:FLASK_ENV = $(if ($env:FLASK_ENV) { $env:FLASK_ENV } else { "development" })

if (-not [string]::IsNullOrWhiteSpace($DatabaseUrl)) {
  $env:DATABASE_URL = $DatabaseUrl
} elseif (-not $env:DATABASE_URL) {
  Write-Warn "No DATABASE_URL found (dev.env or param). Defaulting to SQLite (sqlite:///uvt.db)."
  $env:DATABASE_URL = "sqlite:///uvt.db"
}

if (-not $env:JWT_SECRET) { $env:JWT_SECRET = "dev-jwt-secret" }
if (-not $env:SECRET_KEY) { $env:SECRET_KEY = "dev-secret" }

Write-Info "FLASK_APP=$env:FLASK_APP"
Write-Info "DATABASE_URL=$env:DATABASE_URL"

# --- Sanity: can Flask import the app? ---
Write-Info "Verifying Flask can load the app..."
& $python -m flask --app $env:FLASK_APP routes | Out-Null
Write-Info "App import OK."

# --- Create database tables ---
Write-Info "Creating database tables..."
& $python -c @"
from backend.uvt_app import create_app
from backend.database import db
app = create_app()
with app.app_context():
    db.create_all()
    print('[UVT] Tables created.')
"@ | Out-Host

Write-Info "Done."
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  1) Start the API:" -ForegroundColor Green
Write-Host "     $python -m flask --app $FlaskApp run" -ForegroundColor Green
Write-Host ""
Write-Host "  2) (Optional) Register admin via API if fresh DB:" -ForegroundColor Green
Write-Host "     POST http://127.0.0.1:5000/api/auth/register" -ForegroundColor Green
Write-Host ""
Write-Warn "Note: Env vars set by this script only apply to the current PowerShell session."
