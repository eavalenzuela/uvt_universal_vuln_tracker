<#  update-db.ps1
    Usage examples:
      .\update-db.ps1
      .\update-db.ps1 -DatabaseUrl "postgresql+psycopg://uvt_user:uvt_pass@localhost:5432/uvt"
      .\update-db.ps1 -DatabaseUrl "sqlite:///uvt.db"

    Notes:
      - Postgres backups use pg_dump and restores use pg_restore. Ensure PostgreSQL client tools
        are installed and on PATH. You can also rely on standard PG* env vars (PGHOST, PGPORT,
        PGUSER, PGPASSWORD, PGDATABASE) if you prefer not to embed credentials in DATABASE_URL.
#>

[CmdletBinding()]
param(
  [string]$DatabaseUrl = "",
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

    if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
      $val = $val.Substring(1, $val.Length - 2)
    }

    [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
  }
}

if (-not (Test-Path ".\backend")) {
  Write-Err "Couldn't find .\backend. Run this script from the repo root."
  exit 1
}

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

Import-DotEnv ".\dev.env"

if (-not $env:FLASK_APP) {
  $env:FLASK_APP = $FlaskApp
}

if (-not [string]::IsNullOrWhiteSpace($DatabaseUrl)) {
  $env:DATABASE_URL = $DatabaseUrl
}

if (-not $env:DATABASE_URL) {
  Write-Err "DATABASE_URL not found (dev.env or param)."
  exit 1
}

Write-Info "FLASK_APP=$env:FLASK_APP"
Write-Info "DATABASE_URL=$env:DATABASE_URL"

$backupPath = $null
$databaseUrl = $env:DATABASE_URL

if ($databaseUrl -match '^sqlite:\/\/(.+)$') {
  $sqlitePath = $Matches[1]
  $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $dbDir = Split-Path $sqlitePath
  $dbLeaf = Split-Path $sqlitePath -Leaf
  if ([string]::IsNullOrWhiteSpace($dbDir)) { $dbDir = "." }

  $backupPath = Join-Path $dbDir "$dbLeaf.$timestamp.bak"
  Write-Info "Backing up SQLite DB to $backupPath ..."
  Copy-Item -Path $sqlitePath -Destination $backupPath -Force
} elseif ($databaseUrl.StartsWith("postgres", [System.StringComparison]::OrdinalIgnoreCase)) {
  $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $backupPath = Join-Path $PWD "uvt-postgres-$timestamp.dump"
  Write-Info "Backing up Postgres DB to $backupPath ..."
  & pg_dump -Fc -f $backupPath $databaseUrl | Out-Host
} else {
  Write-Err "Unsupported DATABASE_URL scheme."
  exit 1
}

$upgradeSucceeded = $false
try {
  Write-Info "Applying migrations (db upgrade)..."
  & $python -m flask --app $env:FLASK_APP db upgrade | Out-Host
  $upgradeSucceeded = $true
  Write-Info "Migrations applied successfully."
} catch {
  Write-Err "Migration failed: $($_.Exception.Message)"

  if ($backupPath) {
    try {
      if ($databaseUrl -match '^sqlite:\/\/(.+)$') {
        $sqlitePath = $Matches[1]
        Write-Warn "Restoring SQLite DB from $backupPath ..."
        Copy-Item -Path $backupPath -Destination $sqlitePath -Force
      } elseif ($databaseUrl.StartsWith("postgres", [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Warn "Restoring Postgres DB from $backupPath ..."
        & pg_restore --clean --if-exists -d $databaseUrl $backupPath | Out-Host
      }
      Write-Warn "Restore completed."
    } catch {
      Write-Err "Restore failed: $($_.Exception.Message)"
      exit 1
    }
  }

  exit 1
}

if (-not $upgradeSucceeded) {
  Write-Err "Migration did not complete."
  exit 1
}

Write-Info "Done."
