#!/usr/bin/env bash
# update-db.sh — back up the database, then apply Alembic migrations.
#
# Usage:
#   ./update-db.sh
#   ./update-db.sh --database-url "postgresql+psycopg://uvt_user:uvt_pass@localhost:5432/uvt"
#   ./update-db.sh --database-url "sqlite:///uvt.db"
#   ./update-db.sh --dry-run          # show pending revisions, change nothing
#
# On failure this script STOPS and tells you where the backup is. It does not
# restore automatically.
#
# The previous version ran `flask db upgrade` — a command that did not exist,
# because Flask-Migrate had been removed — and treated the resulting non-zero
# exit as a failed migration, which sent it down a
# `pg_restore --clean --if-exists` path against the live database. The
# documented upgrade procedure therefore always failed and always dropped and
# recreated every object, while migrating nothing. Restoring a backup over a
# live database is a decision for an operator looking at the error, not
# something a script should do on its own.
#
# Requirements: PostgreSQL client tools (pg_dump) for Postgres deployments.

set -euo pipefail

DATABASE_URL=""
DEFAULT_FLASK_APP="backend.uvt_app:create_app"
FLASK_APP_PARAM="$DEFAULT_FLASK_APP"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database-url) DATABASE_URL="$2"; shift 2 ;;
    --flask-app)    FLASK_APP_PARAM="$2"; shift 2 ;;
    --dry-run)      DRY_RUN=true; shift ;;
    -h|--help)      sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "[UVT] Unknown argument: $1" >&2; exit 1 ;;
  esac
done

info() { printf '[UVT] %s\n' "$1"; }
warn() { printf '[UVT] %s\n' "$1" >&2; }
err()  { printf '[UVT] %s\n' "$1" >&2; }

import_dotenv() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  info "Loading environment from $path ..."
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* || "$line" != *"="* ]] && continue
    local key="${line%%=*}" val="${line#*=}"
    key="${key//[[:space:]]/}"
    val="${val#"${val%%[![:space:]]*}"}"
    if [[ "$val" == \"*\" || "$val" == \'*\' ]]; then
      val="${val:1:${#val}-2}"
    fi
    export "$key=$val"
  done < "$path"
}

if [[ ! -d "backend" ]]; then
  err "Couldn't find ./backend. Run this script from the repo root."
  exit 1
fi

python_cmd=""
for cmd in python3 python; do
  if "$cmd" -c "import sys" >/dev/null 2>&1; then python_cmd="$cmd"; break; fi
done
if [[ -z "$python_cmd" ]]; then
  err "Python not found. Install Python 3.11+ and ensure it's on PATH."
  exit 1
fi

import_dotenv "backend/dev.env"
import_dotenv ".env"

export FLASK_APP="${FLASK_APP:-$FLASK_APP_PARAM}"
[[ -n "$DATABASE_URL" ]] && export DATABASE_URL="$DATABASE_URL"

if [[ -z "${DATABASE_URL:-}" ]]; then
  err "DATABASE_URL not found (pass --database-url, or set it in .env)."
  exit 1
fi

info "FLASK_APP=$FLASK_APP"
info "Database: ${DATABASE_URL%%:*}://…"

info "Current revision:"
"$python_cmd" -m flask db current 2>&1 | sed 's/^/  /' || true
info "Target revision:"
"$python_cmd" -m flask db heads 2>&1 | sed 's/^/  /' || true

if [[ "$DRY_RUN" == true ]]; then
  info "Dry run — no changes made."
  exit 0
fi

# --- backup --------------------------------------------------------------
backup_path=""
if [[ "$DATABASE_URL" =~ ^sqlite:///(.+)$ ]]; then
  sqlite_path="${BASH_REMATCH[1]}"
  if [[ -f "$sqlite_path" ]]; then
    backup_path="${sqlite_path}.$(date +%Y%m%d-%H%M%S).bak"
    info "Backing up SQLite database to $backup_path ..."
    cp -f "$sqlite_path" "$backup_path"
  else
    info "SQLite database does not exist yet; it will be created."
  fi
elif [[ "$DATABASE_URL" == postgres* ]]; then
  if ! command -v pg_dump >/dev/null 2>&1; then
    err "pg_dump not found. Install the PostgreSQL client tools, or take a backup"
    err "another way and re-run with the backup already in place."
    exit 1
  fi
  backup_path="$(pwd)/uvt-postgres-$(date +%Y%m%d-%H%M%S).dump"
  info "Backing up PostgreSQL database to $backup_path ..."
  # SQLAlchemy's +driver suffix is not valid libpq syntax.
  pg_dump -Fc -f "$backup_path" "${DATABASE_URL/+psycopg/}"
else
  err "Unsupported DATABASE_URL scheme."
  exit 1
fi

# --- migrate -------------------------------------------------------------
info "Applying migrations ..."
if "$python_cmd" -m flask db upgrade; then
  info "Migrations applied successfully."
  "$python_cmd" -m flask db current 2>&1 | sed 's/^/  /' || true
  [[ -n "$backup_path" ]] && info "Backup retained at $backup_path"
  exit 0
fi

err ""
err "Migration FAILED. The database has NOT been modified beyond whatever the"
err "failed revision committed before erroring — Alembic runs each revision in"
err "a transaction, so a failed revision is rolled back."
err ""
if [[ -n "$backup_path" ]]; then
  err "A pre-migration backup is at:"
  err "    $backup_path"
  err ""
  err "Inspect the error above first. Restore only if you have decided that is"
  err "the right move — it discards everything written since the backup:"
  if [[ "$DATABASE_URL" =~ ^sqlite:///(.+)$ ]]; then
    err "    cp '$backup_path' '${BASH_REMATCH[1]}'"
  else
    err "    pg_restore --clean --if-exists -d '${DATABASE_URL/+psycopg/}' '$backup_path'"
  fi
fi
exit 1
