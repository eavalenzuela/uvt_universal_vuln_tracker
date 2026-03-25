#!/usr/bin/env bash
# update-db.sh
# Usage examples:
#   ./update-db.sh
#   ./update-db.sh --database-url "postgresql+psycopg://uvt_user:uvt_pass@localhost:5432/uvt"
#   ./update-db.sh --database-url "sqlite:///uvt.db"
#
# Notes:
#   - Postgres backups use pg_dump and restores use pg_restore. Ensure PostgreSQL client tools
#     are installed and on PATH. You can also rely on standard PG* env vars (PGHOST, PGPORT,
#     PGUSER, PGPASSWORD, PGDATABASE) if you prefer not to embed credentials in DATABASE_URL.

set -euo pipefail

DATABASE_URL=""
DEFAULT_FLASK_APP="backend.uvt_app:create_app"
FLASK_APP_PARAM="$DEFAULT_FLASK_APP"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database-url)
      DATABASE_URL="$2"
      shift 2
      ;;
    --flask-app)
      FLASK_APP_PARAM="$2"
      shift 2
      ;;
    *)
      echo "[UVT] Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

write_info() { printf '[UVT] %s\n' "$1"; }
write_warn() { printf '[UVT] %s\n' "$1" >&2; }
write_err() { printf '[UVT] %s\n' "$1" >&2; }

import_dotenv() {
  local path="$1"
  [[ -f "$path" ]] || return 0

  write_info "Loading environment from $path ..."
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line## }"
    line="${line%% }"
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue

    if [[ "$line" != *"="* ]]; then
      continue
    fi

    local key="${line%%=*}"
    local val="${line#*=}"

    key="${key## }"
    key="${key%% }"
    val="${val## }"
    val="${val%% }"

    if [[ "$val" == "\""*"\"" ]] || [[ "$val" == "'"*"'" ]]; then
      val="${val:1:${#val}-2}"
    fi

    export "$key=$val"
  done < "$path"
}

if [[ ! -d "backend" ]]; then
  write_err "Couldn't find ./backend. Run this script from the repo root."
  exit 1
fi

python_cmd=""
for cmd in python3 python; do
  if "$cmd" -c "import sys; print(sys.executable)" >/dev/null 2>&1; then
    python_cmd="$cmd"
    break
  fi
done

if [[ -z "$python_cmd" ]]; then
  write_err "Python not found. Install Python 3.11+ and ensure it's on PATH."
  exit 1
fi

write_info "Using Python command: $python_cmd"
write_info "Repo root: $(pwd)"

import_dotenv "dev.env"

if [[ -z "${FLASK_APP:-}" ]]; then
  export FLASK_APP="$FLASK_APP_PARAM"
fi

if [[ -n "$DATABASE_URL" ]]; then
  export DATABASE_URL="$DATABASE_URL"
fi

if [[ -z "${DATABASE_URL:-}" ]]; then
  write_err "DATABASE_URL not found (dev.env or param)."
  exit 1
fi

write_info "FLASK_APP=$FLASK_APP"
write_info "DATABASE_URL=$DATABASE_URL"

backup_path=""
current_db_url="$DATABASE_URL"

if [[ "$current_db_url" =~ ^sqlite://(.+)$ ]]; then
  sqlite_path="${BASH_REMATCH[1]}"
  timestamp=$(date +"%Y%m%d-%H%M%S")
  db_dir=$(dirname "$sqlite_path")
  db_leaf=$(basename "$sqlite_path")
  if [[ -z "$db_dir" ]]; then
    db_dir="."
  fi

  backup_path="$db_dir/$db_leaf.$timestamp.bak"
  write_info "Backing up SQLite DB to $backup_path ..."
  cp -f "$sqlite_path" "$backup_path"
elif [[ "$current_db_url" == postgres* ]]; then
  timestamp=$(date +"%Y%m%d-%H%M%S")
  backup_path="$(pwd)/uvt-postgres-$timestamp.dump"
  write_info "Backing up Postgres DB to $backup_path ..."
  pg_dump -Fc -f "$backup_path" "$current_db_url"
else
  write_err "Unsupported DATABASE_URL scheme."
  exit 1
fi

upgrade_succeeded=false
if "$python_cmd" -m flask --app "$FLASK_APP" db upgrade; then
  upgrade_succeeded=true
  write_info "Migrations applied successfully."
else
  write_err "Migration failed."
  if [[ -n "$backup_path" ]]; then
    if [[ "$current_db_url" =~ ^sqlite://(.+)$ ]]; then
      sqlite_path="${BASH_REMATCH[1]}"
      write_warn "Restoring SQLite DB from $backup_path ..."
      cp -f "$backup_path" "$sqlite_path"
    elif [[ "$current_db_url" == postgres* ]]; then
      write_warn "Restoring Postgres DB from $backup_path ..."
      pg_restore --clean --if-exists -d "$current_db_url" "$backup_path"
    fi
    write_warn "Restore completed."
  fi
  exit 1
fi

if [[ "$upgrade_succeeded" != true ]]; then
  write_err "Migration did not complete."
  exit 1
fi

write_info "Done."
