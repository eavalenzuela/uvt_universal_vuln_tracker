#!/usr/bin/env bash
# setup-dev.sh
# Usage examples:
#   ./setup-dev.sh
#   ./setup-dev.sh --database-url "postgresql+psycopg://uvt_user:uvt_pass@localhost:5432/uvt"
#   ./setup-dev.sh --database-url "sqlite:///uvt.db"

set -euo pipefail

DATABASE_URL=""
VENV_PATH=".venv"
DEFAULT_FLASK_APP="backend.uvt_app:create_app"
FLASK_APP_PARAM="$DEFAULT_FLASK_APP"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database-url)
      DATABASE_URL="$2"
      shift 2
      ;;
    --venv-path)
      VENV_PATH="$2"
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

if [[ ! -d "$VENV_PATH" ]]; then
  write_info "Creating venv at $VENV_PATH ..."
  "$python_cmd" -m venv "$VENV_PATH"
else
  write_info "Venv exists at $VENV_PATH"
fi

activate_script="$VENV_PATH/bin/activate"
if [[ ! -f "$activate_script" ]]; then
  write_err "Venv activation script not found: $activate_script"
  exit 1
fi

# shellcheck disable=SC1090
source "$activate_script"

write_info "Venv activated: $($python_cmd -c 'import sys; print(sys.executable)')"

write_info "Upgrading pip/setuptools/wheel..."
"$python_cmd" -m pip install --upgrade pip setuptools wheel

if [[ -f "requirements.txt" ]]; then
  write_info "Installing dependencies from requirements.txt..."
  "$python_cmd" -m pip install -r requirements.txt
  if [[ "${DATABASE_URL:-}" == postgres* ]] && [[ -f "requirements-postgres.txt" ]]; then
    write_info "PostgreSQL detected — installing psycopg driver..."
    "$python_cmd" -m pip install -r requirements-postgres.txt
  fi
else
  write_info "requirements.txt not found; installing baseline dependencies..."
  "$python_cmd" -m pip install \
    flask flask_sqlalchemy flask_migrate alembic flask_cors \
    pyjwt werkzeug
fi

import_dotenv "dev.env"

if [[ -z "${FLASK_APP:-}" ]]; then
  export FLASK_APP="$FLASK_APP_PARAM"
fi
export FLASK_ENV="${FLASK_ENV:-development}"

if [[ -n "$DATABASE_URL" ]]; then
  export DATABASE_URL="$DATABASE_URL"
elif [[ -z "${DATABASE_URL:-}" ]]; then
  write_warn "No DATABASE_URL found (dev.env or param). Defaulting to SQLite (sqlite:///uvt.db)."
  export DATABASE_URL="sqlite:///uvt.db"
fi

export JWT_SECRET="${JWT_SECRET:-dev-jwt-secret}"
export SECRET_KEY="${SECRET_KEY:-dev-secret}"

write_info "FLASK_APP=$FLASK_APP"
write_info "DATABASE_URL=$DATABASE_URL"

write_info "Verifying Flask can load the app..."
"$python_cmd" -m flask --app "$FLASK_APP" routes >/dev/null
write_info "App import OK."

if [[ ! -d "migrations" ]]; then
  write_warn "migrations/ not found. Initializing Flask-Migrate..."
  "$python_cmd" -m flask --app "$FLASK_APP" db init

  write_info "Creating initial migration..."
  "$python_cmd" -m flask --app "$FLASK_APP" db migrate -m "initial schema"
else
  write_info "migrations/ exists; skipping db init/migrate."
fi

write_info "Applying migrations (db upgrade)..."
"$python_cmd" -m flask --app "$FLASK_APP" db upgrade

write_info "Done."
printf '\n'
printf 'Next steps:\n'
printf '  1) Start the API:\n'
printf '     %s -m flask --app %s run\n' "$python_cmd" "$FLASK_APP"
printf '\n'
printf '  2) (Optional) Register admin via API if fresh DB:\n'
printf '     POST http://127.0.0.1:5000/api/auth/register\n'
printf '\n'
write_warn "Note: Env vars set by this script only apply to the current shell session."
