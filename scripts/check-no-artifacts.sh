#!/usr/bin/env bash
set -euo pipefail

forbidden_pattern='(^|/)(__pycache__/|.*\.py[co]$|.*\.pyd$|.*\.so$|dist/|build/|\.pytest_cache/|\.mypy_cache/)'

tracked="$(git ls-files)"
if [[ -z "$tracked" ]]; then
  exit 0
fi

matches="$(printf '%s\n' "$tracked" | grep -E "$forbidden_pattern" || true)"
if [[ -n "$matches" ]]; then
  echo "❌ Found forbidden tracked cache/build artifacts:" >&2
  printf '%s\n' "$matches" >&2
  echo "\nRun local cleanup, then commit again:" >&2
  echo "  find . -type d -name '__pycache__' -prune -exec rm -rf {} +" >&2
  echo "  find . -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.pyd' \) -delete" >&2
  exit 1
fi

echo "✅ No forbidden cache/build artifacts are tracked."
