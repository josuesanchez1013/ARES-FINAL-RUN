#!/usr/bin/env bash
# Verify the ARES API + UI on this host (written for RHEL 8 and RHEL 9).
#
#   ./scripts/verify_rhel.sh              # uses python3.12, else python3.11
#   PYTHON=python3.11 ./scripts/verify_rhel.sh
#
# Needs Python 3.11 or newer:
#   RHEL 8:  sudo dnf install python3.11   (or python3.12)
#   RHEL 9:  sudo dnf install python3.11   (or python3.12; the default 3.9 is too old)
# On an offline host, point pip at your wheel mirror first, for example
#   export PIP_INDEX_URL=https://your-mirror/simple
# Everything runs in mock mode: no Genesis, MCP server or target system is contacted.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Host =="
grep -E '^(NAME|VERSION)=' /etc/os-release || true

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
  for candidate in python3.12 python3.11; do
    if command -v "$candidate" >/dev/null 2>&1; then PYTHON="$candidate"; break; fi
  done
fi
if [ -z "$PYTHON" ]; then echo "FAIL: install python3.11 or python3.12 (dnf install python3.11)"; exit 1; fi
"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"; print("Python", sys.version.split()[0])'

VENV=".venv-verify-$("$PYTHON" -c 'import sys; print("%d%d" % sys.version_info[:2])')"
echo "== Installing into $VENV =="
"$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
# The whole tests/ folder runs below, so the pipeline requirements are needed too.
"$VENV/bin/pip" install --quiet -r requirements.txt -r requirements-dev.txt
"$VENV/bin/pip" list 2>/dev/null | grep -iE '^(fastapi|uvicorn|starlette|pydantic|python-multipart) '

echo "== Offline tests (pipeline + API) =="
"$VENV/bin/python" -m pytest tests -q

echo "== Theme contrast check =="
"$VENV/bin/python" scripts/check_contrast.py | tail -1

echo "== Live smoke test (mock mode) =="
test -f frontend/dist/index.html || { echo "FAIL: frontend/dist is missing (run: cd frontend && npm ci && npm run build)"; exit 1; }
PORT="${PORT:-8099}"
DATA="$(mktemp -d)"
ARES_USE_MOCK=true ARES_MOCK_STEP_DELAY=0.1 ARES_DATA_DIR="$DATA" \
  "$VENV/bin/python" -m uvicorn ares_api.main:app --host 127.0.0.1 --port "$PORT" --log-level warning &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$DATA"' EXIT
for _ in $(seq 1 50); do
  "$VENV/bin/python" -c "import httpx,sys; httpx.get('http://127.0.0.1:$PORT/api/health')" 2>/dev/null && break
  sleep 0.2
done
"$VENV/bin/python" scripts/smoke.py "http://127.0.0.1:$PORT"

echo
echo "ALL CHECKS PASSED on $(grep -E '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '\"') with $("$PYTHON" --version)"
