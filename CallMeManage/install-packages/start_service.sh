#!/usr/bin/env bash
# Run CallMe Manage in this terminal instead of as a service - for development and
# troubleshooting. Normally the system runs as services: callmemanage status.
# Settings come from /etc/callmemanage/callmemanage.conf (or CALLMEMANAGE_CONF); the config
# is checked first and nothing starts while something required is missing.
# Logs are appended to logs/backend.log and logs/frontend.log (rotated daily). Ctrl+C stops both.
set -euo pipefail

# this script lives in install-packages/; the project is one level up
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
export CALLMEMANAGE_CONF="${CALLMEMANAGE_CONF:-/etc/callmemanage/callmemanage.conf}"

if [[ "${EUID}" -eq 0 ]]; then
    echo "Do not start the system as root; run ./install-packages/start_service.sh as the project user." >&2
    exit 1
fi
[[ -x .venv/bin/python ]] || { echo "Not installed yet - run: sudo ./install.sh" >&2; exit 1; }
if systemctl is-active --quiet callmemanage-backend.service callmemanage-frontend.service 2>/dev/null; then
    echo "CallMe Manage already runs as a service (it holds the ports) - stop it first: sudo callmemanage stop" >&2
    exit 1
fi

.venv/bin/python tools/env_check.py || exit 1

mkdir -p logs
export PYTHONUNBUFFERED=1

# host, port and certificate come from the config file (see app.py)
.venv/bin/python app.py 2>&1 | python3 tools/log_writer.py logs/backend.log &
BACKEND_PID=$!

# vite directly (not through npm/sh) so a stop signal reaches the server itself;
# port, host and certificate come from the config file (see vite.config.js)
(cd frontend/cloud_management && exec ./node_modules/.bin/vite preview) 2>&1 \
    | python3 tools/log_writer.py logs/frontend.log &
FRONTEND_PID=$!

# Shutdown without losing log lines or forcing uvicorn:
# - Ctrl+C in the terminal already reaches every process (uvicorn and vite stop gracefully,
#   log_writer ignores it and keeps writing), so nothing is re-sent - a second SIGINT
#   would make uvicorn skip its clean shutdown.
# - otherwise (one service died, or this script got SIGTERM) the services get one SIGTERM.
# Only our own uvicorn/vite children are signalled, never the log writers or other processes.
service_pids() { pgrep -P $$ -f "python app.py|vite preview" || true; }
stop() {
    trap '' INT TERM
    local pids
    if [[ "$1" != "interrupt" ]]; then
        pids="$(service_pids)"; [[ -n "$pids" ]] && kill -TERM $pids 2>/dev/null
    fi
    for _ in $(seq 1 30); do
        [[ -z "$(service_pids)" ]] && break
        sleep 0.5
    done
    pids="$(service_pids)"; [[ -n "$pids" ]] && kill -TERM $pids 2>/dev/null   # still running after 15 s
    wait 2>/dev/null || true
}
trap 'stop interrupt; exit 0' INT
trap 'stop terminate; exit 0' TERM

echo "Running in this terminal (Ctrl+C to stop). Ports: see FRONTEND_PORT / BACKEND_PORT in $CALLMEMANAGE_CONF"
wait -n "$BACKEND_PID" "$FRONTEND_PID" || true
echo "One of the services stopped - stopping the other." >&2
stop died
