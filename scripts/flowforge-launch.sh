#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
URL="http://127.0.0.1:8000"
LOG="${TMPDIR:-/tmp}/flowforge.log"

notify() {
    command -v notify-send >/dev/null 2>&1 && notify-send "FlowForge Proxy" "$1"
}

health_ok() {
    curl -fsS --max-time 2 "$URL/health" >/dev/null 2>&1
}

if health_ok; then
    xdg-open "$URL"
    exit 0
fi

cd "$ROOT" || exit 1

if [ ! -x ".venv/bin/flowforge" ]; then
    notify "Python venv missing. Run: uv sync"
    exit 1
fi

if [ ! -f "frontend/dist/index.html" ]; then
    notify "Building frontend..."
    if ! (cd frontend && npm run build); then
        notify "Frontend build failed"
        exit 1
    fi
fi

nohup "$ROOT/.venv/bin/flowforge" >"$LOG" 2>&1 &

for _ in $(seq 1 60); do
    if health_ok; then
        xdg-open "$URL"
        exit 0
    fi
    sleep 0.5
done

notify "Server failed to start. Log: $LOG"
exit 1
