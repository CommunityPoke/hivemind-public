#!/usr/bin/env bash
# Deploy helper for the PIP docker compose stack.
# Usage: deploy.sh [up|down|status|logs|keygen|identity]
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE="docker compose"

wait_health() {
    local port="$1" name="$2" i
    for i in $(seq 1 30); do
        if curl -sf "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
            echo "${name}: healthy on :${port}"
            return 0
        fi
        sleep 1
    done
    echo "${name}: NOT healthy on :${port} after 30s" >&2
    return 1
}

case "${1:-up}" in
    up)
        if [ ! -f .env ]; then
            cp config/.env.example .env
            echo "warning: created .env from config/.env.example — EDIT IT before exposing publicly" >&2
        fi
        if [ ! -f config/policy.yaml ]; then
            cp config/policy.example.yaml config/policy.yaml
            echo "warning: created config/policy.yaml from the example — peers are placeholders" >&2
        fi
        $COMPOSE build
        $COMPOSE up -d
        wait_health 8642 pip-http
        wait_health 8643 pip-mcp
        ;;
    down)
        $COMPOSE down
        ;;
    status)
        $COMPOSE ps
        ;;
    logs)
        shift || true
        $COMPOSE logs -f "$@"
        ;;
    keygen|identity)
        $COMPOSE run --rm pip-http "$1"
        ;;
    *)
        echo "usage: $0 [up|down|status|logs|keygen|identity]" >&2
        exit 2
        ;;
esac
