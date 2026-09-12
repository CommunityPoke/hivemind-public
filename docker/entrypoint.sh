#!/usr/bin/env bash
# PIP container entrypoint. First arg selects the subcommand.
# Never echo env values — they may carry the bearer token.
set -euo pipefail

if [ ! -f "${PIP_POLICY_FILE:-/config/policy.yaml}" ]; then
    echo "warning: ${PIP_POLICY_FILE:-/config/policy.yaml} not found; starting with empty policy" >&2
fi

cmd="${1:-serve-http}"
case "$cmd" in
    serve-http)
        exec pip-node serve-http
        ;;
    serve-mcp)
        # HEALTHCHECK reads PIP_HEALTH_PORT from the container env — set it
        # per-service in compose (or -e PIP_HEALTH_PORT=8643 for docker run).
        exec pip-node serve-mcp --transport streamable-http
        ;;
    *)
        exec pip-node "$@"
        ;;
esac
