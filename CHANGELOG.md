# Changelog

## 1.2.0

- Added `pip-node serve-all`: single-port mode serving the HTTP API plus MCP
  at `/mcp` (`transport.combined.create_combined_app`), for PaaS deployments
  with platform TLS termination (e.g. Fly.io — see `deploy/fly.toml.example`
  and `main.py`, which honors `PORT`/`FLY_APP_NAME`).
- `create_app` accepts a `lifespan=` kwarg so mounted transports' lifespans
  run.

## 1.1.0

- Added `PIP_MCP_PORT` (default 8643) — MCP streamable-http now binds its own port.
- MCP streamable-http gains a `/healthz` endpoint exempt from the bearer gate.
- Production deployment: multi-stage `Dockerfile` (non-root, healthcheck),
  `docker-compose.yml` (loopback-only ports, read-only fs, cap_drop),
  `docker/entrypoint.sh`, `deploy/` (deploy.sh, Caddyfile, systemd units),
  `docs/DEPLOYMENT.md`.
- `SqliteStore` sets a 5s busy timeout for multi-process WAL access.

## 1.0.0

Initial release of the Poke Interconnect Protocol (PIP) v1.

- Core: Ed25519 identity, canonical-JSON signed envelopes, schema-validated
  payloads (handshake, message, data, receipt, error), policy engine with
  scopes/consent/rate limits, outbound redaction, replay protection,
  idempotency, persistent outbox with backoff, in-memory and SQLite stores.
- Transports: FastAPI HTTP (`/.well-known/pip`, `/healthz`, `/pip/v1/inbox`,
  `/metrics`, optional bearer gate, `HttpPeerClient`) and MCP via `FastMCP`
  (5 tools, 3 resources, 2 prompts, stdio + streamable-http).
- CLI `pip-node`: `keygen`, `identity`, `serve-http`, `serve-mcp`, `sign`,
  `send`.
- Config via `PIP_*` environment (pydantic-settings); Prometheus metrics and
  JSON structured logs.
