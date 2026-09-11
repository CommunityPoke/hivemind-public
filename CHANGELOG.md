# Changelog

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
