# poke-interconnect — Poke Interconnect Protocol (PIP) v1

PIP lets independent Poke instances discover each other's capabilities and
exchange **signed, consented, idempotent** messages and data. One envelope
format, one policy engine, and one security model are shared by two
transports: an HTTP/JSON API and an MCP server.

The full normative spec lives in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).
Install name: `poke-interconnect`; import name: `pip_protocol`; CLI: `pip-node`.

## Architecture

```
        Peer A                          Peer B
  ┌──────────────────┐          ┌──────────────────┐
  │ pip-node / SDK   │          │ pip-node / SDK   │
  │  ┌────────────┐  │          │  ┌────────────┐  │
  │  │   Node     │  │ envelope │  │   Node     │  │
  │  │ sign/verify│  ├─────────►│  │ verify →   │  │
  │  │ policy     │  │ receipt  │  │ policy →   │  │
  │  │ redaction  │  │◄─────────┤  │ handler    │  │
  │  └─────┬──────┘  │          │  └─────┬──────┘  │
  │  HTTP / MCP      │          │  HTTP / MCP      │
  └──────────────────┘          └──────────────────┘
       Ed25519 identity · pip:<base32(sha256(pubkey))[:26]>
```

## Quickstart

```bash
uv venv .venv && uv pip install -e .[dev]   # or: pip install poke-interconnect

# 1. generate an instance key (mode 0600)
pip-node keygen --out ./data/instance.key

# 2. configure peers and consent
cp config/policy.example.yaml config/policy.yaml   # edit peers/scopes/consents
cp config/.env.example .env                        # optional

# 3. serve
PIP_PRIVATE_KEY_FILE=./data/instance.key PIP_POLICY_FILE=./config/policy.yaml \
  pip-node serve-http                                   # HTTP on 127.0.0.1:8642
pip-node serve-mcp --transport stdio                    # MCP over stdio
pip-node serve-mcp --transport streamable-http          # MCP over HTTP
```

Other CLI commands: `pip-node identity`, `pip-node sign`, `pip-node send`
(see `pip-node --help`). Try the in-process demo:
`python examples/two_nodes_demo.py`.

### MCP client config

See `config/mcp-client.example.json`:

```json
{ "mcpServers": { "poke": {
    "command": "pip-node",
    "args": ["serve-mcp", "--transport", "stdio"],
    "env": { "PIP_PRIVATE_KEY_FILE": "./data/instance.key" } } } }
```

## HTTP API (§8)

| Endpoint | Auth | Description |
|---|---|---|
| `GET /.well-known/pip` | none | signed handshake envelope (identity + capabilities) |
| `GET /healthz` | none | `{"status":"ok","version":"pip/1.0"}` |
| `POST /pip/v1/inbox` | signature (+bearer) | envelope → signed `receipt`/`data`/`error` |
| `GET /metrics` | bearer if set | Prometheus text format |

`PIP_HTTP_BEARER_TOKEN` is an optional defense-in-depth gate; it never
replaces the envelope signature. `X-PIP-Request-Id` is echoed/generated,
`X-PIP-Trace-Id` propagated to logs.

## MCP (§9)

Tools: `pip_handshake`, `pip_send_message`, `pip_exchange_data`,
`pip_get_receipt`, `pip_list_capabilities` (public). Every tool takes a signed
`envelope` dict; failures return a **signed `error` envelope** in the result
(never a raw exception).

Resources: `pip://identity`, `pip://capabilities`, `pip://policy/scopes`.
Prompts: `pip_compose_message(to, subject, intent)`,
`pip_request_data(dataset, purpose)`.

## Configuration (§12)

| Variable | Default | Notes |
|---|---|---|
| `PIP_PRIVATE_KEY_FILE` | `./data/instance.key` | mode 0600; key material never in env |
| `PIP_DISPLAY_NAME` | `poke` | |
| `PIP_POLICY_FILE` | `./config/policy.yaml` | YAML or JSON |
| `PIP_STORE_URL` | `memory://` | or `sqlite:///data/pip.db` |
| `PIP_HTTP_HOST` / `PIP_HTTP_PORT` | `127.0.0.1` / `8642` | loopback by default |
| `PIP_MCP_PORT` | `8643` | streamable-http MCP port |
| `PIP_PUBLIC_HTTP_URL` / `PIP_PUBLIC_MCP_URL` | unset | advertised endpoints |
| `PIP_HTTP_BEARER_TOKEN` | unset | optional transport gate |
| `PIP_MAX_CLOCK_SKEW_SECONDS` | `300` | |
| `PIP_IDEMPOTENCY_TTL_SECONDS` | `86400` | |
| `PIP_LOG_LEVEL` | `INFO` | JSON structured logs |

## Deployment

Container image, compose stack, TLS proxy examples, and a systemd unit live in
`Dockerfile`, `docker-compose.yml`, `docker/`, and `deploy/`. See
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md); quick path:
`./deploy/deploy.sh up`.

## Security model (summary)

Ed25519 signatures over canonical JSON (`"PIPv1\n" + canonical_json(env-sig)`);
peers pinned by public key with rotation grace; nonce + time-window replay
protection; idempotency keys for effectively-once delivery; scope + consent
authorization; outbound redaction before signing; size caps and per-peer token
bucket rate limits. See §13 threat model and `docs/SECURITY.md`.

## Delivery semantics

At-least-once from the sender (client retries with the same
`idempotency_key`), effectively-once at the receiver. `pip.delivery.Outbox`
persists pending envelopes with exponential backoff (base 2s, cap 300s, 8
attempts → dead).

## Observability

Prometheus counters `envelopes_received_total{type,outcome}`,
`envelopes_sent_total`, `policy_denials_total{code}`; histogram
`handler_seconds`. Structured JSON logs, one line per envelope/request — never
payload bodies, keys, or tokens.

## Development

```bash
uv pip install -e .[dev]
ruff check . && ruff format --check . && mypy src && pytest -q
```

## Limitations (v1)

Transport confidentiality is delegated to TLS (terminate at a reverse proxy);
no metadata privacy; no Sybil resistance / peer reputation.

## License

MIT — see `LICENSE`.
