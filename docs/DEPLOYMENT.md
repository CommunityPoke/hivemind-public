# Deploying a PIP node

## Prerequisites

- Docker + docker compose v2, **or** Python ≥3.10 + uv for a bare-metal run.
- A policy file listing your peers (`config/policy.yaml`, see
  `config/policy.example.yaml`).

## Local run (no containers)

```bash
uv venv .venv && uv pip install -e .
pip-node keygen --out ./data/instance.key
cp config/policy.example.yaml config/policy.yaml   # edit peers
./.venv/bin/pip-node serve-http                     # :8642
./.venv/bin/pip-node serve-mcp --transport streamable-http  # :8643
```

## Container run

```bash
docker build -t poke-interconnect .

# one-off helpers (key ends up in the named volume)
docker run --rm -v pip-data:/data poke-interconnect keygen
docker run --rm -v pip-data:/data poke-interconnect identity

# HTTP transport
docker run -d --name pip-http \
  -v pip-data:/data -v $PWD/config/policy.yaml:/config/policy.yaml:ro \
  -p 127.0.0.1:8642:8642 -e PIP_HEALTH_PORT=8642 \
  poke-interconnect serve-http

# MCP streamable-http transport (same volume → same identity)
docker run -d --name pip-mcp \
  -v pip-data:/data -v $PWD/config/policy.yaml:/config/policy.yaml:ro \
  -p 127.0.0.1:8643:8643 -e PIP_HEALTH_PORT=8643 \
  poke-interconnect serve-mcp
```

The image runs as non-root `pip` (uid 10001), generates the instance key into
`/data` on first start if absent, and health-checks
`$PIP_HEALTH_PORT/healthz` (8642 for `serve-http`, 8643 for `serve-mcp`).

## Compose (recommended)

```bash
./deploy/deploy.sh up        # builds, starts both services, waits for health
./deploy/deploy.sh status|logs|down
./deploy/deploy.sh identity  # print the node identity document
```

Both services share the `pip-data` volume (same key + sqlite store; WAL mode
plus a 5s busy timeout make the concurrent access safe). Ports bind to
`127.0.0.1` only — never publish 8642/8643 on a public interface.

## TLS

Terminate TLS at a reverse proxy; PIP v1 has no in-transport encryption.
See `deploy/Caddyfile.example`. Equivalent nginx: `proxy_pass
http://127.0.0.1:8642;`. Set `PIP_PUBLIC_HTTP_URL`/`PIP_PUBLIC_MCP_URL` to the
public https URLs so your identity document advertises them.

## Key handling

- The private key lives only at `/data/instance.key` (0600, uid 10001). Back up
  the `pip-data` volume; losing it means a new identity.
- Rotation: publish `previous_keys` in the identity document (see
  `docs/PROTOCOL.md` §2/§4).

## Policy management

Edit `config/policy.yaml` (mounted read-only into the container), then
`docker compose restart`. Peers, scopes, consents, rate limits, redaction.

## Bearer token (optional)

`PIP_HTTP_BEARER_TOKEN=` gates `/pip/v1/inbox`, `/metrics`, and the MCP
streamable-http endpoint. Generate with `openssl rand -hex 32`. `/healthz` is
always unauthenticated.

## Health & metrics

- `GET /healthz` on both transports → `{"status":"ok",...}`.
- `GET /metrics` on the HTTP transport → Prometheus text (bearer-gated if
  configured). Scrape via the proxy or from the host.

## Logs

Structured JSON to stdout — `deploy/deploy.sh logs` or `docker compose logs -f`.
Never contain payload bodies, keys, or tokens.

## Upgrades

```bash
git pull && ./deploy/deploy.sh up   # rebuilds image, restarts services
```

Data (key, sqlite store) survives in the `pip-data` volume.

## systemd alternative (no containers)

`deploy/systemd/pip-node.service.example` and `pip-mcp.service.example`:
install under a `pip` user, `EnvironmentFile=/etc/pip-node/env`,
`ReadWritePaths=/var/lib/pip-node`.

## Checklist

- [ ] `config/policy.yaml` reviewed (real peers, scopes, consents)
- [ ] `.env` reviewed; bearer token set if needed
- [ ] ports reachable only via the TLS proxy
- [ ] key backed up; volume snapshot scheduled
- [ ] `curl https://<host>/.well-known/pip` returns a signed handshake
- [ ] metrics scraping + log shipping configured
