# Poke Interconnect Protocol (PIP) v1 — Specification

Status: v1.0 (stable). Wire version string: `pip/1.0`.

PIP lets independent Poke instances discover each other's capabilities and
exchange signed, consented, idempotent messages and data over two transports:
an HTTP/JSON API and an MCP server. Both transports share one envelope format,
one policy engine, and one set of security rules.

## 1. Terminology

- **Instance** — a running Poke deployment with its own identity keypair.
- **Instance ID** — `pip:<base32(sha256(pubkey))[:26] lowercase>` derived from the
  Ed25519 public key. Stable, self-certifying.
- **Peer** — another instance we have a trust record for.
- **Envelope** — the signed unit of exchange (message, data, receipt, error).
- **Capability** — a named, versioned thing an instance can do (e.g. `data.query`).
- **Scope** — a permission string granted to a peer, e.g. `messages:send`.
- **Consent** — an explicit, revocable, scoped grant from the local operator that
  allows a peer to access a resource class (e.g. `data:notes`).

## 2. Identity & authentication

- Keys: Ed25519 (`cryptography` library). Public key encoded as
  `ed25519:<base64url unpadded 32 bytes>`.
- Instance ID as above. Peers are pinned by public key; a key that does not
  hash to the claimed instance ID is rejected (`IDENTITY_MISMATCH`).
- Key rotation: an instance may publish `previous_keys` in its identity
  document; envelopes signed by a previous key are accepted only for
  `rotation_grace_seconds` (default 86400) after `rotated_at`.
- Authentication of a request = a valid signature on the envelope from a known
  peer (or an unknown peer if `policy.allow_unknown_peers` is true, in which
  case only `handshake` is permitted).
- HTTP additionally supports an optional static bearer token
  (`PIP_HTTP_BEARER_TOKEN`) as a defense-in-depth transport gate; it never
  replaces the signature.

## 3. Envelope

Canonical JSON (RFC 8785-style: sorted keys, no whitespace, UTF-8, no NaN) of
the `payload` object is what gets signed, together with the header fields.

```json
{
  "pip": "1.0",
  "id": "01J...ULID or uuid4",
  "type": "message" | "data" | "receipt" | "error" | "handshake",
  "from": "pip:...",
  "to": "pip:...",
  "ts": "2026-09-11T22:00:00Z",
  "expires": "2026-09-11T22:05:00Z",
  "nonce": "base64url 16 bytes",
  "idempotency_key": "optional, client-chosen, <=128 chars",
  "in_reply_to": "optional envelope id",
  "payload": { ... type-specific ... },
  "sig": {
    "alg": "ed25519",
    "kid": "ed25519:<pubkey>",
    "value": "base64url signature"
  }
}
```

Signing input: `"PIPv1\n" + canonical_json({all fields except "sig"})`.
Verification order: schema → version → identity/kid → signature → time window →
replay → policy/consent → handler.

### Payload types

- `handshake`: `{ "identity": IdentityDocument, "capabilities": [Capability] }`
- `message`: `{ "subject": str<=200, "body": str<=64KiB, "content_type": "text/plain"|"text/markdown"|"application/json", "attributes": {str: str} }`
- `data`: `{ "op": "offer"|"request"|"response", "dataset": str, "schema_version": str, "records": [obj] (<=1000), "cursor": str|null, "query": obj|null }`
- `receipt`: `{ "ref": envelope id, "status": "accepted"|"delivered"|"rejected"|"duplicate", "reason": str|null }`
- `error`: `{ "code": ErrorCode, "message": str, "ref": envelope id|null, "retryable": bool }`

Error codes: `SCHEMA_INVALID`, `VERSION_UNSUPPORTED`, `IDENTITY_MISMATCH`,
`SIGNATURE_INVALID`, `EXPIRED`, `CLOCK_SKEW`, `REPLAY`, `UNKNOWN_PEER`,
`FORBIDDEN`, `CONSENT_REQUIRED`, `RATE_LIMITED`, `PAYLOAD_TOO_LARGE`,
`CAPABILITY_UNKNOWN`, `INTERNAL`.

## 4. Capability discovery

`IdentityDocument`:
```json
{ "instance_id": "pip:...", "public_key": "ed25519:...", "display_name": str,
  "pip_versions": ["1.0"], "endpoints": {"http": url|null, "mcp": url|null},
  "previous_keys": [{"public_key": "...", "rotated_at": ts}],
  "issued_at": ts }
```
`Capability`: `{ "name": "messages.send"|"data.query"|"data.offer"|..., "version": "1.0", "scopes_required": [scope], "description": str }`.

Discovery: `GET /.well-known/pip` returns the signed handshake envelope
(self-addressed). MCP exposes the same as resource `pip://identity` and
`pip://capabilities`.

## 5. Authorization & consent

Policy file (YAML/JSON, loaded at startup, hot-reload not required):

```yaml
allow_unknown_peers: false
default_scopes: []              # scopes granted to every known peer
peers:
  - instance_id: pip:abc...
    public_key: ed25519:...
    display_name: "Alice's Poke"
    scopes: [messages:send, data:request]
    consents:
      - resource: data:notes        # resource class
        actions: [read]             # read | write
        expires: 2027-01-01T00:00:00Z
        granted_by: operator
rate_limits:
  per_peer_per_minute: 60
  burst: 20
max_payload_bytes: 262144
redaction:
  fields: [email, phone, ssn, api_key, token, password, secret]
  patterns: ["\\b[\\w.+-]+@[\\w-]+\\.[\\w.]+\\b"]
```

Scopes: `messages:send`, `messages:read`, `data:request`, `data:offer`,
`data:respond`, `capabilities:read`, `admin:*`. Scope check is exact or
prefix-wildcard (`data:*`). Every handler declares required scopes; the policy
engine (`pip.policy.PolicyEngine.authorize(peer, action, resource)`) is the single
enforcement point shared by HTTP and MCP. Consent is required for any `data`
operation whose `dataset` maps to a consent-protected resource class; missing
consent → `CONSENT_REQUIRED` (not `FORBIDDEN`, so peers can prompt the operator).

## 6. Privacy & redaction

Outbound `data` records and `message` bodies pass through `pip.redaction.Redactor`
which (a) drops/masks configured field names (case-insensitive, nested) and
(b) masks regex matches with `[REDACTED]`. Redaction is applied before signing
so the signature covers the redacted content. Logs never include payload
bodies, keys or tokens — only envelope ids, types, peer ids, and outcome.

## 7. Replay protection, idempotency, delivery semantics

- Time window: `|now - ts| <= max_clock_skew_seconds` (default 300) else
  `CLOCK_SKEW`; `now > expires` → `EXPIRED`. `expires - ts` <= 1 hour.
- Replay: `(from, nonce)` stored until `expires`; duplicate → `REPLAY`.
- Idempotency: if `idempotency_key` present, `(from, idempotency_key)` is stored
  for `idempotency_ttl_seconds` (default 86400) along with the first receipt;
  a repeat returns the stored receipt with `status: duplicate` and does not
  re-run the handler. Storage backends: in-memory (default) and SQLite
  (`PIP_STORE_URL=sqlite:///path`). Interface `pip.store.Store`.
- Delivery: at-least-once from the sender (client retries with the same
  `idempotency_key` and exponential backoff on `retryable` errors / network
  failure); effectively-once at the receiver via idempotency. Receiver always
  answers a `receipt` envelope (`accepted` synchronously; handlers are
  synchronous in v1). An outbox (`pip.delivery.Outbox`) persists pending
  outbound envelopes with attempt count and next-attempt time.

## 8. Transport — HTTP

FastAPI app `pip.transport.http.create_app(node)`:

- `GET  /.well-known/pip` → signed handshake envelope (no auth).
- `GET  /healthz` → `{"status":"ok","version":"pip/1.0"}`.
- `POST /pip/v1/inbox` → body: envelope; response: receipt or error envelope
  (HTTP 200 accepted/duplicate, 400 schema, 401 signature/identity, 403
  forbidden/consent, 409 replay, 413 too large, 429 rate limit, 422 other
  validation). Response envelope is signed by the receiver.
- `GET  /metrics` → Prometheus text format (counters: envelopes_received_total
  {type,outcome}, envelopes_sent_total, policy_denials_total {code};
  histogram: handler_seconds). Guarded by bearer token if configured.
- Request id header `X-PIP-Request-Id` echoed; structured JSON logs via stdlib
  `logging` with a JSON formatter.

Client: `pip.transport.http.HttpPeerClient(node, peer)` with `send(envelope)`
using `httpx`, verifying the returned receipt signature.

## 9. Transport — MCP

`pip.mcp_server` uses the official `mcp` Python SDK (`FastMCP`), stdio and
streamable-HTTP transports. Every tool call carries the caller's identity via a
signed envelope argument, so MCP is just another transport for the same
verification pipeline — there is no unauthenticated tool.

Tools:
- `pip_handshake(envelope: dict) -> dict` — verify peer handshake, return ours.
- `pip_send_message(envelope: dict) -> dict` — deliver a `message` envelope; returns receipt.
- `pip_exchange_data(envelope: dict) -> dict` — `data` request/offer; returns `data` response or receipt.
- `pip_get_receipt(envelope: dict) -> dict` — signed `receipt` lookup by `ref` (for idempotent retries).
- `pip_list_capabilities() -> dict` — public, returns capabilities (unsigned convenience view).

Resources: `pip://identity`, `pip://capabilities`, `pip://policy/scopes` (the
scope vocabulary, no peer data).

Prompts: `pip_compose_message(to, subject, intent)` and
`pip_request_data(dataset, purpose)` — templates that help an LLM-driven Poke
instance produce a well-formed payload to be signed by its local node.

Outputs are validated against the same Pydantic models; errors are returned as
signed `error` envelopes inside the tool result (never raised as raw
exceptions), with `isError` set.

## 10. Observability

- Metrics as in §8; `pip.observability.Metrics` is transport-agnostic.
- Structured logs: one line per envelope with `event`, `envelope_id`, `type`,
  `peer`, `outcome`, `code`, `duration_ms`. No payload content.
- Optional `X-PIP-Trace-Id` propagated to logs.

## 11. Versioning

- `pip` field must be `1.x`; minor versions are additive (unknown payload
  fields ignored, unknown envelope types rejected). Major mismatch →
  `VERSION_UNSUPPORTED` with the supported list in the error payload.
- Capabilities and datasets carry their own `version`/`schema_version`.
- Package version follows semver; `pip.PROTOCOL_VERSION = "1.0"`.

## 12. Secure configuration

Settings via environment (`pydantic-settings`, prefix `PIP_`):

| Variable | Default | Notes |
|---|---|---|
| `PIP_PRIVATE_KEY_FILE` | `./data/instance.key` | 0600; generated by `pip keygen` |
| `PIP_DISPLAY_NAME` | `poke` | |
| `PIP_POLICY_FILE` | `./config/policy.yaml` | |
| `PIP_STORE_URL` | `memory://` | or `sqlite:///data/pip.db` |
| `PIP_HTTP_HOST` / `PIP_HTTP_PORT` | `127.0.0.1` / `8642` | |
| `PIP_PUBLIC_HTTP_URL` / `PIP_PUBLIC_MCP_URL` | unset | advertised endpoints |
| `PIP_HTTP_BEARER_TOKEN` | unset | optional transport gate |
| `PIP_MAX_CLOCK_SKEW_SECONDS` | `300` | |
| `PIP_IDEMPOTENCY_TTL_SECONDS` | `86400` | |
| `PIP_LOG_LEVEL` | `INFO` | |

Rules: private key never in env/config files (file path only); refuse to start
if key file mode is group/world readable (unless `PIP_ALLOW_INSECURE_KEY_PERMS=1`
for tests); bind to loopback by default; TLS is terminated by a reverse proxy
(documented). Example files live in `config/` with no real secrets.

## 13. Threat model summary

Mitigated: spoofing (signatures + pinned keys), replay (nonce + window), tamper
(canonical signing), over-collection (consent + redaction), abuse (rate limit +
size caps), downgrade (explicit version negotiation), key compromise (rotation
with grace). Out of scope for v1: transport-layer confidentiality (delegate to
TLS), metadata privacy, Sybil resistance / peer reputation.
