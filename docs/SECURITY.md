# Security

## Reporting a vulnerability

Please report security issues privately to the CommunityPoke maintainers —
open a GitHub security advisory on this repository rather than a public issue.

## Key handling

- Instance keys are Ed25519. The private key lives **only** in a file
  (`PIP_PRIVATE_KEY_FILE`, mode `0600`); it is never placed in environment
  variables or config files, and never logged.
- The loader refuses group/world-readable key files. Set
  `PIP_ALLOW_INSECURE_KEY_PERMS=1` for tests only.
- Rotate keys by publishing `previous_keys` in your identity document; peers
  accept the old key for `rotation_grace_seconds` (default 86400).

## Deployment

- Bind to loopback by default (`PIP_HTTP_HOST=127.0.0.1`). PIP v1 delegates
  transport confidentiality to TLS — terminate TLS at a reverse proxy in
  front of `serve-http` / `serve-mcp --transport streamable-http`.
- `PIP_HTTP_BEARER_TOKEN` is an optional defense-in-depth gate; the envelope
  signature remains the real authentication.
- Logs and metrics never include payload bodies, keys, or tokens.

## What PIP does and does not cover

See `docs/PROTOCOL.md` §13. Mitigated: spoofing, replay, tamper,
over-collection, abuse, downgrade, key compromise. Out of scope for v1:
transport-layer confidentiality, metadata privacy, Sybil resistance.
