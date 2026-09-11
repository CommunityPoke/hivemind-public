"""pip-node command line interface."""

import argparse
import json
import sys
from pathlib import Path

from .bootstrap import build_node_from_settings
from .config import Settings
from .envelope import verify_signature
from .errors import PipError
from .identity import KeyPair
from .observability import configure_logging
from .schemas import EnvelopeType, parse_envelope


def _cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"error: {out} exists (use --force)", file=sys.stderr)
        return 2
    keypair = KeyPair.generate()
    keypair.save(out)
    print(f"wrote {out} (mode 0600)")
    print(f"instance_id: {keypair.instance_id}")
    print(f"public_key:  {keypair.public_key}")
    return 0


def _cmd_identity(args: argparse.Namespace) -> int:
    node = build_node_from_settings(Settings())
    print(node.identity_document().model_dump_json())
    return 0


def _cmd_serve_http(args: argparse.Namespace) -> int:
    import uvicorn

    from .transport.http import create_app

    settings = Settings()
    configure_logging(settings.log_level)
    node = build_node_from_settings(settings)
    app = create_app(node, settings)
    uvicorn.run(app, host=settings.http_host, port=settings.http_port)
    return 0


def _cmd_serve_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import create_mcp_server, run_mcp

    settings = Settings()
    configure_logging(settings.log_level)
    node = build_node_from_settings(settings)
    server = create_mcp_server(node, settings)
    run_mcp(
        server,
        args.transport,
        host=settings.http_host,
        port=settings.http_port,
        bearer_token=settings.http_bearer_token,
    )
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    node = build_node_from_settings(Settings())
    payload = json.loads(args.payload_json)
    env = node.build(
        EnvelopeType(args.type),
        args.to,
        payload,
        idempotency_key=args.idempotency_key,
    )
    print(env.model_dump_json(by_alias=True))
    return 0


def _cmd_send(args: argparse.Namespace) -> int:
    from .transport.http import HttpPeerClient

    settings = Settings()
    node = build_node_from_settings(settings)
    envelope = parse_envelope(json.loads(Path(args.envelope_file).read_text()))
    client = HttpPeerClient(
        node,
        args.url,
        args.peer_key,
        bearer_token=settings.http_bearer_token,
    )
    try:
        response = client.send(envelope)
    except PipError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(response.model_dump_json(by_alias=True))
    verify_signature(response, args.peer_key)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pip-node", description="PIP v1 node CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate an instance key (mode 0600)")
    p.add_argument("--out", default="./data/instance.key")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=_cmd_keygen)

    p = sub.add_parser("identity", help="print the identity document")
    p.set_defaults(func=_cmd_identity)

    p = sub.add_parser("serve-http", help="run the HTTP transport")
    p.set_defaults(func=_cmd_serve_http)

    p = sub.add_parser("serve-mcp", help="run the MCP transport")
    p.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    p.set_defaults(func=_cmd_serve_mcp)

    p = sub.add_parser("sign", help="sign a payload into an envelope (prints JSON)")
    p.add_argument("--type", required=True, choices=[t.value for t in EnvelopeType])
    p.add_argument("--to", required=True)
    p.add_argument("--payload-json", required=True)
    p.add_argument("--idempotency-key", default=None)
    p.set_defaults(func=_cmd_sign)

    p = sub.add_parser("send", help="send a signed envelope to a peer")
    p.add_argument("--url", required=True)
    p.add_argument("--peer-key", required=True)
    p.add_argument("--envelope-file", required=True)
    p.set_defaults(func=_cmd_send)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except PipError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
