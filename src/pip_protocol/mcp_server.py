"""MCP transport (spec §9): every tool call carries a signed envelope."""

import json
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from .config import Settings
from .errors import ErrorCode, PipError
from .node import Node
from .schemas import Envelope, EnvelopeType, ReceiptPayload, parse_envelope

SCOPE_VOCABULARY = [
    "messages:send",
    "messages:read",
    "data:request",
    "data:offer",
    "data:respond",
    "capabilities:read",
    "admin:*",
]


def _dump(envelope: Envelope) -> dict[str, Any]:
    return envelope.model_dump(mode="json", by_alias=True)


def create_mcp_server(node: Node, settings: Settings | None = None) -> FastMCP:
    settings = settings or Settings()
    server: FastMCP = FastMCP("pip-v1", host=settings.http_host, port=settings.http_port)

    def _handle_dict(raw: dict[str, Any]) -> tuple[Envelope | None, dict[str, Any] | None]:
        """Parse a raw tool argument; returns (envelope, error_dict)."""
        try:
            return parse_envelope(raw), None
        except PipError as err:
            return None, _dump(node.error_for_raw(raw, err))

    @server.tool(name="pip_handshake", description="Verify a peer handshake; return ours")
    def pip_handshake(envelope: dict[str, Any]) -> dict[str, Any]:
        env, err = _handle_dict(envelope)
        if err is not None or env is None:
            return err or {}
        resp, _ = node.handle(env)
        rp = resp.typed_payload()
        if (
            resp.type == EnvelopeType.RECEIPT
            and isinstance(rp, ReceiptPayload)
            and rp.status
            in (
                "accepted",
                "duplicate",
            )
        ):
            return _dump(node.handshake_envelope(to=env.from_))
        return _dump(resp)

    @server.tool(name="pip_send_message", description="Deliver a message envelope")
    def pip_send_message(envelope: dict[str, Any]) -> dict[str, Any]:
        env, err = _handle_dict(envelope)
        if err is not None or env is None:
            return err or {}
        if env.type != EnvelopeType.MESSAGE:
            return _dump(
                node.error_for_raw(
                    envelope, PipError(ErrorCode.SCHEMA_INVALID, "expected a message envelope")
                )
            )
        resp, _ = node.handle(env)
        return _dump(resp)

    @server.tool(name="pip_exchange_data", description="Handle a data request/offer envelope")
    def pip_exchange_data(envelope: dict[str, Any]) -> dict[str, Any]:
        env, err = _handle_dict(envelope)
        if err is not None or env is None:
            return err or {}
        if env.type != EnvelopeType.DATA:
            return _dump(
                node.error_for_raw(
                    envelope, PipError(ErrorCode.SCHEMA_INVALID, "expected a data envelope")
                )
            )
        resp, _ = node.handle(env)
        return _dump(resp)

    @server.tool(name="pip_get_receipt", description="Look up a stored receipt by ref")
    def pip_get_receipt(envelope: dict[str, Any]) -> dict[str, Any]:
        env, err = _handle_dict(envelope)
        if err is not None or env is None:
            return err or {}
        try:
            peer = node.verify_inbound(env)
            payload = env.typed_payload()
            if env.type != EnvelopeType.RECEIPT or not isinstance(payload, ReceiptPayload):
                raise PipError(ErrorCode.SCHEMA_INVALID, "expected a receipt envelope with a ref")
            if peer is None:
                raise PipError(ErrorCode.UNKNOWN_PEER, "peer is not in the policy file")
            node.engine.authorize(peer, "messages:read")
        except PipError as exc:
            return _dump(node.error_for_raw(env.model_dump(mode="json", by_alias=True), exc))
        stored = node.store.find_receipt_by_ref(peer.instance_id, payload.ref)
        if stored is None:
            return _dump(node._receipt(env, "rejected", "unknown ref"))
        return stored

    @server.tool(name="pip_list_capabilities", description="List this instance's capabilities")
    def pip_list_capabilities() -> dict[str, Any]:
        doc = node.identity_document()
        return {
            "instance_id": doc.instance_id,
            "capabilities": [c.model_dump(mode="json") for c in node.capabilities()],
            "pip_versions": doc.pip_versions,
        }

    @server.resource("pip://identity")
    def identity_resource() -> str:
        return node.identity_document().model_dump_json()

    @server.resource("pip://capabilities")
    def capabilities_resource() -> str:
        return json.dumps([c.model_dump(mode="json") for c in node.capabilities()])

    @server.resource("pip://policy/scopes")
    def scopes_resource() -> str:
        return json.dumps(SCOPE_VOCABULARY)

    @server.prompt(name="pip_compose_message")
    def pip_compose_message(to: str, subject: str, intent: str) -> str:
        return (
            f"Compose a PIP `message` payload addressed to {to}.\n"
            f"Subject: {subject}\nIntent: {intent}\n\n"
            "Produce JSON matching this schema for the local node to sign:\n"
            '{"subject": str <= 200 chars, "body": str <= 64KiB, '
            '"content_type": "text/plain"|"text/markdown"|"application/json", '
            '"attributes": {str: str}}\n'
            "Pass it to the local node's build(EnvelopeType.MESSAGE, to, payload)."
        )

    @server.prompt(name="pip_request_data")
    def pip_request_data(dataset: str, purpose: str) -> str:
        return (
            f"Compose a PIP `data` request payload for dataset {dataset!r}.\n"
            f"Purpose: {purpose}\n\n"
            "Produce JSON matching this schema for the local node to sign:\n"
            '{"op": "request", "dataset": str, "schema_version": str, '
            '"records": [], "cursor": str|null, "query": obj|null}\n'
            "Use query.filter for equality matching and query.limit for page size."
        )

    return server


def run_mcp(
    server: FastMCP,
    transport: Literal["stdio", "streamable-http"] = "stdio",
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    bearer_token: str | None = None,
) -> None:
    if transport == "stdio":
        server.run("stdio")
        return
    app = server.streamable_http_app()
    if bearer_token is not None:
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request
        from starlette.responses import JSONResponse

        from .transport.http import bearer_ok

        class _Bearer(BaseHTTPMiddleware):
            async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
                if not bearer_ok(request.headers.get("authorization"), bearer_token):
                    return JSONResponse({"error": "unauthorized"}, status_code=401)
                return await call_next(request)

        app.add_middleware(_Bearer)
    import uvicorn

    uvicorn.run(app, host=host, port=port)
