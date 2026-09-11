"""HTTP transport (spec §8): FastAPI app, peer client, outbox delivery."""

import json
import logging
import secrets
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from ..config import Settings
from ..delivery import Outbox
from ..envelope import verify_signature
from ..errors import ErrorCode, PipError
from ..identity import instance_id_from_public_key
from ..node import Node
from ..observability import log_event
from ..schemas import Envelope, parse_envelope

logger = logging.getLogger("pip_protocol.http")

_BODY_HEADROOM_BYTES = 8192


def bearer_ok(authorization: str | None, token: str | None) -> bool:
    """Constant-time bearer token check shared by HTTP and MCP transports."""
    if token is None:
        return True
    if authorization is None or not authorization.startswith("Bearer "):
        return False
    return secrets.compare_digest(authorization[len("Bearer ") :], token)


def unauthorized() -> JSONResponse:
    return JSONResponse({"error": "unauthorized"}, status_code=401)


def create_app(node: Node, settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="poke-interconnect", version="1.0.0")

    @app.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("x-pip-request-id") or uuid.uuid4().hex
        trace_id = request.headers.get("x-pip-trace-id")
        request.state.request_id = request_id
        request.state.trace_id = trace_id
        response = await call_next(request)
        response.headers["X-PIP-Request-Id"] = request_id
        log_event(
            logger,
            "http_request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            request_id=request_id,
            trace_id=trace_id,
        )
        return response

    @app.get("/.well-known/pip")
    async def well_known() -> dict[str, Any]:
        return node.handshake_envelope().model_dump(mode="json", by_alias=True)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": "pip/1.0"}

    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        if not bearer_ok(request.headers.get("authorization"), settings.http_bearer_token):
            return unauthorized()
        return PlainTextResponse(node.metrics.render(), media_type="text/plain; version=0.0.4")

    @app.post("/pip/v1/inbox")
    async def inbox(request: Request) -> Response:
        if not bearer_ok(request.headers.get("authorization"), settings.http_bearer_token):
            return unauthorized()
        body = await request.body()
        if len(body) > node.policy.max_payload_bytes + _BODY_HEADROOM_BYTES:
            env = node.error_for_raw(
                None, PipError(ErrorCode.PAYLOAD_TOO_LARGE, "request body too large")
            )
            return JSONResponse(env.model_dump(mode="json", by_alias=True), status_code=413)
        try:
            raw: Any = json.loads(body)
        except Exception:
            raw = None
        try:
            envelope = parse_envelope(raw if isinstance(raw, dict) else {})
        except PipError as exc:
            env = node.error_for_raw(raw if isinstance(raw, dict) else None, exc)
            return JSONResponse(
                env.model_dump(mode="json", by_alias=True), status_code=exc.http_status
            )
        response_env, err = node.handle(envelope)
        status = err.http_status if err is not None else 200
        return JSONResponse(response_env.model_dump(mode="json", by_alias=True), status_code=status)

    return app


class HttpPeerClient:
    """Client for a remote peer's HTTP transport (spec §8)."""

    def __init__(
        self,
        node: Node,
        peer_url: str,
        peer_public_key: str,
        *,
        bearer_token: str | None = None,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.node = node
        self.peer_url = peer_url.rstrip("/")
        self.peer_public_key = peer_public_key
        self.peer_instance_id = instance_id_from_public_key(peer_public_key)
        self.bearer_token = bearer_token
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _headers(self) -> dict[str, str]:
        if self.bearer_token:
            return {"Authorization": f"Bearer {self.bearer_token}"}
        return {}

    def send(self, envelope: Envelope) -> Envelope:
        """POST an envelope to the peer inbox; verify the signed response."""
        resp = self._client.post(
            f"{self.peer_url}/pip/v1/inbox",
            content=envelope.model_dump_json(by_alias=True),
            headers={"Content-Type": "application/json", **self._headers()},
        )
        try:
            response_env = parse_envelope(resp.json())
        except Exception as exc:
            raise PipError(ErrorCode.SCHEMA_INVALID, f"invalid response: {exc}") from exc
        verify_signature(response_env, self.peer_public_key)
        if response_env.in_reply_to != envelope.id:
            raise PipError(ErrorCode.SIGNATURE_INVALID, "response in_reply_to does not match")
        return response_env

    def fetch_handshake(self) -> Envelope:
        """GET /.well-known/pip; verify the self-signed handshake."""
        resp = self._client.get(f"{self.peer_url}/.well-known/pip", headers=self._headers())
        envelope = parse_envelope(resp.json())
        verify_signature(envelope, self.peer_public_key)
        if envelope.from_ != self.peer_instance_id:
            raise PipError(ErrorCode.IDENTITY_MISMATCH, "handshake from unexpected peer")
        return envelope


def deliver_outbox(node: Node, outbox: Outbox, clients: dict[str, HttpPeerClient]) -> None:
    """One delivery pass over due outbox items (spec §7)."""
    for item in outbox.due():
        client = clients.get(item.peer_id)
        if client is None:
            outbox.mark_failed(item, f"no client for peer {item.peer_id}")
            continue
        try:
            envelope = parse_envelope(item.envelope)
            client.send(envelope)
        except PipError as exc:
            if exc.retryable:
                outbox.mark_failed(item, str(exc))
            else:
                outbox.mark_dead(item, str(exc))
        except Exception as exc:  # network/transport failure → retryable
            outbox.mark_failed(item, str(exc))
        else:
            outbox.mark_delivered(item)
