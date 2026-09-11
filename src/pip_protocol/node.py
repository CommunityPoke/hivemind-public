"""Transport-agnostic PIP node (spec §3–§7)."""

import base64
import logging
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any, Literal, Protocol

from pydantic import BaseModel

from . import PROTOCOL_VERSION, SUPPORTED_VERSIONS
from .canonical import canonical_json
from .clock import Clock, SystemClock
from .envelope import MAX_TTL_SECONDS, build_envelope, signing_input, verify_signature
from .errors import ErrorCode, PipError
from .identity import (
    Capability,
    IdentityDocument,
    KeyPair,
    PreviousKey,
    instance_id_from_public_key,
)
from .observability import Metrics, log_event
from .policy import PeerRecord, Policy, PolicyEngine, dataset_resource
from .redaction import Redactor
from .schemas import (
    DataPayload,
    Envelope,
    EnvelopeType,
    ErrorPayload,
    HandshakePayload,
    ReceiptPayload,
    Signature,
)
from .store import MemoryStore, Store

logger = logging.getLogger("pip_protocol.node")

Handler = Callable[["Node", Envelope, BaseModel], BaseModel | None]


class DataProvider(Protocol):
    """Backend for inbound `data` request envelopes."""

    def query(
        self, dataset: str, query: dict[str, Any] | None, cursor: str | None
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Return (records, next_cursor); next_cursor None means exhausted."""
        ...


class DictDataProvider:
    """In-memory provider backed by ``{dataset: [records]}`` with paging.

    ``query`` may contain ``{"filter": {field: value}}`` for equality matching
    and ``{"limit": n}`` to cap the page size (default ``page_size``).
    """

    def __init__(self, datasets: dict[str, list[dict[str, Any]]], page_size: int = 100) -> None:
        self.datasets = datasets
        self.page_size = page_size

    def query(
        self, dataset: str, query: dict[str, Any] | None, cursor: str | None
    ) -> tuple[list[dict[str, Any]], str | None]:
        records = list(self.datasets.get(dataset, []))
        if query and isinstance(query.get("filter"), dict):
            records = [r for r in records if all(r.get(k) == v for k, v in query["filter"].items())]
        limit = self.page_size
        if query and isinstance(query.get("limit"), int):
            limit = max(1, int(query["limit"]))
        start = int(cursor) if cursor else 0
        page = records[start : start + limit]
        next_cursor = str(start + limit) if start + limit < len(records) else None
        return page, next_cursor


class Node:
    """One PIP instance: identity, policy, storage, redaction, dispatch."""

    def __init__(
        self,
        keypair: KeyPair,
        policy: Policy | None = None,
        *,
        store: Store | None = None,
        clock: Clock | None = None,
        data_provider: DataProvider | None = None,
        metrics: Metrics | None = None,
        display_name: str = "poke",
        endpoints: dict[str, str | None] | None = None,
        previous_keys: list[PreviousKey] | None = None,
    ) -> None:
        self.keypair = keypair
        self.clock = clock or SystemClock()
        self.policy = policy or Policy()
        self.engine = PolicyEngine(self.policy, self.clock)
        self.store = store or MemoryStore()
        self.redactor = Redactor(self.policy.redaction)
        self.data_provider = data_provider or DictDataProvider({})
        self.metrics = metrics or Metrics()
        self.display_name = display_name
        self.endpoints = endpoints or {}
        self.previous_keys = previous_keys or []
        self.inbox: list[Envelope] = []
        self._handlers: dict[EnvelopeType, Handler] = {
            EnvelopeType.HANDSHAKE: _default_handshake_handler,
            EnvelopeType.MESSAGE: _default_message_handler,
            EnvelopeType.DATA: _default_data_handler,
        }

    @property
    def instance_id(self) -> str:
        return self.keypair.instance_id

    # ------------------------------------------------------------------ #
    # Outbound
    # ------------------------------------------------------------------ #

    def identity_document(self) -> IdentityDocument:
        return IdentityDocument(
            instance_id=self.instance_id,
            public_key=self.keypair.public_key,
            display_name=self.display_name,
            pip_versions=list(SUPPORTED_VERSIONS),
            endpoints=self.endpoints,
            previous_keys=[PreviousKey.model_validate(k) for k in self.previous_keys],
            issued_at=self.clock.now(),
        )

    def capabilities(self) -> list[Capability]:
        caps = [
            Capability(
                name="messages.send",
                scopes_required=["messages:send"],
                description="Receive message envelopes",
            ),
            Capability(
                name="data.query",
                scopes_required=["data:request"],
                description="Answer data request envelopes",
            ),
            Capability(
                name="data.offer",
                scopes_required=["data:offer"],
                description="Receive data offer envelopes",
            ),
        ]
        return caps

    def handshake_envelope(self, to: str | None = None) -> Envelope:
        payload = HandshakePayload(
            identity=self.identity_document(), capabilities=self.capabilities()
        )
        return build_envelope(
            self.keypair,
            type=EnvelopeType.HANDSHAKE,
            to=to or self.instance_id,
            payload=payload.model_dump(mode="json"),
            clock=self.clock,
        )

    def build(
        self,
        type: EnvelopeType,
        to: str,
        payload: BaseModel | dict[str, Any],
        *,
        ttl_seconds: int = 300,
        idempotency_key: str | None = None,
        in_reply_to: str | None = None,
    ) -> Envelope:
        """Redact, then sign an outbound envelope."""
        if isinstance(payload, BaseModel):
            payload = self.redactor.redact_payload(type, payload)
            raw = payload.model_dump(mode="json")
        else:
            raw = self.redactor.redact_value(payload)
        env = build_envelope(
            self.keypair,
            type=type,
            to=to,
            payload=raw,
            ttl_seconds=ttl_seconds,
            idempotency_key=idempotency_key,
            in_reply_to=in_reply_to,
            clock=self.clock,
        )
        self.metrics.envelopes_sent.labels(type=type.value).inc()
        return env

    # ------------------------------------------------------------------ #
    # Inbound
    # ------------------------------------------------------------------ #

    def verify_inbound(self, envelope: Envelope) -> PeerRecord | None:
        """Run the §3 verification order. Returns the peer record or None.

        Raises PipError on any failure.
        """
        if envelope.pip.split(".", 1)[0] != PROTOCOL_VERSION.split(".", 1)[0]:
            raise PipError(
                ErrorCode.VERSION_UNSUPPORTED,
                f"unsupported pip version {envelope.pip!r}; supported: {SUPPORTED_VERSIONS}",
            )
        if len(canonical_json(envelope.payload)) > self.policy.max_payload_bytes:
            raise PipError(ErrorCode.PAYLOAD_TOO_LARGE, "payload exceeds max_payload_bytes")

        # identity / kid
        if envelope.sig is None:
            raise PipError(ErrorCode.SIGNATURE_INVALID, "envelope is unsigned")
        kid = envelope.sig.kid
        if instance_id_from_public_key(kid) != envelope.from_:
            raise PipError(ErrorCode.IDENTITY_MISMATCH, "sig.kid does not hash to envelope.from")
        peer = self.engine.get_peer(envelope.from_)
        now = self.clock.now()
        if peer is not None:
            allowed_keys = [peer.public_key]
            for prev in peer.previous_keys:
                if now < prev.rotated_at + timedelta(seconds=self.policy.rotation_grace_seconds):
                    allowed_keys.append(prev.public_key)
            if kid not in allowed_keys:
                raise PipError(
                    ErrorCode.IDENTITY_MISMATCH,
                    "kid is not the peer's pinned key or a previous key in grace",
                )
        elif not self.policy.allow_unknown_peers:
            raise PipError(ErrorCode.UNKNOWN_PEER, "peer is not in the policy file")

        verify_signature(envelope, kid)

        # time window
        skew = self.policy.max_clock_skew_seconds
        if envelope.expires < envelope.ts or (envelope.expires - envelope.ts) > timedelta(
            seconds=MAX_TTL_SECONDS
        ):
            raise PipError(ErrorCode.SCHEMA_INVALID, "invalid expires window")
        if abs((now - envelope.ts).total_seconds()) > skew:
            raise PipError(ErrorCode.CLOCK_SKEW, "ts outside max_clock_skew_seconds")
        if now > envelope.expires:
            raise PipError(ErrorCode.EXPIRED, "envelope has expired")

        # replay
        if self.store.seen_nonce(envelope.from_, envelope.nonce, envelope.expires):
            raise PipError(ErrorCode.REPLAY, "nonce already seen")

        envelope.typed_payload()  # validate payload schema for the declared type
        return peer

    def on(self, type: EnvelopeType, fn: Handler) -> None:
        self._handlers[type] = fn

    def handle(self, envelope: Envelope) -> tuple[Envelope, PipError | None]:
        """Process an inbound envelope; never raises for peer-caused failures.

        Returns ``(response_envelope, error_or_none)``; the response is always a
        signed envelope (receipt, data response, or error).
        """
        start = time.monotonic()
        outcome = "ok"
        err: PipError | None = None
        try:
            peer = self.verify_inbound(envelope)
            response = self._dispatch(envelope, peer)
            outcome = "error" if response.type == EnvelopeType.ERROR else "accepted"
            if response.type == EnvelopeType.ERROR:
                p = response.typed_payload()
                if isinstance(p, ErrorPayload):
                    err = PipError(ErrorCode(p.code), p.message, retryable=p.retryable)
            return response, err
        except PipError as exc:
            err = exc
            outcome = "error"
            return self._error_envelope(envelope, exc), err
        except Exception as exc:  # handler bug → INTERNAL
            err = PipError(ErrorCode.INTERNAL, str(exc))
            outcome = "error"
            return self._error_envelope(envelope, err), err
        finally:
            self.metrics.envelopes_received.labels(type=envelope.type.value, outcome=outcome).inc()
            if err is not None:
                self.metrics.policy_denials.labels(code=err.code.value).inc()
            self.metrics.handler_seconds.labels(type=envelope.type.value).observe(
                time.monotonic() - start
            )
            log_event(
                logger,
                "envelope_handled",
                envelope_id=envelope.id,
                type=envelope.type.value,
                peer=envelope.from_,
                outcome=outcome,
                code=err.code.value if err else None,
                duration_ms=round((time.monotonic() - start) * 1000, 3),
            )

    # ------------------------------------------------------------------ #

    def _dispatch(self, envelope: Envelope, peer: PeerRecord | None) -> Envelope:
        # idempotent replay short-circuit
        if envelope.idempotency_key is not None:
            stored = self.store.get_idempotent(envelope.from_, envelope.idempotency_key)
            if stored is not None:
                receipt = Envelope.model_validate(stored)
                rp = receipt.typed_payload()
                if isinstance(rp, ReceiptPayload):
                    rp.status = "duplicate"
                    receipt.payload = rp.model_dump(mode="json")
                    receipt.sig = self._re_sign(receipt)
                return receipt

        self.engine.check_rate(envelope.from_)
        payload = envelope.typed_payload()

        # policy / consent per type
        if envelope.type == EnvelopeType.HANDSHAKE:
            pass  # identity already verified; unknown peers only reach here if allowed
        elif envelope.type == EnvelopeType.MESSAGE:
            self.engine.authorize(peer, "messages:send")
        elif envelope.type == EnvelopeType.DATA:
            if not isinstance(payload, DataPayload):
                raise PipError(ErrorCode.SCHEMA_INVALID, "invalid data payload")
            resource = dataset_resource(payload.dataset)
            if payload.op == "request":
                self.engine.authorize(peer, "data:request", resource=resource, action="read")
            elif payload.op == "offer":
                self.engine.authorize(peer, "data:offer", resource=resource, action="write")
            else:  # response
                self.engine.authorize(peer, "data:respond")
        else:  # receipt / error inbound
            self.engine.authorize(peer, "messages:send")

        handler = self._handlers.get(envelope.type)
        result = handler(self, envelope, payload) if handler else None

        if result is None:
            response = self._receipt(envelope, "accepted")
        elif isinstance(result, ReceiptPayload):
            response = self._respond(envelope, EnvelopeType.RECEIPT, result)
        elif isinstance(result, DataPayload):
            response = self._respond(envelope, EnvelopeType.DATA, result)
        elif isinstance(result, ErrorPayload):
            response = self._respond(envelope, EnvelopeType.ERROR, result)
        elif isinstance(result, HandshakePayload):
            response = self._respond(envelope, EnvelopeType.HANDSHAKE, result)
        else:
            response = self._receipt(envelope, "accepted")

        if envelope.idempotency_key is not None and response.type in (
            EnvelopeType.RECEIPT,
            EnvelopeType.DATA,
        ):
            self.store.put_idempotent(
                envelope.from_,
                envelope.idempotency_key,
                response.model_dump(mode="json", by_alias=True),
                self.policy.idempotency_ttl_seconds,
            )
        return response

    def _re_sign(self, envelope: Envelope) -> Signature:
        sig = self.keypair.sign(signing_input(envelope))
        return Signature(
            kid=self.keypair.public_key,
            value=base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii"),
        )

    def _respond(self, envelope: Envelope, type: EnvelopeType, payload: BaseModel) -> Envelope:
        return build_envelope(
            self.keypair,
            type=type,
            to=envelope.from_,
            payload=payload.model_dump(mode="json"),
            in_reply_to=envelope.id,
            clock=self.clock,
        )

    def _receipt(
        self,
        envelope: Envelope,
        status: Literal["accepted", "delivered", "rejected", "duplicate"],
        reason: str | None = None,
    ) -> Envelope:
        return self._respond(
            envelope,
            EnvelopeType.RECEIPT,
            ReceiptPayload(ref=envelope.id, status=status, reason=reason),
        )

    def _error_envelope(self, envelope: Envelope, err: PipError) -> Envelope:
        payload = ErrorPayload(
            code=err.code.value,
            message=err.message,
            ref=envelope.id,
            retryable=err.retryable,
            supported_versions=list(SUPPORTED_VERSIONS)
            if err.code == ErrorCode.VERSION_UNSUPPORTED
            else None,
        )
        try:
            return self._respond(envelope, EnvelopeType.ERROR, payload)
        except PipError:
            # even building an error envelope failed; return unsigned
            return Envelope(
                pip=PROTOCOL_VERSION,
                id="error",
                type=EnvelopeType.ERROR,
                from_=self.instance_id,
                to=envelope.from_,
                ts=self.clock.now(),
                expires=self.clock.now(),
                nonce="AAAAAAAAAAAAAAAAAAAAAA",
                payload=payload.model_dump(mode="json"),
            )


def _default_handshake_handler(
    node: Node, envelope: Envelope, payload: BaseModel
) -> BaseModel | None:
    return None  # accept; discovery uses GET /.well-known/pip


def _default_message_handler(
    node: Node, envelope: Envelope, payload: BaseModel
) -> BaseModel | None:
    node.inbox.append(envelope)
    return None


def _default_data_handler(node: Node, envelope: Envelope, payload: BaseModel) -> BaseModel | None:
    if not isinstance(payload, DataPayload) or payload.op != "request":
        return None
    if payload.op == "request":
        records, next_cursor = node.data_provider.query(
            payload.dataset, payload.query, payload.cursor
        )
        return DataPayload(
            op="response",
            dataset=payload.dataset,
            schema_version=payload.schema_version,
            records=records,
            cursor=next_cursor,
        )
    return None
