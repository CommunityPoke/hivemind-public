import base64

from conftest import make_peer
from pip_protocol.clock import FakeClock
from pip_protocol.envelope import signing_input, verify_signature
from pip_protocol.errors import ErrorCode
from pip_protocol.identity import KeyPair
from pip_protocol.node import DictDataProvider, Node
from pip_protocol.policy import Consent, Policy
from pip_protocol.schemas import (
    DataPayload,
    Envelope,
    EnvelopeType,
    ErrorPayload,
    MessagePayload,
    Signature,
    parse_envelope,
)


def make_nodes(clock, *, scopes=None, consents=None, datasets=None, b_extra=None):
    ka, kb = KeyPair.generate(), KeyPair.generate()
    policy = Policy(
        peers=[
            make_peer(
                ka,
                scopes if scopes is not None else ["messages:send"],
                consents or [],
            )
        ]
    )
    node_a = Node(ka, Policy(peers=[make_peer(kb, ["admin:*"])]), clock=clock)
    node_b = Node(
        kb,
        policy,
        clock=clock,
        data_provider=DictDataProvider(datasets or {}),
        **(b_extra or {}),
    )
    return node_a, node_b


def test_handshake_self_addressed(clock):
    node = Node(KeyPair.generate(), clock=clock)
    env = node.handshake_envelope()
    assert env.to == node.instance_id
    verify_signature(env, node.keypair.public_key)
    p = env.typed_payload()
    assert p.identity.instance_id == node.instance_id


def test_message_end_to_end(clock):
    a, b = make_nodes(clock)
    env = a.build(
        EnvelopeType.MESSAGE,
        b.instance_id,
        MessagePayload(subject="hi", body="hello b"),
    )
    resp, err = b.handle(env)
    assert err is None
    assert resp.type == EnvelopeType.RECEIPT
    rp = resp.typed_payload()
    assert rp.ref == env.id and rp.status == "accepted"
    verify_signature(resp, b.keypair.public_key)
    assert len(b.inbox) == 1


def test_message_forbidden_without_scope(clock):
    a, b = make_nodes(clock, scopes=[])
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="x"))
    resp, err = b.handle(env)
    assert err is not None and err.code == ErrorCode.FORBIDDEN
    assert resp.type == EnvelopeType.ERROR
    ep = resp.typed_payload()
    assert isinstance(ep, ErrorPayload)
    assert ep.code == "FORBIDDEN" and ep.ref == env.id
    verify_signature(resp, b.keypair.public_key)


def test_unknown_peer(clock):
    a = Node(KeyPair.generate(), clock=clock)
    b = Node(KeyPair.generate(), Policy(), clock=clock)
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="x"))
    resp, err = b.handle(env)
    assert err is not None and err.code == ErrorCode.UNKNOWN_PEER
    assert resp.type == EnvelopeType.ERROR


def test_version_unsupported(clock):
    a, b = make_nodes(clock)
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="x"))
    wire = env.model_dump(mode="json", by_alias=True)
    wire["pip"] = "2.0"
    # re-sign so the signature covers the tampered version
    forged = parse_envelope(wire)
    forged.sig = Signature(
        kid=a.keypair.public_key,
        value=base64.urlsafe_b64encode(a.keypair.sign(signing_input(forged))).decode(),
    )
    resp, err = b.handle(forged)
    assert err is not None and err.code == ErrorCode.VERSION_UNSUPPORTED


def test_expired_envelope(clock):
    a, b = make_nodes(clock)
    env = a.build(
        EnvelopeType.MESSAGE,
        b.instance_id,
        MessagePayload(subject="s", body="x"),
        ttl_seconds=60,
    )
    clock.advance(120)
    _, err = b.handle(env)
    assert err is not None and err.code == ErrorCode.EXPIRED


def test_clock_skew(clock):
    a_clock, b_clock = FakeClock(), FakeClock()
    ka, kb = KeyPair.generate(), KeyPair.generate()
    a = Node(ka, Policy(peers=[make_peer(kb, ["admin:*"])]), clock=a_clock)
    b = Node(kb, Policy(peers=[make_peer(ka, ["messages:send"])]), clock=b_clock)
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="x"))
    b_clock.advance(400)  # beyond 300s skew
    _, err = b.handle(env)
    assert err is not None and err.code == ErrorCode.CLOCK_SKEW


def test_replay_detected(clock):
    a, b = make_nodes(clock)
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="x"))
    b.handle(env)
    _, err = b.handle(env)
    assert err is not None and err.code == ErrorCode.REPLAY


def test_idempotent_duplicate(clock):
    a, b = make_nodes(clock)
    env = a.build(
        EnvelopeType.MESSAGE,
        b.instance_id,
        MessagePayload(subject="s", body="x"),
        idempotency_key="key-1",
    )
    resp1, _ = b.handle(env)
    env2 = a.build(
        EnvelopeType.MESSAGE,
        b.instance_id,
        MessagePayload(subject="s", body="x"),
        idempotency_key="key-1",
    )
    resp2, err = b.handle(env2)
    assert err is None
    assert resp2.typed_payload().status == "duplicate"
    assert resp2.typed_payload().ref == env.id
    assert len(b.inbox) == 1  # handler did not re-run


def test_data_request_response(clock):
    consent = Consent(resource="data:notes", actions=["read"])
    a, b = make_nodes(
        clock,
        scopes=["data:request"],
        consents=[consent],
        datasets={"notes": [{"n": i} for i in range(5)]},
    )
    env = a.build(
        EnvelopeType.DATA,
        b.instance_id,
        DataPayload(op="request", dataset="notes", query={"limit": 3}),
    )
    resp, err = b.handle(env)
    assert err is None
    assert resp.type == EnvelopeType.DATA
    p = resp.typed_payload()
    assert isinstance(p, DataPayload)
    assert p.op == "response"
    assert len(p.records) == 3
    assert p.cursor == "3"
    verify_signature(resp, b.keypair.public_key)


def test_data_request_paging(clock):
    consent = Consent(resource="data:notes", actions=["read"])
    a, b = make_nodes(
        clock,
        scopes=["data:request"],
        consents=[consent],
        datasets={"notes": [{"n": i} for i in range(5)]},
    )
    env = a.build(
        EnvelopeType.DATA,
        b.instance_id,
        DataPayload(op="request", dataset="notes", query={"limit": 3}, cursor="3"),
    )
    resp, _ = b.handle(env)
    p = resp.typed_payload()
    assert len(p.records) == 2 and p.cursor is None


def test_data_request_consent_required(clock):
    a, b = make_nodes(clock, scopes=["data:request"], datasets={"notes": []})
    env = a.build(EnvelopeType.DATA, b.instance_id, DataPayload(op="request", dataset="notes"))
    resp, err = b.handle(env)
    assert err is not None and err.code == ErrorCode.CONSENT_REQUIRED
    assert resp.type == EnvelopeType.ERROR


def test_data_offer_write_consent(clock):
    consent = Consent(resource="data:notes", actions=["write"])
    a, b = make_nodes(clock, scopes=["data:offer"], consents=[consent])
    env = a.build(
        EnvelopeType.DATA,
        b.instance_id,
        DataPayload(op="offer", dataset="notes", records=[{"x": 1}]),
    )
    resp, err = b.handle(env)
    assert err is None and resp.typed_payload().status == "accepted"


def test_identity_mismatch(clock):
    a, b = make_nodes(clock)
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="x"))
    wire = env.model_dump(mode="json", by_alias=True)
    other = KeyPair.generate()
    wire["from"] = other.instance_id  # kid no longer hashes to from
    forged = parse_envelope(wire)
    _, err = b.handle(forged)
    assert err is not None and err.code == ErrorCode.IDENTITY_MISMATCH


def test_signature_invalid(clock):
    a, b = make_nodes(clock)
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="x"))
    env.payload["body"] = "tampered"
    _, err = b.handle(env)
    assert err is not None and err.code == ErrorCode.SIGNATURE_INVALID


def test_error_http_status_mapping():
    from pip_protocol.errors import PipError

    assert PipError(ErrorCode.FORBIDDEN).http_status == 403
    assert PipError(ErrorCode.REPLAY).http_status == 409
    assert PipError(ErrorCode.RATE_LIMITED).http_status == 429
    assert PipError(ErrorCode.INTERNAL).http_status == 500
    assert PipError(ErrorCode.RATE_LIMITED).retryable


def test_metrics_recorded(clock):
    a, b = make_nodes(clock)
    env = a.build(EnvelopeType.MESSAGE, b.instance_id, MessagePayload(subject="s", body="x"))
    b.handle(env)
    text = b.metrics.render()
    assert 'envelopes_received_total{outcome="accepted",type="message"} 1.0' in text


def test_outbound_redaction_before_signing(clock):
    ka, kb = KeyPair.generate(), KeyPair.generate()
    policy = Policy(
        peers=[make_peer(kb, ["admin:*"])],
        redaction={"fields": ["password"], "patterns": []},
    )
    a = Node(ka, policy, clock=clock)
    env = a.build(
        EnvelopeType.MESSAGE,
        "pip:x",
        MessagePayload(subject="s", body="x", attributes={"Password": "hunter2"}),  # noqa: S105
    )
    assert env.payload["attributes"]["Password"] == "[REDACTED]"  # noqa: S105
    verify_signature(env, ka.public_key)  # signature covers redacted content


def test_envelope_parse_roundtrip(clock):
    a, _ = make_nodes(clock)
    env = a.build(EnvelopeType.MESSAGE, "pip:x", MessagePayload(subject="s", body="x"))
    env2 = Envelope.model_validate(env.model_dump(mode="json", by_alias=True))
    assert env2.id == env.id


def test_envelope_wrong_addressee(clock):
    """F1: B rejects an envelope addressed to C."""
    a, b = make_nodes(clock)
    c = KeyPair.generate()
    env = a.build(EnvelopeType.MESSAGE, c.instance_id, MessagePayload(subject="s", body="x"))
    _, err = b.handle(env)
    assert err is not None and err.code == ErrorCode.IDENTITY_MISMATCH


def test_data_response_redacted(clock):
    """F2: outbound data responses pass through the redactor."""
    consent = Consent(resource="data:notes", actions=["read"])
    ka, kb = KeyPair.generate(), KeyPair.generate()
    a = Node(ka, Policy(peers=[make_peer(kb, ["admin:*"])]), clock=clock)
    b = Node(
        kb,
        Policy(
            peers=[make_peer(ka, ["data:request"], [consent])],
            redaction={"fields": ["email"]},
        ),
        clock=clock,
        data_provider=DictDataProvider({"notes": [{"email": "a@b.c", "n": 1}]}),
    )
    env = a.build(EnvelopeType.DATA, b.instance_id, DataPayload(op="request", dataset="notes"))
    resp, err = b.handle(env)
    assert err is None
    p = resp.typed_payload()
    assert p.records == [{"email": "[REDACTED]", "n": 1}]
    verify_signature(resp, b.keypair.public_key)
