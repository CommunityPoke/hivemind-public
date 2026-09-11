import base64

import pytest

from pip_protocol.envelope import build_envelope, signing_input, verify_signature
from pip_protocol.errors import ErrorCode, PipError
from pip_protocol.schemas import (
    EnvelopeType,
    MessagePayload,
    parse_envelope,
)


def make_message(kp, to="pip:x", clock=None, **kw):
    return build_envelope(
        kp,
        type=EnvelopeType.MESSAGE,
        to=to,
        payload=MessagePayload(subject="hi", body="hello").model_dump(mode="json"),
        clock=clock,
        **kw,
    )


def test_build_and_verify(keypair, clock):
    env = make_message(keypair, clock=clock)
    assert env.sig is not None
    verify_signature(env, keypair.public_key)


def test_roundtrip_wire(keypair, clock):
    env = make_message(keypair, clock=clock)
    wire = env.model_dump(mode="json", by_alias=True)
    assert wire["from"] == keypair.instance_id
    parsed = parse_envelope(wire)
    verify_signature(parsed, keypair.public_key)


def test_ts_serialised_z(keypair, clock):
    wire = make_message(keypair, clock=clock).model_dump(mode="json", by_alias=True)
    assert wire["ts"].endswith("Z") or wire["ts"].endswith("+00:00")


def test_tamper_detected(keypair, clock):
    env = make_message(keypair, clock=clock)
    wire = env.model_dump(mode="json", by_alias=True)
    wire["payload"]["body"] = "evil"
    parsed = parse_envelope(wire)
    with pytest.raises(PipError) as e:
        verify_signature(parsed, keypair.public_key)
    assert e.value.code == ErrorCode.SIGNATURE_INVALID


def test_unsigned_raises(keypair, clock):
    env = make_message(keypair, clock=clock)
    env.sig = None
    with pytest.raises(PipError):
        verify_signature(env, keypair.public_key)


def test_ttl_cap(keypair, clock):
    with pytest.raises(PipError):
        make_message(keypair, clock=clock, ttl_seconds=7200)


def test_nonce_is_16_bytes(keypair, clock):
    env = make_message(keypair, clock=clock)
    raw = base64.urlsafe_b64decode(env.nonce + "=" * (-len(env.nonce) % 4))
    assert len(raw) == 16


def test_signing_input_prefix(keypair, clock):
    env = make_message(keypair, clock=clock)
    assert signing_input(env).startswith(b"PIPv1\n")


def test_typed_payload(keypair, clock):
    env = make_message(keypair, clock=clock)
    p = env.typed_payload()
    assert isinstance(p, MessagePayload)
    assert p.body == "hello"


def test_typed_payload_invalid(keypair, clock):
    env = make_message(keypair, clock=clock)
    env.payload = {"nope": 1}
    # missing required fields
    with pytest.raises(PipError) as e:
        env.typed_payload()
    assert e.value.code == ErrorCode.SCHEMA_INVALID


def test_schema_invalid_on_bad_envelope():
    with pytest.raises(PipError) as e:
        parse_envelope({"type": "message"})
    assert e.value.code == ErrorCode.SCHEMA_INVALID
