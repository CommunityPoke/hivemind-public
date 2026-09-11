"""Build, sign, and verify envelopes (spec §3)."""

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

from . import PROTOCOL_VERSION
from .canonical import canonical_json
from .clock import Clock
from .errors import ErrorCode, PipError
from .identity import KeyPair, verify
from .schemas import Envelope, EnvelopeType, Signature, new_id, new_nonce

SIGNING_PREFIX = b"PIPv1\n"
MAX_TTL_SECONDS = 3600  # spec §7: expires - ts <= 1 hour


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def signing_input(envelope: Envelope) -> bytes:
    """`b"PIPv1\\n" + canonical_json(envelope without sig)`."""
    return SIGNING_PREFIX + canonical_json(envelope.without_sig())


def build_envelope(
    keypair: KeyPair,
    *,
    type: EnvelopeType,
    to: str,
    payload: dict[str, Any],
    ttl_seconds: int = 300,
    idempotency_key: str | None = None,
    in_reply_to: str | None = None,
    clock: Clock | None = None,
) -> Envelope:
    if ttl_seconds > MAX_TTL_SECONDS:
        raise PipError(ErrorCode.SCHEMA_INVALID, "ttl_seconds exceeds the 1 hour maximum")
    now = clock.now() if clock is not None else datetime.now(timezone.utc)
    env = Envelope(
        pip=PROTOCOL_VERSION,
        id=new_id(),
        type=type,
        from_=keypair.instance_id,
        to=to,
        ts=now,
        expires=now + timedelta(seconds=ttl_seconds),
        nonce=new_nonce(),
        idempotency_key=idempotency_key,
        in_reply_to=in_reply_to,
        payload=payload,
    )
    env.sig = Signature(kid=keypair.public_key, value=_b64e(keypair.sign(signing_input(env))))
    return env


def verify_signature(envelope: Envelope, public_key: str) -> None:
    """Raise SIGNATURE_INVALID unless ``public_key`` signed ``envelope``."""
    if envelope.sig is None:
        raise PipError(ErrorCode.SIGNATURE_INVALID, "envelope is unsigned")
    try:
        raw_sig = _b64d(envelope.sig.value)
    except Exception as exc:
        raise PipError(ErrorCode.SIGNATURE_INVALID, "malformed signature") from exc
    if not verify(public_key, signing_input(envelope), raw_sig):
        raise PipError(ErrorCode.SIGNATURE_INVALID, "signature does not verify")
