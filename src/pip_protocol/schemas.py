"""Pydantic v2 wire models for envelopes and payloads (spec §3)."""

import base64
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_core import PydanticCustomError

from .errors import ErrorCode, PipError
from .identity import Capability, IdentityDocument

MAX_BODY_CHARS = 65536
MAX_SUBJECT_CHARS = 200
MAX_RECORDS = 1000
MAX_IDEMPOTENCY_KEY_CHARS = 128


class EnvelopeType(str, Enum):
    HANDSHAKE = "handshake"
    MESSAGE = "message"
    DATA = "data"
    RECEIPT = "receipt"
    ERROR = "error"


class Signature(BaseModel):
    model_config = ConfigDict(extra="ignore")

    alg: Literal["ed25519"] = "ed25519"
    kid: str
    value: str


class HandshakePayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    identity: IdentityDocument
    capabilities: list[Capability] = []


class MessagePayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    subject: str = Field(max_length=MAX_SUBJECT_CHARS)
    body: str = Field(max_length=MAX_BODY_CHARS)
    content_type: Literal["text/plain", "text/markdown", "application/json"] = "text/plain"
    attributes: dict[str, str] = {}


class DataPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    op: Literal["offer", "request", "response"]
    dataset: str
    schema_version: str = "1.0"
    records: Annotated[list[dict[str, Any]], Field(max_length=MAX_RECORDS)] = []
    cursor: str | None = None
    query: dict[str, Any] | None = None


class ReceiptPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ref: str
    status: Literal["accepted", "delivered", "rejected", "duplicate"]
    reason: str | None = None


class ErrorPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    code: str
    message: str
    ref: str | None = None
    retryable: bool = False
    supported_versions: list[str] | None = None


_PAYLOAD_MODELS: dict[EnvelopeType, type[BaseModel]] = {
    EnvelopeType.HANDSHAKE: HandshakePayload,
    EnvelopeType.MESSAGE: MessagePayload,
    EnvelopeType.DATA: DataPayload,
    EnvelopeType.RECEIPT: ReceiptPayload,
    EnvelopeType.ERROR: ErrorPayload,
}


def _require_utc(v: datetime) -> datetime:
    if v.tzinfo is None:
        raise PydanticCustomError("timezone_required", "datetime must be timezone-aware (UTC)")
    return v.astimezone(timezone.utc)


class Envelope(BaseModel):
    """The signed unit of exchange. Unknown fields are ignored per §11."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    pip: str
    id: str
    type: EnvelopeType
    from_: str = Field(alias="from")
    to: str
    ts: datetime
    expires: datetime
    nonce: str
    idempotency_key: str | None = Field(default=None, max_length=MAX_IDEMPOTENCY_KEY_CHARS)
    in_reply_to: str | None = None
    payload: dict[str, Any] = {}
    sig: Signature | None = None

    @field_validator("ts", "expires")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return _require_utc(v)

    @field_validator("nonce")
    @classmethod
    def _nonce_b64(cls, v: str) -> str:
        try:
            raw = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
        except Exception as exc:
            raise PydanticCustomError("nonce_invalid", "nonce must be base64url") from exc
        if len(raw) != 16:
            raise PydanticCustomError("nonce_invalid", "nonce must decode to 16 bytes")
        return v

    @property
    def from_id(self) -> str:
        return self.from_

    def typed_payload(self) -> BaseModel:
        model = _PAYLOAD_MODELS[self.type]
        try:
            return model.model_validate(self.payload)
        except Exception as exc:
            raise PipError(ErrorCode.SCHEMA_INVALID, f"invalid {self.type} payload: {exc}") from exc

    def without_sig(self) -> dict[str, Any]:
        d = self.model_dump(mode="json", by_alias=True)
        d.pop("sig", None)
        return d


def parse_envelope(data: dict[str, Any]) -> Envelope:
    try:
        return Envelope.model_validate(data)
    except Exception as exc:
        raise PipError(ErrorCode.SCHEMA_INVALID, f"invalid envelope: {exc}") from exc


def new_nonce() -> str:
    import secrets

    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")


def new_id() -> str:
    import uuid

    return str(uuid.uuid4())
