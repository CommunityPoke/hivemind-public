"""Ed25519 identity keys and the identity document (spec §2, §4)."""

import base64
import hashlib
import os
import stat
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import BaseModel, ConfigDict, model_validator

from .errors import ErrorCode, PipError

PUBLIC_KEY_PREFIX = "ed25519:"
_INSTANCE_ID_CHARS = 26


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


class InsecureKeyFileError(PipError):
    def __init__(self, path: Path, mode: int) -> None:
        super().__init__(
            ErrorCode.INTERNAL,
            f"private key file {path} has insecure permissions {oct(mode)}; "
            "expected 0600 (set PIP_ALLOW_INSECURE_KEY_PERMS=1 to override)",
        )


class KeyPair:
    """An Ed25519 keypair identifying an instance."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, seed: bytes) -> "KeyPair":
        if len(seed) != 32:
            raise PipError(ErrorCode.INTERNAL, "ed25519 seed must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def private_bytes(self) -> bytes:
        return self._private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    @property
    def public_bytes(self) -> bytes:
        return self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_key(self) -> str:
        return encode_public_key(self.public_bytes)

    @property
    def instance_id(self) -> str:
        return instance_id_from_public_key(self.public_key)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def save(self, path: str | Path) -> None:
        """Write the raw 32-byte seed, base64url-encoded, with mode 0600."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, _b64e(self.private_bytes).encode("ascii"))
        finally:
            os.close(fd)
        os.chmod(p, 0o600)

    @classmethod
    def load(cls, path: str | Path, *, allow_insecure: bool = False) -> "KeyPair":
        p = Path(path)
        mode = stat.S_IMODE(p.stat().st_mode)
        if not allow_insecure and mode & 0o077:
            raise InsecureKeyFileError(p, mode)
        seed = _b64d(p.read_text().strip())
        return cls.from_private_bytes(seed)


def encode_public_key(public_bytes: bytes) -> str:
    if len(public_bytes) != 32:
        raise PipError(ErrorCode.INTERNAL, "ed25519 public key must be 32 bytes")
    return PUBLIC_KEY_PREFIX + _b64e(public_bytes)


def decode_public_key(encoded: str) -> Ed25519PublicKey:
    if not encoded.startswith(PUBLIC_KEY_PREFIX):
        raise PipError(
            ErrorCode.SCHEMA_INVALID, f"public key must start with {PUBLIC_KEY_PREFIX!r}"
        )
    try:
        raw = _b64d(encoded[len(PUBLIC_KEY_PREFIX) :])
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise PipError(ErrorCode.SCHEMA_INVALID, "malformed ed25519 public key") from exc


def instance_id_from_public_key(encoded: str) -> str:
    raw = decode_public_key(encoded).public_bytes(Encoding.Raw, PublicFormat.Raw)
    digest = base64.b32encode(hashlib.sha256(raw).digest()).decode("ascii").lower()
    return f"pip:{digest[:_INSTANCE_ID_CHARS]}"


def verify(public_key: str, data: bytes, signature: bytes) -> bool:
    try:
        decode_public_key(public_key).verify(signature, data)
    except InvalidSignature:
        return False
    return True


class PreviousKey(BaseModel):
    model_config = ConfigDict(extra="ignore")

    public_key: str
    rotated_at: datetime


class IdentityDocument(BaseModel):
    model_config = ConfigDict(extra="ignore")

    instance_id: str
    public_key: str
    display_name: str
    pip_versions: list[str]
    endpoints: dict[str, str | None] = {}
    previous_keys: list[PreviousKey] = []
    issued_at: datetime

    @model_validator(mode="after")
    def _id_matches_key(self) -> "IdentityDocument":
        if instance_id_from_public_key(self.public_key) != self.instance_id:
            raise PipError(ErrorCode.IDENTITY_MISMATCH, "instance_id does not match public_key")
        return self


class Capability(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    version: str = "1.0"
    scopes_required: list[str] = []
    description: str = ""
