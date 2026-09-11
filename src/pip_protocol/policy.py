"""Policy file models and the authorization/consent/rate-limit engine (§5)."""

import json
from datetime import datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict

from .clock import Clock, SystemClock
from .errors import ErrorCode, PipError
from .identity import PreviousKey

DEFAULT_MAX_PAYLOAD_BYTES = 262144


class Consent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    resource: str  # e.g. "data:notes"
    actions: list[Literal["read", "write"]]
    expires: datetime | None = None
    granted_by: str = "operator"

    def allows(self, resource: str, action: str, now: datetime) -> bool:
        if self.resource != resource or action not in self.actions:
            return False
        return self.expires is None or now < self.expires


class PeerRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    instance_id: str
    public_key: str
    display_name: str = ""
    scopes: list[str] = []
    consents: list[Consent] = []
    previous_keys: list[PreviousKey] = []


class RateLimits(BaseModel):
    per_peer_per_minute: int = 60
    burst: int = 20


class RedactionConfig(BaseModel):
    fields: list[str] = []
    patterns: list[str] = []


class Policy(BaseModel):
    model_config = ConfigDict(extra="ignore")

    allow_unknown_peers: bool = False
    default_scopes: list[str] = []
    peers: list[PeerRecord] = []
    rate_limits: RateLimits = RateLimits()
    max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES
    redaction: RedactionConfig = RedactionConfig()
    rotation_grace_seconds: int = 86400
    max_clock_skew_seconds: int = 300
    idempotency_ttl_seconds: int = 86400

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        text = Path(path).read_text()
        if str(path).endswith(".json"):
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)
        return cls.model_validate(data or {})


def dataset_resource(dataset: str) -> str:
    return f"data:{dataset}"


def _scope_grants(granted: str, required: str) -> bool:
    if granted == required:
        return True
    if granted.endswith(":*"):
        prefix = granted[:-1]  # e.g. "data:"
        return required.startswith(prefix) or prefix == "admin:"
    return False


class _TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: float, now: float) -> None:
        self.rate = rate_per_sec
        self.capacity = capacity
        self.tokens = capacity
        self.updated = now


class PolicyEngine:
    """Single enforcement point shared by all transports (spec §5)."""

    def __init__(self, policy: Policy, clock: Clock | None = None) -> None:
        self.policy = policy
        self.clock = clock or SystemClock()
        self._buckets: dict[str, _TokenBucket] = {}

    def get_peer(self, instance_id: str) -> PeerRecord | None:
        for peer in self.policy.peers:
            if peer.instance_id == instance_id:
                return peer
        return None

    def _has_scope(self, peer: PeerRecord, scope: str) -> bool:
        granted = list(peer.scopes) + list(self.policy.default_scopes)
        return any(_scope_grants(g, scope) for g in granted)

    def authorize(
        self,
        peer: PeerRecord | None,
        scope: str,
        *,
        resource: str | None = None,
        action: str | None = None,
    ) -> PeerRecord:
        """Return the peer or raise UNKNOWN_PEER / FORBIDDEN / CONSENT_REQUIRED."""
        if peer is None:
            raise PipError(ErrorCode.UNKNOWN_PEER, "peer is not in the policy file")
        if not self._has_scope(peer, scope):
            raise PipError(ErrorCode.FORBIDDEN, f"peer {peer.instance_id} lacks scope {scope!r}")
        if resource is not None and action is not None:
            now = self.clock.now()
            if not any(c.allows(resource, action, now) for c in peer.consents):
                raise PipError(
                    ErrorCode.CONSENT_REQUIRED,
                    f"no consent for {action} on {resource!r}",
                )
        return peer

    def check_rate(self, peer_id: str) -> None:
        """Token-bucket per peer; raises RATE_LIMITED when empty."""
        limits = self.policy.rate_limits
        rate = max(limits.per_peer_per_minute, 1) / 60.0
        capacity = float(max(limits.burst, 1))
        now = self.clock.now().timestamp()
        bucket = self._buckets.get(peer_id)
        if bucket is None:
            bucket = _TokenBucket(rate, capacity, now)
            self._buckets[peer_id] = bucket
        bucket.tokens = min(capacity, bucket.tokens + (now - bucket.updated) * bucket.rate)
        bucket.updated = now
        if bucket.tokens < 1.0:
            raise PipError(ErrorCode.RATE_LIMITED, f"rate limit exceeded for {peer_id}")
        bucket.tokens -= 1.0
