"""Persistent outbound queue with exponential backoff (spec §7)."""

from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .clock import Clock, SystemClock
from .schemas import new_id
from .store import Store

BACKOFF_BASE_SECONDS = 2.0
BACKOFF_CAP_SECONDS = 300.0
MAX_ATTEMPTS = 8


class OutboxItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=new_id)
    peer_id: str
    envelope: dict[str, Any]
    attempts: int = 0
    next_attempt_at: datetime
    last_error: str | None = None
    dead: bool = False


class Outbox:
    def __init__(
        self,
        store: Store,
        clock: Clock | None = None,
        *,
        max_attempts: int = MAX_ATTEMPTS,
    ) -> None:
        self.store = store
        self.clock = clock or SystemClock()
        self.max_attempts = max_attempts

    def enqueue(self, peer_id: str, envelope: dict[str, Any]) -> OutboxItem:
        item = OutboxItem(
            peer_id=peer_id,
            envelope=envelope,
            next_attempt_at=self.clock.now(),
        )
        self.store.outbox_put(item.model_dump(mode="json"))
        return item

    def due(self) -> list[OutboxItem]:
        return [OutboxItem.model_validate(raw) for raw in self.store.outbox_due(self.clock.now())]

    def mark_failed(self, item: OutboxItem, err: str) -> OutboxItem:
        item.attempts += 1
        item.last_error = err
        if item.attempts >= self.max_attempts:
            item.dead = True
        delay = min(BACKOFF_BASE_SECONDS * (2 ** (item.attempts - 1)), BACKOFF_CAP_SECONDS)
        item.next_attempt_at = self.clock.now() + timedelta(seconds=delay)
        self.store.outbox_update(item.model_dump(mode="json"))
        return item

    def mark_delivered(self, item: OutboxItem) -> None:
        self.store.outbox_delete(item.id)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
