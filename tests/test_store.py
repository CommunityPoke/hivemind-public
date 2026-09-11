from datetime import timedelta

import pytest

from pip_protocol.delivery import Outbox, OutboxItem
from pip_protocol.store import MemoryStore, SqliteStore, open_store


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        yield MemoryStore()
    else:
        s = SqliteStore(str(tmp_path / "pip.db"))
        yield s
        s.close()


def test_nonce_first_seen(store, clock):
    assert store.seen_nonce("p", "n1", clock.now()) is False


def test_nonce_duplicate(store, clock):
    store.seen_nonce("p", "n1", clock.now())
    assert store.seen_nonce("p", "n1", clock.now()) is True


def test_nonce_per_peer(store, clock):
    store.seen_nonce("a", "n1", clock.now())
    assert store.seen_nonce("b", "n1", clock.now()) is False


def test_idempotent_roundtrip(store):
    store.put_idempotent("p", "k", {"status": "accepted"}, 3600)
    assert store.get_idempotent("p", "k") == {"status": "accepted"}


def test_idempotent_missing(store):
    assert store.get_idempotent("p", "nope") is None


def test_purge(store, clock):
    store.seen_nonce("p", "old", clock.now() + timedelta(seconds=10))
    store.seen_nonce("p", "new", clock.now() + timedelta(hours=1))
    store.purge(clock.now() + timedelta(minutes=5))
    # expired nonce purged: treated as unseen
    assert store.seen_nonce("p", "old", clock.now() + timedelta(minutes=6)) is False


def test_open_store_urls(tmp_path):
    assert isinstance(open_store("memory://"), MemoryStore)
    s = open_store(f"sqlite:///{tmp_path}/x.db")
    assert isinstance(s, SqliteStore)
    with pytest.raises(ValueError):
        open_store("bogus://")


def test_outbox_backoff(store, clock):
    from pip_protocol.delivery import BACKOFF_CAP_SECONDS

    outbox = Outbox(store, clock)
    item = outbox.enqueue("peer", {"id": "e1"})
    assert len(outbox.due()) == 1

    item = outbox.mark_failed(item, "boom")
    assert item.attempts == 1
    assert outbox.due() == []  # backed off
    clock.advance(2)
    assert len(outbox.due()) == 1

    # exponential growth capped
    for _ in range(6):
        item = outbox.mark_failed(item, "x")
        clock.advance(BACKOFF_CAP_SECONDS)
    item = outbox.mark_failed(item, "final")
    assert item.attempts == 8
    assert item.dead


def test_outbox_delivered(store, clock):
    outbox = Outbox(store, clock)
    item = outbox.enqueue("peer", {"id": "e1"})
    outbox.mark_delivered(item)
    assert outbox.due() == []


def test_outbox_item_serialization(clock):
    item = OutboxItem(peer_id="p", envelope={}, next_attempt_at=clock.now())
    raw = item.model_dump(mode="json")
    assert OutboxItem.model_validate(raw).peer_id == "p"


def test_find_receipt_by_ref(store):
    receipt = {"payload": {"ref": "env-1", "status": "accepted"}}
    store.put_idempotent("p", "k", receipt, 3600, ref="env-1")
    assert store.find_receipt_by_ref("p", "env-1") == receipt
    assert store.find_receipt_by_ref("p", "nope") is None
    assert store.find_receipt_by_ref("other", "env-1") is None
