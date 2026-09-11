"""Replay/idempotency/outbox storage backends (spec §7)."""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Protocol


class Store(Protocol):
    """Persistence interface for replay protection, idempotency, and the outbox."""

    def seen_nonce(self, peer: str, nonce: str, expires_at: datetime) -> bool:
        """Atomically record (peer, nonce); return True if already present."""
        ...

    def get_idempotent(self, peer: str, key: str) -> dict[str, Any] | None: ...

    def put_idempotent(
        self,
        peer: str,
        key: str,
        receipt: dict[str, Any],
        ttl: int,
        ref: str | None = None,
    ) -> None: ...

    def find_receipt_by_ref(self, peer: str, ref: str) -> dict[str, Any] | None: ...

    def purge(self, now: datetime) -> None: ...

    def outbox_put(self, item: dict[str, Any]) -> None: ...

    def outbox_due(self, now: datetime) -> list[dict[str, Any]]: ...

    def outbox_update(self, item: dict[str, Any]) -> None: ...

    def outbox_delete(self, item_id: str) -> None: ...


def _ts(dt: datetime) -> float:
    return dt.astimezone(timezone.utc).timestamp()


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _parse_dt(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


class MemoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nonces: dict[tuple[str, str], float] = {}
        self._idempotent: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
        self._outbox: dict[str, dict[str, Any]] = {}

    def seen_nonce(self, peer: str, nonce: str, expires_at: datetime) -> bool:
        with self._lock:
            key = (peer, nonce)
            if key in self._nonces:
                return True
            self._nonces[key] = _ts(expires_at)
            return False

    def get_idempotent(self, peer: str, key: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._idempotent.get((peer, key))
            if entry is None:
                return None
            expires, receipt = entry
            if expires < _ts(datetime.now(timezone.utc)):
                return None
            return receipt

    def put_idempotent(
        self,
        peer: str,
        key: str,
        receipt: dict[str, Any],
        ttl: int,
        ref: str | None = None,
    ) -> None:
        with self._lock:
            self._idempotent[(peer, key)] = (
                _ts(datetime.now(timezone.utc)) + ttl,
                receipt,
            )

    def find_receipt_by_ref(self, peer: str, ref: str) -> dict[str, Any] | None:
        with self._lock:
            now = _ts(datetime.now(timezone.utc))
            for (p, _), (expires, receipt) in self._idempotent.items():
                if p == peer and expires >= now and receipt.get("payload", {}).get("ref") == ref:
                    return receipt
            return None

    def purge(self, now: datetime) -> None:
        with self._lock:
            ts = _ts(now)
            self._nonces = {k: v for k, v in self._nonces.items() if v > ts}
            self._idempotent = {k: v for k, v in self._idempotent.items() if v[0] > ts}

    def outbox_put(self, item: dict[str, Any]) -> None:
        with self._lock:
            self._outbox[item["id"]] = dict(item)

    def outbox_due(self, now: datetime) -> list[dict[str, Any]]:
        with self._lock:
            ts = _ts(now)
            return [
                dict(i) for i in self._outbox.values() if _ts(_parse_dt(i["next_attempt_at"])) <= ts
            ]

    def outbox_update(self, item: dict[str, Any]) -> None:
        with self._lock:
            self._outbox[item["id"]] = dict(item)

    def outbox_delete(self, item_id: str) -> None:
        with self._lock:
            self._outbox.pop(item_id, None)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    peer TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (peer, nonce)
);
CREATE TABLE IF NOT EXISTS idempotent (
    peer TEXT NOT NULL,
    key TEXT NOT NULL,
    ref TEXT,
    expires_at REAL NOT NULL,
    receipt TEXT NOT NULL,
    PRIMARY KEY (peer, key)
);
CREATE INDEX IF NOT EXISTS idx_idempotent_ref ON idempotent (peer, ref);
CREATE TABLE IF NOT EXISTS outbox (
    id TEXT PRIMARY KEY,
    item TEXT NOT NULL,
    next_attempt_at REAL NOT NULL
);
"""


class SqliteStore:
    def __init__(self, path: str) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        with self._conn:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def seen_nonce(self, peer: str, nonce: str, expires_at: datetime) -> bool:
        with self._lock, self._conn:
            try:
                self._conn.execute(
                    "INSERT INTO nonces (peer, nonce, expires_at) VALUES (?, ?, ?)",
                    (peer, nonce, _ts(expires_at)),
                )
                return False
            except sqlite3.IntegrityError:
                return True

    def get_idempotent(self, peer: str, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT expires_at, receipt FROM idempotent WHERE peer = ? AND key = ?",
                (peer, key),
            ).fetchone()
            if row is None or row[0] < _ts(datetime.now(timezone.utc)):
                return None
            return json.loads(row[1])  # type: ignore[no-any-return]

    def put_idempotent(
        self,
        peer: str,
        key: str,
        receipt: dict[str, Any],
        ttl: int,
        ref: str | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO idempotent (peer, key, ref, expires_at, receipt)"
                " VALUES (?, ?, ?, ?, ?)",
                (peer, key, ref, _ts(datetime.now(timezone.utc)) + ttl, json.dumps(receipt)),
            )

    def find_receipt_by_ref(self, peer: str, ref: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT expires_at, receipt FROM idempotent WHERE peer = ? AND ref = ?",
                (peer, ref),
            ).fetchone()
            if row is None or row[0] < _ts(datetime.now(timezone.utc)):
                return None
            return json.loads(row[1])  # type: ignore[no-any-return]

    def purge(self, now: datetime) -> None:
        with self._lock, self._conn:
            ts = _ts(now)
            self._conn.execute("DELETE FROM nonces WHERE expires_at <= ?", (ts,))
            self._conn.execute("DELETE FROM idempotent WHERE expires_at <= ?", (ts,))

    def outbox_put(self, item: dict[str, Any]) -> None:
        self.outbox_update(item)

    def outbox_due(self, now: datetime) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT item FROM outbox WHERE next_attempt_at <= ? ORDER BY next_attempt_at",
                (_ts(now),),
            ).fetchall()
            return [json.loads(r[0]) for r in rows]

    def outbox_update(self, item: dict[str, Any]) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO outbox (id, item, next_attempt_at) VALUES (?, ?, ?)",
                (
                    item["id"],
                    json.dumps(item),
                    _ts(_parse_dt(item["next_attempt_at"])),
                ),
            )

    def outbox_delete(self, item_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM outbox WHERE id = ?", (item_id,))


def open_store(url: str) -> Store:
    if url == "memory://":
        return MemoryStore()
    if url.startswith("sqlite:///"):
        return SqliteStore(url[len("sqlite:///") :])
    raise ValueError(f"unsupported store url: {url!r}")
