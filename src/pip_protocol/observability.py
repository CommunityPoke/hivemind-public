"""Metrics and structured logging (spec §8, §10)."""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest


class Metrics:
    """Transport-agnostic metrics with a private registry (test-safe)."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.envelopes_received = Counter(
            "envelopes_received_total",
            "Envelopes received",
            ["type", "outcome"],
            registry=self.registry,
        )
        self.envelopes_sent = Counter(
            "envelopes_sent_total",
            "Envelopes sent",
            ["type"],
            registry=self.registry,
        )
        self.policy_denials = Counter(
            "policy_denials_total",
            "Policy denials",
            ["code"],
            registry=self.registry,
        )
        self.handler_seconds = Histogram(
            "handler_seconds",
            "Handler duration",
            ["type"],
            registry=self.registry,
        )

    def render(self) -> str:
        return generate_latest(self.registry).decode("utf-8")


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "pip_fields", None)
        if isinstance(extra, dict):
            entry.update(extra)
        if record.exc_info:
            entry["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger("pip_protocol")
    root.handlers[:] = [handler]
    root.setLevel(level.upper())


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Emit a structured event. Never pass payload bodies, keys, or tokens."""
    safe = {k: v for k, v in fields.items() if k not in {"payload", "body", "key", "token"}}
    logger.info(event, extra={"pip_fields": {"event": event, **safe}})
