"""Outbound payload redaction (spec §6)."""

import re
from typing import Any, TypeVar

from pydantic import BaseModel

from .policy import RedactionConfig
from .schemas import DataPayload, EnvelopeType, MessagePayload

MASK = "[REDACTED]"
_T = TypeVar("_T", bound=BaseModel)


class Redactor:
    def __init__(self, config: RedactionConfig) -> None:
        self.fields = {f.lower() for f in config.fields}
        self.patterns = [re.compile(p) for p in config.patterns]

    def redact_value(self, obj: Any) -> Any:
        """Recursively redact field-name matches and regex matches."""
        if isinstance(obj, dict):
            out: dict[Any, Any] = {}
            for key, value in obj.items():
                if isinstance(key, str) and key.lower() in self.fields:
                    out[key] = MASK
                else:
                    out[key] = self.redact_value(value)
            return out
        if isinstance(obj, list):
            return [self.redact_value(v) for v in obj]
        if isinstance(obj, str):
            for pattern in self.patterns:
                obj = pattern.sub(MASK, obj)
            return obj
        return obj

    def redact_payload(self, type: EnvelopeType, payload: _T) -> _T:
        """Return a redacted copy of a message or data payload."""
        if isinstance(payload, MessagePayload):
            return payload.model_copy(
                update={
                    "subject": self.redact_value(payload.subject),
                    "body": self.redact_value(payload.body),
                    "attributes": self.redact_value(payload.attributes),
                }
            )
        if isinstance(payload, DataPayload):
            return payload.model_copy(update={"records": self.redact_value(payload.records)})
        return payload
