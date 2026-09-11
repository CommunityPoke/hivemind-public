"""Canonical JSON serialization used for signing (spec §3)."""

import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Serialize ``obj`` to canonical JSON bytes.

    Sorted keys, no whitespace, UTF-8, NaN/Infinity rejected.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
