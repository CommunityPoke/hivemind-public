"""Error codes (spec §3) and the PipError exception type."""

from enum import Enum


class ErrorCode(str, Enum):
    SCHEMA_INVALID = "SCHEMA_INVALID"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    EXPIRED = "EXPIRED"
    CLOCK_SKEW = "CLOCK_SKEW"
    REPLAY = "REPLAY"
    UNKNOWN_PEER = "UNKNOWN_PEER"
    FORBIDDEN = "FORBIDDEN"
    CONSENT_REQUIRED = "CONSENT_REQUIRED"
    RATE_LIMITED = "RATE_LIMITED"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    CAPABILITY_UNKNOWN = "CAPABILITY_UNKNOWN"
    INTERNAL = "INTERNAL"


_HTTP_STATUS: dict[ErrorCode, int] = {
    ErrorCode.SCHEMA_INVALID: 400,
    ErrorCode.IDENTITY_MISMATCH: 401,
    ErrorCode.SIGNATURE_INVALID: 401,
    ErrorCode.UNKNOWN_PEER: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.CONSENT_REQUIRED: 403,
    ErrorCode.REPLAY: 409,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.VERSION_UNSUPPORTED: 422,
    ErrorCode.EXPIRED: 422,
    ErrorCode.CLOCK_SKEW: 422,
    ErrorCode.CAPABILITY_UNKNOWN: 422,
    ErrorCode.INTERNAL: 500,
}

_RETRYABLE: set[ErrorCode] = {
    ErrorCode.RATE_LIMITED,
    ErrorCode.INTERNAL,
}


class PipError(Exception):
    """Protocol error carrying a spec error code.

    Attributes:
        code: the spec §3 error code.
        message: human-readable detail.
        retryable: whether the sender may retry.
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str = "",
        *,
        retryable: bool | None = None,
    ) -> None:
        self.code = code
        self.message = message or code.value
        self.retryable = code in _RETRYABLE if retryable is None else retryable
        super().__init__(f"{code.value}: {self.message}")

    @property
    def http_status(self) -> int:
        return _HTTP_STATUS[self.code]
