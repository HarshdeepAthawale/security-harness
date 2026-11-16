import json
import math
import re
from typing import Any, Literal
from urllib.parse import unquote

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
)

from .limits import (
    MAX_BODY_BYTES,
    MAX_HEADER_COUNT,
    MAX_HEADER_NAME_LENGTH,
    MAX_HEADER_VALUE_LENGTH,
    MAX_PATH_BYTES,
    MAX_QUERY_BYTES,
    MAX_QUERY_PARAMS,
)

# Headers controlled by the broker, the HTTP client or the executor.
# A plan may never set them. Host is reserved: the destination and the
# Host header always come from the trusted scope origin.
BROKER_RESERVED_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "accept-encoding",
    "expect",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
})

HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-zA-Z]+$")
IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

# RFC 3986 path characters only (pchar + "/" + "%"). Anything else (spaces,
# unicode, bidi controls) would be re-encoded by the HTTP client, so the URL
# that scope authorized would differ from the URL that is sent.
PATH_PATTERN = re.compile(r"^[A-Za-z0-9\-._~!$&'()*+,;=:@/%]+$")

_QUERY_SCALAR = (str, int, float, bool, type(None))


def check_json_serializable(value: Any) -> bytes:
    """Serialize to JSON bytes; reject non-JSON values, NaN and Infinity."""
    try:
        return json.dumps(
            value, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Value must be valid JSON")


def has_traversal(path: str) -> bool:
    """Detect literal and repeatedly encoded traversal segments."""
    current = path
    for _ in range(6):
        if any(seg in {".", ".."} for seg in current.split("/")):
            return True
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
    return False


class RequestPlan(BaseModel):

    model_config = ConfigDict(extra="forbid", frozen=True)

    identity: StrictStr
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    path: StrictStr
    headers: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    pack: StrictStr
    expect: StrictStr

    @field_validator("identity")
    @classmethod
    def validate_identity(cls, value):
        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("Invalid identity format")
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value):
        if not value:
            raise ValueError("Path cannot be empty")
        if len(value.encode("utf-8", "replace")) > MAX_PATH_BYTES:
            raise ValueError("Path too long")
        if not value.startswith("/"):
            raise ValueError("Path must start with '/'")
        if value.startswith("//"):
            raise ValueError("Protocol-relative paths are not allowed")
        if "\\" in value:
            raise ValueError("Backslashes are not allowed")
        if "?" in value or "#" in value:
            raise ValueError("Query strings and fragments must be separate")
        if not PATH_PATTERN.fullmatch(value):
            raise ValueError("Path contains characters that must be percent-encoded")
        if re.search(r"%(?![0-9a-fA-F]{2})", value):
            raise ValueError("Malformed URL encoding")
        if re.search(r"%(?:2f|5c|00)", value, re.IGNORECASE):
            raise ValueError("Encoded separators and null bytes are not allowed")
        if has_traversal(value):
            raise ValueError("Path traversal detected")
        return value

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, headers):
        if len(headers) > MAX_HEADER_COUNT:
            raise ValueError("Too many headers")

        seen = set()
        for name, value in headers.items():
            lowered = name.lower()

            if len(name) > MAX_HEADER_NAME_LENGTH or not HEADER_NAME_PATTERN.fullmatch(name):
                raise ValueError(f"Invalid header name: {name}")
            if lowered in BROKER_RESERVED_HEADERS:
                raise ValueError(f"Header is controlled by Broker: {name}")
            if lowered in seen:
                raise ValueError(f"Duplicate header: {name}")
            seen.add(lowered)

            if len(value) > MAX_HEADER_VALUE_LENGTH:
                raise ValueError("Header value too long")
            if not value.isascii():
                raise ValueError("Non-ASCII header value")
            if "\r" in value or "\n" in value:
                raise ValueError("CRLF injection detected")
            if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in value):
                raise ValueError("Control character in header value")
        return headers

    @field_validator("query")
    @classmethod
    def validate_query(cls, query):
        if len(query) > MAX_QUERY_PARAMS:
            raise ValueError("Too many query parameters")

        for key, value in query.items():
            if not key or len(key) > 256 or not key.isprintable():
                raise ValueError("Invalid query parameter name")
            for item in value if isinstance(value, list) else [value]:
                if not isinstance(item, _QUERY_SCALAR):
                    raise ValueError("Query values must be scalars or lists of scalars")
                if isinstance(item, float) and not math.isfinite(item):
                    raise ValueError("Query values must be finite")

        if len(check_json_serializable(query)) > MAX_QUERY_BYTES:
            raise ValueError("Query parameters too large")
        return query

    @field_validator("body")
    @classmethod
    def validate_body(cls, body):
        if body is None:
            return body
        if len(check_json_serializable(body)) > MAX_BODY_BYTES:
            raise ValueError("Request body too large")
        return body

    @field_validator("pack")
    @classmethod
    def validate_pack(cls, value):
        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("Invalid pack name")
        return value

    @field_validator("expect")
    @classmethod
    def validate_expect(cls, value):
        statuses = value.split("/")
        for status in statuses:
            if not status.isdigit() or not status.isascii():
                raise ValueError("Invalid expected HTTP status")
            if not 100 <= int(status) <= 599:
                raise ValueError("HTTP status must be between 100 and 599")
        if len(statuses) != len(set(statuses)):
            raise ValueError("Duplicate expected status codes")
        return value
